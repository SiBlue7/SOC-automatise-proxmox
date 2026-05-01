import re
import socketserver
import threading
import time
from datetime import datetime
from typing import Dict, Iterable, Optional

from auth_log_parser import build_ssh_event, extract_syslog_hostname, parse_auth_log_line
from config import AppConfig, SyslogVmMapping, read_settings
from storage import init_db, insert_ssh_events, record_syslog_run


OCTET_COUNT_RE = re.compile(r"^\d+\s+(?P<message><\d{1,3}>.*)$")
OCTET_COUNT_BYTES_RE = re.compile(rb"^(?P<size>\d+)\s")


def log(message: str) -> None:
    print(f"{datetime.now().isoformat(timespec='seconds')} | {message}", flush=True)


def normalize_key(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip().lower()
    return normalized or None


def strip_syslog_framing(message: str) -> str:
    cleaned = message.strip().rstrip("\x00")
    octet_match = OCTET_COUNT_RE.match(cleaned)
    if octet_match:
        return octet_match.group("message").strip()
    return cleaned


def split_tcp_frames(buffer: bytes) -> tuple[list[bytes], bytes]:
    frames: list[bytes] = []
    while buffer:
        buffer = buffer.lstrip(b"\r\n")
        if not buffer:
            break

        octet_match = OCTET_COUNT_BYTES_RE.match(buffer)
        if octet_match:
            size = int(octet_match.group("size"))
            header_size = octet_match.end()
            frame_end = header_size + size
            if len(buffer) < frame_end:
                break
            frames.append(buffer[header_size:frame_end])
            buffer = buffer[frame_end:]
            continue

        if b"\n" not in buffer:
            break
        raw_line, buffer = buffer.split(b"\n", 1)
        if raw_line.strip():
            frames.append(raw_line.rstrip(b"\r"))
    return frames, buffer


class SyslogEventProcessor:
    def __init__(self, settings: AppConfig):
        self.settings = settings
        self.mappings = self._build_mapping_index(settings.syslog_vm_map)
        self.events_seen = 0
        self.events_inserted = 0
        self.unmatched_events = 0

    @staticmethod
    def _build_mapping_index(mappings: Iterable[SyslogVmMapping]) -> Dict[str, SyslogVmMapping]:
        index: Dict[str, SyslogVmMapping] = {}
        for mapping in mappings:
            for candidate in {mapping.host, mapping.name}:
                key = normalize_key(candidate)
                if key:
                    index[key] = mapping
        return index

    def resolve_mapping(self, remote_ip: str, hostname: Optional[str]) -> Optional[SyslogVmMapping]:
        for candidate in (remote_ip, hostname):
            key = normalize_key(candidate)
            if key and key in self.mappings:
                return self.mappings[key]
        return None

    def process_line(self, line: str, remote_ip: str, protocol: str) -> None:
        collected_at = datetime.now()
        message = strip_syslog_framing(line)
        if not message:
            return

        parsed_event = parse_auth_log_line(message, collected_at)
        if parsed_event is None:
            return

        self.events_seen += 1
        hostname = extract_syslog_hostname(message)
        mapping = self.resolve_mapping(remote_ip, hostname)
        if mapping is None:
            self.unmatched_events += 1
            warning = (
                f"Evenement SSH ignore: aucune entree SYSLOG_VM_MAP pour "
                f"remote={remote_ip} hostname={hostname or '-'}"
            )
            log(f"syslog warning | {warning}")
            record_syslog_run(
                self.settings.db_path,
                status="warning",
                message=warning,
                events_seen=self.events_seen,
                events_inserted=self.events_inserted,
                timestamp=collected_at,
            )
            return

        event = build_ssh_event(
            parsed_event=parsed_event,
            collected_at=collected_at,
            node=mapping.node,
            vmid=mapping.vmid,
            target_host=mapping.host,
            line_hash_seed=f"{protocol}|{remote_ip}|{hostname or ''}",
            ingest_method=f"syslog-{protocol}",
            hostname=hostname,
        )
        inserted = insert_ssh_events(self.settings.db_path, [event])
        self.events_inserted += inserted
        if inserted:
            log(
                "syslog event | "
                f"protocol={protocol} node={mapping.node} vmid={mapping.vmid} "
                f"type={parsed_event.event_type} source={parsed_event.source_ip}"
            )
            record_syslog_run(
                self.settings.db_path,
                status="success",
                message="Evenement Syslog SSH insere.",
                events_seen=self.events_seen,
                events_inserted=self.events_inserted,
                timestamp=collected_at,
            )


class ReusableThreadingUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True


class ReusableThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        remote_ip = self.client_address[0]
        message = data.decode("utf-8", errors="replace")
        self.server.processor.process_line(message, remote_ip, "udp")


class SyslogTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        remote_ip = self.client_address[0]
        buffer = b""
        while True:
            chunk = self.request.recv(4096)
            if not chunk:
                break
            buffer += chunk
            frames, buffer = split_tcp_frames(buffer)
            for frame in frames:
                message = frame.decode("utf-8", errors="replace")
                self.server.processor.process_line(message, remote_ip, "tcp")
        if buffer.strip():
            message = buffer.decode("utf-8", errors="replace")
            self.server.processor.process_line(message, remote_ip, "tcp")


def start_udp_server(settings: AppConfig, processor: SyslogEventProcessor) -> socketserver.BaseServer:
    server = ReusableThreadingUDPServer((settings.syslog_bind_host, settings.syslog_port), SyslogUDPHandler)
    server.processor = processor
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def start_tcp_server(settings: AppConfig, processor: SyslogEventProcessor) -> socketserver.BaseServer:
    server = ReusableThreadingTCPServer((settings.syslog_bind_host, settings.syslog_port), SyslogTCPHandler)
    server.processor = processor
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def main() -> None:
    settings = read_settings()
    init_db(settings.db_path)

    if not settings.syslog_enabled:
        log("syslog collector disabled | SYSLOG_ENABLED=False")
        record_syslog_run(settings.db_path, status="disabled", message="SYSLOG_ENABLED=False")
        while True:
            time.sleep(3600)

    if not settings.syslog_vm_map:
        log("syslog warning | SYSLOG_VM_MAP est vide: les evenements seront ignores.")
        record_syslog_run(settings.db_path, status="warning", message="SYSLOG_VM_MAP est vide.")

    processor = SyslogEventProcessor(settings)
    servers = []
    if "udp" in settings.syslog_protocols:
        servers.append(start_udp_server(settings, processor))
    if "tcp" in settings.syslog_protocols:
        servers.append(start_tcp_server(settings, processor))

    protocols = ",".join(sorted(settings.syslog_protocols))
    log(
        "syslog collector started | "
        f"bind={settings.syslog_bind_host}:{settings.syslog_port} protocols={protocols} "
        f"mappings={len(settings.syslog_vm_map)}"
    )
    record_syslog_run(
        settings.db_path,
        status="listening",
        message=f"Collecteur Syslog en ecoute sur {settings.syslog_bind_host}:{settings.syslog_port} ({protocols}).",
    )

    try:
        while True:
            time.sleep(60)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("syslog collector stopped")
