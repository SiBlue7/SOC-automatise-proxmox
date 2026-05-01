import hashlib
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from config import AppConfig, SshLogTarget


FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<username>\S+) from (?P<source_ip>\S+)")
ACCEPTED_PASSWORD_RE = re.compile(r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)")
ISO_TS_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})")
SYSLOG_TS_RE = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


@dataclass(frozen=True)
class SshCollectionResult:
    target: SshLogTarget
    events: List[Dict[str, object]]
    error: Optional[str] = None


def build_ssh_command(settings: AppConfig, target: SshLogTarget) -> List[str]:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/tmp/soc_known_hosts",
        "-o",
        f"ConnectTimeout={settings.ssh_connect_timeout_seconds}",
    ]
    if settings.ssh_key_path:
        command.extend(["-i", settings.ssh_key_path])
    command.append(f"{target.user}@{target.host}")

    remote_command = (
        f"(journalctl -u ssh -u sshd --since '{settings.ssh_log_lookback_minutes} minutes ago' "
        f"--no-pager -o short-iso 2>/dev/null || "
        f"tail -n {settings.ssh_log_max_lines} {target.log_path})"
    )
    command.append(remote_command)
    return command


def collect_target_logs(settings: AppConfig, target: SshLogTarget, node_name: str, collected_at: datetime) -> SshCollectionResult:
    command = build_ssh_command(settings, target)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=settings.ssh_connect_timeout_seconds + 15,
        )
    except Exception as exc:
        return SshCollectionResult(target=target, events=[], error=str(exc))

    if completed.returncode != 0:
        error = completed.stderr.strip() or completed.stdout.strip() or f"ssh exited with {completed.returncode}"
        return SshCollectionResult(target=target, events=[], error=error)

    events = []
    for line in completed.stdout.splitlines():
        event = parse_auth_log_line(line, target, node_name, collected_at)
        if event:
            events.append(event)
    return SshCollectionResult(target=target, events=events)


def parse_auth_log_line(
    line: str,
    target: SshLogTarget,
    node_name: str,
    collected_at: datetime,
) -> Optional[Dict[str, object]]:
    event_type = None
    username = None
    source_ip = None

    failed_match = FAILED_PASSWORD_RE.search(line)
    invalid_match = INVALID_USER_RE.search(line)
    accepted_match = ACCEPTED_PASSWORD_RE.search(line)

    if failed_match:
        event_type = "failed_password"
        username = failed_match.group("username")
        source_ip = failed_match.group("source_ip")
    elif invalid_match:
        event_type = "invalid_user"
        username = invalid_match.group("username")
        source_ip = invalid_match.group("source_ip")
    elif accepted_match:
        event_type = "accepted_password"
        username = accepted_match.group("username")
        source_ip = accepted_match.group("source_ip")
    else:
        return None

    event_time = parse_log_timestamp(line, collected_at)
    line_hash = hashlib.sha256(f"{target.vmid}|{target.host}|{line}".encode("utf-8")).hexdigest()
    return {
        "timestamp": event_time.isoformat(timespec="seconds"),
        "collected_at": collected_at.isoformat(timespec="seconds"),
        "node": node_name,
        "vmid": target.vmid,
        "target_host": target.host,
        "source_ip": source_ip,
        "username": username,
        "event_type": event_type,
        "raw_line": line,
        "line_hash": line_hash,
    }


def parse_log_timestamp(line: str, fallback: datetime) -> datetime:
    iso_match = ISO_TS_RE.match(line)
    if iso_match:
        value = iso_match.group("ts").replace("T", " ")
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass

    syslog_match = SYSLOG_TS_RE.match(line)
    if syslog_match:
        value = f"{fallback.year} {syslog_match.group('ts')}"
        try:
            return datetime.strptime(value, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    return fallback


def validate_ssh_setup(settings: AppConfig) -> Optional[str]:
    if not settings.ssh_log_targets:
        return None
    if settings.ssh_key_path and not Path(settings.ssh_key_path).exists():
        return f"SSH_KEY_PATH introuvable dans le conteneur: {settings.ssh_key_path}"
    if not settings.ssh_key_path:
        return "SSH_LOG_TARGETS est configure, mais SSH_KEY_PATH est vide; ssh utilisera les cles par defaut du conteneur."
    return None
