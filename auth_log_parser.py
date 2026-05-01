import hashlib
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional


FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<username>\S+) from (?P<source_ip>\S+)"
)
INVALID_USER_RE = re.compile(r"Invalid user (?P<username>\S+) from (?P<source_ip>\S+)")
ACCEPTED_PASSWORD_RE = re.compile(r"Accepted \S+ for (?P<username>\S+) from (?P<source_ip>\S+)")
PRI_RE = re.compile(r"^<\d{1,3}>")
ISO_TS_RE = re.compile(r"^(?:<\d{1,3}>1\s+|<\d{1,3}>)?(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})")
SYSLOG_TS_RE = re.compile(r"^(?:<\d{1,3}>)?(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
SYSLOG_HOST_RE = re.compile(
    r"^(?:<\d{1,3}>)?"
    r"(?:(?:\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[+-]\d{2}:\d{2}|Z)?)|"
    r"(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}))\s+"
    r"(?P<hostname>\S+)"
)


@dataclass(frozen=True)
class ParsedAuthEvent:
    event_time: datetime
    event_type: str
    username: str
    source_ip: str
    raw_line: str


def parse_auth_log_line(line: str, fallback: datetime) -> Optional[ParsedAuthEvent]:
    cleaned_line = line.strip()
    if not cleaned_line:
        return None

    failed_match = FAILED_PASSWORD_RE.search(cleaned_line)
    invalid_match = INVALID_USER_RE.search(cleaned_line)
    accepted_match = ACCEPTED_PASSWORD_RE.search(cleaned_line)

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

    return ParsedAuthEvent(
        event_time=parse_log_timestamp(cleaned_line, fallback),
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        raw_line=cleaned_line,
    )


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


def extract_syslog_hostname(line: str) -> Optional[str]:
    match = SYSLOG_HOST_RE.match(line.strip())
    if not match:
        return None
    hostname = match.group("hostname")
    if hostname in {"-", ""}:
        return None
    return hostname


def build_ssh_event(
    parsed_event: ParsedAuthEvent,
    collected_at: datetime,
    node: str,
    vmid: int,
    target_host: str,
    line_hash_seed: str,
    ingest_method: str,
    hostname: Optional[str] = None,
) -> Dict[str, object]:
    line_hash = hashlib.sha256(
        f"{ingest_method}|{node}|{vmid}|{target_host}|{line_hash_seed}|{parsed_event.raw_line}".encode("utf-8")
    ).hexdigest()
    return {
        "timestamp": parsed_event.event_time.isoformat(timespec="seconds"),
        "collected_at": collected_at.isoformat(timespec="seconds"),
        "node": node,
        "vmid": vmid,
        "target_host": target_host,
        "source_ip": parsed_event.source_ip,
        "username": parsed_event.username,
        "event_type": parsed_event.event_type,
        "raw_line": parsed_event.raw_line,
        "line_hash": line_hash,
        "ingest_method": ingest_method,
        "hostname": hostname,
    }
