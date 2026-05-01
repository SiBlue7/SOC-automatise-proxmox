import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from auth_log_parser import build_ssh_event, parse_auth_log_line as parse_shared_auth_log_line
from config import AppConfig, SshLogTarget


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
    parsed_event = parse_shared_auth_log_line(line, collected_at)
    if parsed_event is None:
        return None

    return build_ssh_event(
        parsed_event=parsed_event,
        collected_at=collected_at,
        node=node_name,
        vmid=target.vmid,
        target_host=target.host,
        line_hash_seed=target.host,
        ingest_method="ssh",
    )


def validate_ssh_setup(settings: AppConfig) -> Optional[str]:
    if not settings.ssh_log_targets:
        return None
    if settings.ssh_key_path and not Path(settings.ssh_key_path).exists():
        return f"SSH_KEY_PATH introuvable dans le conteneur: {settings.ssh_key_path}"
    if not settings.ssh_key_path:
        return "SSH_LOG_TARGETS est configure, mais SSH_KEY_PATH est vide; ssh utilisera les cles par defaut du conteneur."
    return None
