import os
from dataclasses import dataclass
from typing import List, Optional, Set

from dotenv import load_dotenv


@dataclass(frozen=True)
class SshLogTarget:
    vmid: int
    host: str
    user: str
    log_path: str


@dataclass(frozen=True)
class SyslogVmMapping:
    vmid: int
    host: str
    name: str
    node: str


@dataclass(frozen=True)
class AppConfig:
    host: str
    user: str
    token_id: str
    token_secret: str
    verify_ssl: bool
    db_path: str
    protected_vmids: Set[int]
    host_cpu_warn: float
    host_cpu_critical: float
    vm_cpu_warn: float
    vm_cpu_critical: float
    vm_ram_warn: float
    vm_ram_critical: float
    alert_min_duration_seconds: int
    max_history_points: int
    collect_interval_seconds: int
    app_persist_on_render: bool
    collector_heartbeat_seconds: int
    ssh_log_targets: List[SshLogTarget]
    ssh_key_path: str
    ssh_connect_timeout_seconds: int
    ssh_log_lookback_minutes: int
    ssh_log_max_lines: int
    ssh_auth_failure_warn: int
    ssh_auth_failure_critical: int
    ssh_source_failure_warn: int
    ssh_distributed_source_warn: int
    ssh_success_after_failure_warn: int
    ssh_correlation_cpu_threshold: float
    ssh_correlation_window_seconds: int
    syslog_enabled: bool
    syslog_bind_host: str
    syslog_port: int
    syslog_protocols: Set[str]
    syslog_default_node: str
    syslog_vm_map: List[SyslogVmMapping]
    ml_enabled: bool
    ml_auto_train: bool
    ml_model_path: str
    ml_contamination: float
    ml_score_warn: float
    ml_score_critical: float
    ml_train_synthetic_samples: int
    ml_evaluation_synthetic_samples: int


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_float_env(name: str, default: float, minimum: float = 0.0, maximum: float = 100.0) -> float:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = float(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} doit etre un nombre.") from exc
    if value < minimum or value > maximum:
        raise ValueError(f"{name} doit etre compris entre {minimum} et {maximum}.")
    return value


def parse_int_env(name: str, default: int, minimum: int = 0) -> int:
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} doit etre un entier.") from exc
    if value < minimum:
        raise ValueError(f"{name} doit etre superieur ou egal a {minimum}.")
    return value


def parse_vmid_set(value: Optional[str]) -> Set[int]:
    if value is None or not value.strip():
        return set()

    vmids: Set[int] = set()
    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue
        try:
            vmids.add(int(part))
        except ValueError as exc:
            raise ValueError("PROTECTED_VMIDS doit contenir des VMID separes par des virgules.") from exc
    return vmids


def parse_ssh_log_targets(value: Optional[str]) -> List[SshLogTarget]:
    if value is None or not value.strip():
        return []

    targets: List[SshLogTarget] = []
    for raw_target in value.split(";"):
        target = raw_target.strip()
        if not target:
            continue
        parts = target.split(":")
        if len(parts) not in {3, 4}:
            raise ValueError(
                "SSH_LOG_TARGETS doit utiliser le format "
                "vmid:host:user[:log_path], separe par des points-virgules."
            )
        try:
            vmid = int(parts[0])
        except ValueError as exc:
            raise ValueError("Le premier champ de chaque SSH_LOG_TARGETS doit etre un VMID.") from exc

        targets.append(
            SshLogTarget(
                vmid=vmid,
                host=parts[1].strip(),
                user=parts[2].strip(),
                log_path=parts[3].strip() if len(parts) == 4 and parts[3].strip() else "/var/log/auth.log",
            )
        )

    return targets


def parse_syslog_protocols(value: Optional[str]) -> Set[str]:
    if value is None or not value.strip():
        return {"tcp", "udp"}

    protocols = {part.strip().lower() for part in value.split(",") if part.strip()}
    invalid = protocols - {"tcp", "udp"}
    if invalid:
        raise ValueError("SYSLOG_PROTOCOLS accepte uniquement tcp, udp ou tcp,udp.")
    if not protocols:
        raise ValueError("SYSLOG_PROTOCOLS ne peut pas etre vide si SYSLOG_ENABLED=True.")
    return protocols


def parse_syslog_vm_map(value: Optional[str], default_node: str) -> List[SyslogVmMapping]:
    if value is None or not value.strip():
        return []

    mappings: List[SyslogVmMapping] = []
    for raw_mapping in value.split(";"):
        mapping = raw_mapping.strip()
        if not mapping:
            continue
        parts = [part.strip() for part in mapping.split(":")]
        if len(parts) not in {2, 3, 4}:
            raise ValueError(
                "SYSLOG_VM_MAP doit utiliser le format "
                "vmid:host[:name[:node]], separe par des points-virgules."
            )
        try:
            vmid = int(parts[0])
        except ValueError as exc:
            raise ValueError("Le premier champ de chaque SYSLOG_VM_MAP doit etre un VMID.") from exc
        host = parts[1]
        if not host:
            raise ValueError("Le champ host de SYSLOG_VM_MAP ne peut pas etre vide.")
        mappings.append(
            SyslogVmMapping(
                vmid=vmid,
                host=host,
                name=parts[2] if len(parts) >= 3 and parts[2] else f"VM {vmid}",
                node=parts[3] if len(parts) == 4 and parts[3] else default_node,
            )
        )
    return mappings


def sanitize_host(raw_host: str) -> str:
    host = raw_host.strip()
    host = host.removeprefix("https://").removeprefix("http://")
    return host.rstrip("/")


def read_settings() -> AppConfig:
    load_dotenv()

    required = {
        "PROXMOX_HOST": os.getenv("PROXMOX_HOST", "").strip(),
        "PROXMOX_USER": os.getenv("PROXMOX_USER", "").strip(),
        "PROXMOX_TOKEN_ID": os.getenv("PROXMOX_TOKEN_ID", "").strip(),
        "PROXMOX_SECRET": os.getenv("PROXMOX_SECRET", "").strip(),
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        missing_vars = ", ".join(missing)
        raise ValueError(
            f"Variables d'environnement manquantes: {missing_vars}. "
            "Complete le fichier .env avant de lancer l'application."
        )

    host_cpu_warn = parse_float_env("ALERT_HOST_CPU_WARN", 80.0)
    host_cpu_critical = parse_float_env("ALERT_HOST_CPU_CRITICAL", 95.0)
    vm_cpu_warn = parse_float_env("ALERT_VM_CPU_WARN", 80.0)
    vm_cpu_critical = parse_float_env("ALERT_VM_CPU_CRITICAL", 95.0)
    vm_ram_warn = parse_float_env("ALERT_VM_RAM_WARN", 85.0)
    vm_ram_critical = parse_float_env("ALERT_VM_RAM_CRITICAL", 95.0)

    if host_cpu_warn >= host_cpu_critical:
        raise ValueError("ALERT_HOST_CPU_WARN doit etre inferieur a ALERT_HOST_CPU_CRITICAL.")
    if vm_cpu_warn >= vm_cpu_critical:
        raise ValueError("ALERT_VM_CPU_WARN doit etre inferieur a ALERT_VM_CPU_CRITICAL.")
    if vm_ram_warn >= vm_ram_critical:
        raise ValueError("ALERT_VM_RAM_WARN doit etre inferieur a ALERT_VM_RAM_CRITICAL.")
    ml_score_warn = parse_float_env("ML_SCORE_WARN", 70.0)
    ml_score_critical = parse_float_env("ML_SCORE_CRITICAL", 85.0)
    if ml_score_warn >= ml_score_critical:
        raise ValueError("ML_SCORE_WARN doit etre inferieur a ML_SCORE_CRITICAL.")
    ml_contamination = parse_float_env("ML_CONTAMINATION", 0.08, minimum=0.001, maximum=0.5)

    ssh_auth_failure_warn = parse_int_env("SSH_AUTH_FAILURE_WARN", 5, minimum=1)
    ssh_auth_failure_critical = parse_int_env("SSH_AUTH_FAILURE_CRITICAL", 20, minimum=1)
    if ssh_auth_failure_warn >= ssh_auth_failure_critical:
        raise ValueError("SSH_AUTH_FAILURE_WARN doit etre inferieur a SSH_AUTH_FAILURE_CRITICAL.")
    ssh_source_failure_warn = parse_int_env("SSH_SOURCE_FAILURE_WARN", ssh_auth_failure_warn, minimum=1)
    ssh_distributed_source_warn = parse_int_env("SSH_DISTRIBUTED_SOURCE_WARN", 3, minimum=2)
    ssh_success_after_failure_warn = parse_int_env("SSH_SUCCESS_AFTER_FAILURE_WARN", 3, minimum=1)
    syslog_default_node = os.getenv("SYSLOG_DEFAULT_NODE", "pve").strip() or "pve"

    return AppConfig(
        host=sanitize_host(required["PROXMOX_HOST"]),
        user=required["PROXMOX_USER"],
        token_id=required["PROXMOX_TOKEN_ID"],
        token_secret=required["PROXMOX_SECRET"],
        verify_ssl=parse_bool(os.getenv("VERIFY_SSL"), default=False),
        db_path=os.getenv("SOC_DB_PATH", "soc_dashboard.sqlite3").strip() or "soc_dashboard.sqlite3",
        protected_vmids=parse_vmid_set(os.getenv("PROTECTED_VMIDS")),
        host_cpu_warn=host_cpu_warn,
        host_cpu_critical=host_cpu_critical,
        vm_cpu_warn=vm_cpu_warn,
        vm_cpu_critical=vm_cpu_critical,
        vm_ram_warn=vm_ram_warn,
        vm_ram_critical=vm_ram_critical,
        alert_min_duration_seconds=parse_int_env("ALERT_MIN_DURATION_SECONDS", 0),
        max_history_points=parse_int_env("MAX_HISTORY_POINTS", 30, minimum=5),
        collect_interval_seconds=parse_int_env("COLLECT_INTERVAL_SECONDS", 5, minimum=1),
        app_persist_on_render=parse_bool(os.getenv("APP_PERSIST_ON_RENDER"), default=False),
        collector_heartbeat_seconds=parse_int_env("COLLECTOR_HEARTBEAT_SECONDS", 30, minimum=5),
        ssh_log_targets=parse_ssh_log_targets(os.getenv("SSH_LOG_TARGETS")),
        ssh_key_path=os.getenv("SSH_KEY_PATH", "").strip(),
        ssh_connect_timeout_seconds=parse_int_env("SSH_CONNECT_TIMEOUT_SECONDS", 5, minimum=1),
        ssh_log_lookback_minutes=parse_int_env("SSH_LOG_LOOKBACK_MINUTES", 10, minimum=1),
        ssh_log_max_lines=parse_int_env("SSH_LOG_MAX_LINES", 300, minimum=20),
        ssh_auth_failure_warn=ssh_auth_failure_warn,
        ssh_auth_failure_critical=ssh_auth_failure_critical,
        ssh_source_failure_warn=ssh_source_failure_warn,
        ssh_distributed_source_warn=ssh_distributed_source_warn,
        ssh_success_after_failure_warn=ssh_success_after_failure_warn,
        ssh_correlation_cpu_threshold=parse_float_env("SSH_CORRELATION_CPU_THRESHOLD", 50.0),
        ssh_correlation_window_seconds=parse_int_env("SSH_CORRELATION_WINDOW_SECONDS", 300, minimum=30),
        syslog_enabled=parse_bool(os.getenv("SYSLOG_ENABLED"), default=True),
        syslog_bind_host=os.getenv("SYSLOG_BIND_HOST", "0.0.0.0").strip() or "0.0.0.0",
        syslog_port=parse_int_env("SYSLOG_PORT", 5514, minimum=1),
        syslog_protocols=parse_syslog_protocols(os.getenv("SYSLOG_PROTOCOLS")),
        syslog_default_node=syslog_default_node,
        syslog_vm_map=parse_syslog_vm_map(os.getenv("SYSLOG_VM_MAP"), syslog_default_node),
        ml_enabled=parse_bool(os.getenv("ML_ENABLED"), default=True),
        ml_auto_train=parse_bool(os.getenv("ML_AUTO_TRAIN"), default=True),
        ml_model_path=os.getenv("ML_MODEL_PATH", "/data/models/isolation_forest.joblib").strip()
        or "/data/models/isolation_forest.joblib",
        ml_contamination=ml_contamination,
        ml_score_warn=ml_score_warn,
        ml_score_critical=ml_score_critical,
        ml_train_synthetic_samples=parse_int_env("ML_TRAIN_SYNTHETIC_SAMPLES", 800, minimum=100),
        ml_evaluation_synthetic_samples=parse_int_env("ML_EVALUATION_SYNTHETIC_SAMPLES", 100, minimum=20),
    )
