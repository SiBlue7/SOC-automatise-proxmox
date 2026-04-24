import os
from dataclasses import dataclass
from typing import Optional, Set

from dotenv import load_dotenv


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
    )
