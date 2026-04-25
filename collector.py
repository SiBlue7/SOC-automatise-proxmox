import time
from datetime import datetime
from typing import Dict, Set

from config import AppConfig, read_settings
from detection import evaluate_detection
from proxmox_client import (
    connect_proxmox,
    fetch_node_status,
    fetch_nodes,
    fetch_qemu_vms,
    fetch_vm_statuses,
)
from storage import (
    init_db,
    insert_host_metric,
    insert_vm_metric,
    record_collector_run,
    resolve_alerts_for_node,
    upsert_alert,
)


def log(message: str) -> None:
    print(f"{datetime.now().isoformat(timespec='seconds')} | {message}", flush=True)


def persist_metrics(
    settings: AppConfig,
    node_name: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    timestamp: datetime,
) -> None:
    insert_host_metric(settings.db_path, node_name, node_status, timestamp)
    for vm in vm_statuses.values():
        insert_vm_metric(settings.db_path, node_name, vm, timestamp)


def run_collection_cycle(
    settings: AppConfig,
    proxmox,
    active_breaches: Dict[str, datetime],
    fired_alert_keys: Set[str],
) -> None:
    sample_time = datetime.now()
    nodes_seen = 0
    vm_count = 0
    alerts_seen = 0
    errors = []

    nodes = fetch_nodes(proxmox)
    node_names = [node["node"] for node in nodes if node.get("node")]

    for node_name in node_names:
        try:
            node_status = fetch_node_status(proxmox, node_name)
            qemu_vms = fetch_qemu_vms(proxmox, node_name)
            vm_statuses = fetch_vm_statuses(proxmox, node_name, qemu_vms)

            persist_metrics(settings, node_name, node_status, vm_statuses, sample_time)

            evaluation = evaluate_detection(
                settings,
                node_name,
                node_status,
                vm_statuses,
                active_breaches,
                fired_alert_keys,
                now=sample_time,
            )
            for alert in evaluation.current_alerts:
                upsert_alert(settings.db_path, alert)
            resolve_alerts_for_node(settings.db_path, node_name, evaluation.active_keys, sample_time)

            nodes_seen += 1
            vm_count += len(vm_statuses)
            alerts_seen += len(evaluation.current_alerts)
        except Exception as exc:
            errors.append(f"{node_name}: {exc}")

    if errors:
        message = " | ".join(errors)
        record_collector_run(
            settings.db_path,
            status="error",
            message=message,
            nodes_seen=nodes_seen,
            vm_count=vm_count,
            alerts_seen=alerts_seen,
            timestamp=sample_time,
        )
        log(f"cycle error | nodes={nodes_seen} vms={vm_count} alerts={alerts_seen} | {message}")
        return

    if not node_names:
        message = "Aucun noeud retourne par l'API Proxmox."
        record_collector_run(
            settings.db_path,
            status="warning",
            message=message,
            nodes_seen=0,
            vm_count=0,
            alerts_seen=0,
            timestamp=sample_time,
        )
        log(f"cycle warning | {message}")
        return

    message = "Cycle de collecte termine."
    record_collector_run(
        settings.db_path,
        status="success",
        message=message,
        nodes_seen=nodes_seen,
        vm_count=vm_count,
        alerts_seen=alerts_seen,
        timestamp=sample_time,
    )
    log(f"cycle ok | nodes={nodes_seen} vms={vm_count} alerts={alerts_seen}")


def main() -> None:
    settings = read_settings()
    init_db(settings.db_path)
    active_breaches: Dict[str, datetime] = {}
    fired_alert_keys: Set[str] = set()
    proxmox = None

    log(
        "collector started | "
        f"interval={settings.collect_interval_seconds}s db={settings.db_path}"
    )

    while True:
        cycle_started = time.monotonic()
        try:
            if proxmox is None:
                proxmox = connect_proxmox(settings)
                log("connected to Proxmox API")
            run_collection_cycle(settings, proxmox, active_breaches, fired_alert_keys)
        except Exception as exc:
            proxmox = None
            message = f"Erreur collecteur: {exc}"
            record_collector_run(settings.db_path, status="error", message=message)
            log(message)

        elapsed = time.monotonic() - cycle_started
        sleep_for = max(settings.collect_interval_seconds - elapsed, 1)
        time.sleep(sleep_for)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("collector stopped")
