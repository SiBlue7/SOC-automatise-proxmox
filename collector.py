import time
from datetime import datetime, timedelta
from typing import Dict, Set

from config import AppConfig, read_settings
from detection import build_signal_alert, evaluate_detection
from incident_engine import upsert_incident_for_alert
from ml_model import (
    MODEL_NAME,
    MODEL_VERSION,
    load_model,
    prediction_to_row,
    score_live_vm,
    train_and_save_model,
)
from proxmox_client import (
    connect_proxmox,
    fetch_node_status,
    fetch_nodes,
    fetch_qemu_vms,
    fetch_vm_statuses,
)
from storage import (
    fetch_ssh_distributed_counts,
    fetch_ssh_failure_counts,
    fetch_previous_vm_metric,
    fetch_ssh_source_failure_counts,
    fetch_ssh_success_after_failures,
    init_db,
    insert_host_metric,
    insert_ml_score,
    insert_vm_metric,
    insert_ssh_events,
    record_collector_run,
    record_ml_model_run,
    resolve_alerts_for_node,
    sync_incident_statuses_for_node,
    upsert_alert,
)
from ssh_log_collector import collect_target_logs, validate_ssh_setup


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
    ml_bundle,
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

            ssh_events_inserted = collect_ssh_events_for_node(settings, node_name, vm_statuses, sample_time)
            since = sample_time - timedelta(seconds=settings.ssh_correlation_window_seconds)
            ssh_failure_counts = fetch_ssh_failure_counts(settings.db_path, node_name, since)
            ssh_source_failure_counts = fetch_ssh_source_failure_counts(settings.db_path, node_name, since)
            ssh_distributed_counts = fetch_ssh_distributed_counts(settings.db_path, node_name, since)
            ssh_success_after_failures = fetch_ssh_success_after_failures(settings.db_path, node_name, since)
            for target in settings.ssh_log_targets:
                if target.vmid in vm_statuses:
                    ssh_failure_counts.setdefault(target.vmid, 0)

            evaluation = evaluate_detection(
                settings,
                node_name,
                node_status,
                vm_statuses,
                active_breaches,
                fired_alert_keys,
                ssh_failure_counts=ssh_failure_counts,
                ssh_source_failure_counts=ssh_source_failure_counts,
                ssh_distributed_counts=ssh_distributed_counts,
                ssh_success_after_failures=ssh_success_after_failures,
                now=sample_time,
            )
            ml_alerts = evaluate_ml_for_node(
                settings,
                node_name,
                vm_statuses,
                ssh_failure_counts,
                ssh_distributed_counts,
                ssh_success_after_failures,
                active_breaches,
                fired_alert_keys,
                sample_time,
                ml_bundle,
            )
            active_keys = set(evaluation.active_keys)
            active_keys.update(alert.alert_key for alert in ml_alerts)
            for alert in evaluation.current_alerts:
                alert_id, _ = upsert_alert(settings.db_path, alert)
                upsert_incident_for_alert(settings.db_path, alert_id, alert, sample_time)
            for alert in ml_alerts:
                alert_id, _ = upsert_alert(settings.db_path, alert)
                upsert_incident_for_alert(settings.db_path, alert_id, alert, sample_time)
            resolve_alerts_for_node(settings.db_path, node_name, active_keys, sample_time)
            sync_incident_statuses_for_node(settings.db_path, node_name, sample_time)

            nodes_seen += 1
            vm_count += len(vm_statuses)
            alerts_seen += len(evaluation.current_alerts) + len(ml_alerts)
            if ssh_events_inserted:
                log(f"ssh logs | node={node_name} inserted={ssh_events_inserted}")
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


def collect_ssh_events_for_node(
    settings: AppConfig,
    node_name: str,
    vm_statuses: Dict[int, Dict[str, object]],
    collected_at: datetime,
) -> int:
    inserted = 0
    if not settings.ssh_log_targets:
        return inserted

    for target in settings.ssh_log_targets:
        if target.vmid not in vm_statuses:
            continue
        result = collect_target_logs(settings, target, node_name, collected_at)
        if result.error:
            log(f"ssh logs error | vmid={target.vmid} host={target.host} | {result.error}")
            continue
        inserted += insert_ssh_events(settings.db_path, result.events)
    return inserted


def evaluate_ml_for_node(
    settings: AppConfig,
    node_name: str,
    vm_statuses: Dict[int, Dict[str, object]],
    ssh_failure_counts: Dict[int, int],
    ssh_distributed_counts: Dict[int, Dict[str, int]],
    ssh_success_after_failures: list,
    active_breaches: Dict[str, datetime],
    fired_alert_keys: Set[str],
    sample_time: datetime,
    ml_bundle,
):
    if not settings.ml_enabled or ml_bundle is None:
        return []

    success_after_failure_counts: Dict[int, int] = {}
    for signal in ssh_success_after_failures:
        vmid = int(signal.get("vmid", 0))
        if vmid <= 0:
            continue
        success_after_failure_counts[vmid] = success_after_failure_counts.get(vmid, 0) + 1

    alerts = []
    for vmid, vm_status in vm_statuses.items():
        previous_metric = fetch_previous_vm_metric(settings.db_path, node_name, vmid, sample_time)
        distributed = ssh_distributed_counts.get(vmid, {})
        prediction = score_live_vm(
            settings=settings,
            bundle=ml_bundle,
            node=node_name,
            vmid=vmid,
            vm_status=vm_status,
            previous_metric=previous_metric,
            ssh_failed_count=ssh_failure_counts.get(vmid, 0),
            ssh_source_count=int(distributed.get("source_count", 0)),
            ssh_success_after_failure_count=success_after_failure_counts.get(vmid, 0),
            timestamp=sample_time,
        )
        insert_ml_score(settings.db_path, prediction_to_row(prediction))

        alert_key = f"{node_name}:{vmid}:ml_isolation_forest_anomaly"
        if not prediction.is_anomaly:
            active_breaches.pop(alert_key, None)
            fired_alert_keys.discard(alert_key)
            continue

        active_since = active_breaches.setdefault(alert_key, sample_time)
        fired_alert_keys.add(alert_key)
        target_name = str(vm_status.get("name") or f"VM {vmid}")
        alerts.append(
            build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ml_isolation_forest_anomaly",
                metric="ml_anomaly_score",
                value=prediction.anomaly_score,
                threshold=settings.ml_score_warn,
                severity=prediction.severity,
                score=int(round(prediction.anomaly_score)),
                message=f"Anomalie comportementale Isolation Forest: {prediction.message}",
                active_since=active_since,
                detected_at=sample_time,
            )
        )
    return alerts


def initialize_ml_model(settings: AppConfig):
    if not settings.ml_enabled:
        log("ml disabled")
        return None
    try:
        bundle = load_model(settings)
        if bundle is not None:
            log(
                "ml model loaded | "
                f"name={bundle.get('model_name')} version={bundle.get('model_version')}"
            )
            return bundle
        if not settings.ml_auto_train:
            log("ml model missing | auto-train disabled")
            return None
        bundle = train_and_save_model(settings)
        evaluation = bundle.get("evaluation", {})
        record_ml_model_run(
            settings.db_path,
            model_name=str(bundle.get("model_name", MODEL_NAME)),
            model_version=str(bundle.get("model_version", MODEL_VERSION)),
            status="success",
            training_rows=int(bundle.get("training_rows", 0)),
            evaluation_rows=int(evaluation.get("evaluation_rows", 0)),
            accuracy=float(evaluation.get("accuracy", 0.0)),
            recall=float(evaluation.get("recall", 0.0)),
            precision=float(evaluation.get("precision", 0.0)),
            message="Auto-entrainement Isolation Forest au demarrage du collecteur.",
        )
        log(
            "ml model trained | "
            f"rows={bundle.get('training_rows')} path={settings.ml_model_path}"
        )
        return bundle
    except Exception as exc:
        record_ml_model_run(
            settings.db_path,
            model_name=MODEL_NAME,
            model_version=MODEL_VERSION,
            status="error",
            message=str(exc),
        )
        log(f"ml disabled after error | {exc}")
        return None


def main() -> None:
    settings = read_settings()
    init_db(settings.db_path)
    active_breaches: Dict[str, datetime] = {}
    fired_alert_keys: Set[str] = set()
    proxmox = None
    ml_bundle = initialize_ml_model(settings)

    log(
        "collector started | "
        f"interval={settings.collect_interval_seconds}s db={settings.db_path}"
    )
    ssh_setup_warning = validate_ssh_setup(settings)
    if ssh_setup_warning:
        log(f"ssh logs warning | {ssh_setup_warning}")

    while True:
        cycle_started = time.monotonic()
        try:
            if proxmox is None:
                proxmox = connect_proxmox(settings)
                log("connected to Proxmox API")
            run_collection_cycle(settings, proxmox, active_breaches, fired_alert_keys, ml_bundle)
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
