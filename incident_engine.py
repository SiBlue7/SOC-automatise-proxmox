from datetime import datetime
from typing import Optional, Tuple

from detection import AlertCandidate
from storage import link_alert_to_incident, upsert_incident


SSH_EVENT_TYPES = {
    "ssh_bruteforce_suspected",
    "ssh_cpu_correlated",
    "ssh_bruteforce_source",
    "ssh_bruteforce_distributed",
    "ssh_success_after_failures",
}

ML_EVENT_TYPES = {
    "ml_isolation_forest_anomaly",
}


def parse_source_identity(alert: AlertCandidate) -> Tuple[Optional[str], Optional[str]]:
    parts = alert.alert_key.split(":")
    if alert.event_type == "ssh_bruteforce_source" and len(parts) >= 5:
        return parts[-1], None
    if alert.event_type == "ssh_success_after_failures" and len(parts) >= 6:
        return parts[-2], parts[-1]
    return None, None


def incident_fields_for_alert(alert: AlertCandidate) -> Tuple[str, str, str, Optional[str], Optional[str]]:
    bucket = alert.active_since.strftime("%Y%m%d%H%M%S")
    if alert.event_type in SSH_EVENT_TYPES:
        source_ip, username = parse_source_identity(alert)
        title = f"Suspicion intrusion SSH sur VM {alert.vmid}"
        if alert.event_type == "ssh_success_after_failures":
            title = f"Succes SSH suspect sur VM {alert.vmid}"
        return "ssh_intrusion", title, f"{alert.node}:{alert.vmid}:ssh_intrusion:{bucket}", source_ip, username

    if alert.event_type in {"vm_cpu_pressure", "vm_ram_pressure"}:
        return (
            "resource_pressure",
            f"Pression ressources sur VM {alert.vmid}",
            f"{alert.node}:{alert.vmid}:resource_pressure:{bucket}",
            None,
            None,
        )

    if alert.event_type in ML_EVENT_TYPES:
        return (
            "ml_anomaly",
            f"Anomalie ML sur VM {alert.vmid}",
            f"{alert.node}:{alert.vmid}:ml_anomaly:{bucket}",
            None,
            None,
        )

    if alert.scope == "host":
        return (
            "host_pressure",
            f"Pression ressources sur noeud {alert.node}",
            f"{alert.node}:host:resource_pressure:{bucket}",
            None,
            None,
        )

    return (
        "generic",
        f"Incident {alert.event_type} sur VM {alert.vmid or 'host'}",
        f"{alert.node}:{alert.vmid or 'host'}:{alert.event_type}:{bucket}",
        None,
        None,
    )


def upsert_incident_for_alert(db_path: str, alert_id: int, alert: AlertCandidate, timestamp: Optional[datetime] = None) -> int:
    category, title, incident_key, source_ip, username = incident_fields_for_alert(alert)
    event_time = timestamp or alert.detected_at
    incident_id = upsert_incident(
        db_path=db_path,
        incident_key=incident_key,
        node=alert.node,
        vmid=alert.vmid,
        category=category,
        title=title,
        severity=alert.severity,
        score=alert.score,
        summary=alert.message,
        first_seen=alert.active_since,
        last_seen=alert.detected_at,
        source_ip=source_ip,
        username=username,
    )
    link_alert_to_incident(db_path, incident_id, alert_id, event_time)
    return incident_id
