from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set

from config import AppConfig


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    scope: str
    metric: str
    warn_threshold: float
    critical_threshold: float
    description: str


@dataclass(frozen=True)
class AlertCandidate:
    alert_key: str
    node: str
    vmid: Optional[int]
    scope: str
    event_type: str
    metric: str
    value: float
    threshold: float
    severity: str
    score: int
    message: str
    active_since: datetime
    detected_at: datetime


@dataclass(frozen=True)
class DetectionEvaluation:
    current_alerts: List[AlertCandidate]
    new_alerts: List[AlertCandidate]
    active_keys: Set[str]


SEVERITY_ORDER = {"low": 1, "medium": 2, "critical": 3}


def build_rules(settings: AppConfig) -> List[DetectionRule]:
    return [
        DetectionRule(
            rule_id="host_cpu_pressure",
            scope="host",
            metric="cpu_percent",
            warn_threshold=settings.host_cpu_warn,
            critical_threshold=settings.host_cpu_critical,
            description="Surcharge CPU du noeud Proxmox",
        ),
        DetectionRule(
            rule_id="vm_cpu_pressure",
            scope="vm",
            metric="cpu_percent",
            warn_threshold=settings.vm_cpu_warn,
            critical_threshold=settings.vm_cpu_critical,
            description="Surcharge CPU d'une VM QEMU",
        ),
        DetectionRule(
            rule_id="vm_ram_pressure",
            scope="vm",
            metric="ram_percent",
            warn_threshold=settings.vm_ram_warn,
            critical_threshold=settings.vm_ram_critical,
            description="Pression RAM d'une VM QEMU",
        ),
    ]


def severity_for(value: float, warn_threshold: float, critical_threshold: float) -> str:
    if value >= critical_threshold:
        return "critical"
    midpoint = warn_threshold + ((critical_threshold - warn_threshold) / 2)
    if value >= midpoint:
        return "medium"
    return "low"


def score_for(value: float, warn_threshold: float, critical_threshold: float) -> int:
    if value >= critical_threshold:
        overflow = min(value - critical_threshold, 5.0)
        return min(100, int(90 + (overflow * 2)))

    span = max(critical_threshold - warn_threshold, 1.0)
    ratio = max(0.0, min((value - warn_threshold) / span, 1.0))
    return int(40 + (ratio * 49))


def metric_label(metric: str) -> str:
    labels = {
        "cpu_percent": "CPU",
        "ram_percent": "RAM",
    }
    return labels.get(metric, metric)


def vm_ram_percent(vm_status: Dict[str, object]) -> float:
    maxmem = int(vm_status.get("maxmem", 0))
    if maxmem <= 0:
        return 0.0
    return (int(vm_status.get("mem", 0)) / maxmem) * 100


def get_metric_value(rule: DetectionRule, target: Dict[str, object]) -> float:
    if rule.metric == "cpu_percent":
        return float(target.get("cpu", 0.0)) * 100
    if rule.metric == "ram_percent":
        return vm_ram_percent(target)
    return 0.0


def build_alert(
    rule: DetectionRule,
    node_name: str,
    vmid: Optional[int],
    target_name: str,
    value: float,
    active_since: datetime,
    detected_at: datetime,
) -> AlertCandidate:
    severity = severity_for(value, rule.warn_threshold, rule.critical_threshold)
    threshold = rule.critical_threshold if severity == "critical" else rule.warn_threshold
    score = score_for(value, rule.warn_threshold, rule.critical_threshold)
    label = metric_label(rule.metric)
    scope_label = "host" if vmid is None else f"VM {vmid}"
    message = (
        f"{rule.description}: {label} a {value:.2f}% sur {scope_label} "
        f"({target_name})."
    )

    key_vmid = "host" if vmid is None else str(vmid)
    return AlertCandidate(
        alert_key=f"{node_name}:{key_vmid}:{rule.rule_id}",
        node=node_name,
        vmid=vmid,
        scope=rule.scope,
        event_type=rule.rule_id,
        metric=rule.metric,
        value=round(value, 2),
        threshold=threshold,
        severity=severity,
        score=score,
        message=message,
        active_since=active_since,
        detected_at=detected_at,
    )


def evaluate_detection(
    settings: AppConfig,
    node_name: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    active_breaches: Dict[str, datetime],
    fired_alert_keys: Set[str],
    now: Optional[datetime] = None,
) -> DetectionEvaluation:
    detected_at = now or datetime.now()
    rules = build_rules(settings)
    current_alerts: List[AlertCandidate] = []
    new_alerts: List[AlertCandidate] = []
    active_keys: Set[str] = set()

    targets = []
    targets.append(("host", None, node_name, node_status))
    for vmid, vm_status in vm_statuses.items():
        targets.append(("vm", vmid, str(vm_status.get("name") or f"VM {vmid}"), vm_status))

    for scope, vmid, target_name, target in targets:
        for rule in rules:
            if rule.scope != scope:
                continue

            value = get_metric_value(rule, target)
            key_vmid = "host" if vmid is None else str(vmid)
            alert_key = f"{node_name}:{key_vmid}:{rule.rule_id}"

            if value < rule.warn_threshold:
                active_breaches.pop(alert_key, None)
                fired_alert_keys.discard(alert_key)
                continue

            active_since = active_breaches.setdefault(alert_key, detected_at)
            elapsed_seconds = (detected_at - active_since).total_seconds()
            if elapsed_seconds < settings.alert_min_duration_seconds:
                active_keys.add(alert_key)
                continue

            alert = build_alert(
                rule=rule,
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                value=value,
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(alert_key)

            if alert_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(alert_key)

    current_alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.score), reverse=True)
    new_alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.score), reverse=True)
    return DetectionEvaluation(current_alerts=current_alerts, new_alerts=new_alerts, active_keys=active_keys)
