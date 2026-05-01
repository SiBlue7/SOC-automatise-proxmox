from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

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
        "ssh_failed_count": "Echecs SSH",
        "ssh_failed_count_source": "Echecs SSH par source",
        "ssh_source_count": "Sources SSH distinctes",
        "ssh_cpu_correlation": "Correlation SSH/CPU",
        "ssh_success_after_failures": "Succes SSH apres echecs",
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


def build_signal_alert(
    node_name: str,
    vmid: int,
    target_name: str,
    event_type: str,
    metric: str,
    value: float,
    threshold: float,
    severity: str,
    score: int,
    message: str,
    active_since: datetime,
    detected_at: datetime,
) -> AlertCandidate:
    return AlertCandidate(
        alert_key=f"{node_name}:{vmid}:{event_type}",
        node=node_name,
        vmid=vmid,
        scope="vm",
        event_type=event_type,
        metric=metric,
        value=round(value, 2),
        threshold=threshold,
        severity=severity,
        score=score,
        message=f"{message} sur VM {vmid} ({target_name}).",
        active_since=active_since,
        detected_at=detected_at,
    )


def evaluate_ssh_signals(
    settings: AppConfig,
    node_name: str,
    vm_statuses: Dict[int, Dict[str, object]],
    ssh_failure_counts: Dict[int, int],
    ssh_source_failure_counts: Optional[Dict[Tuple[int, str], int]],
    ssh_distributed_counts: Optional[Dict[int, Dict[str, int]]],
    ssh_success_after_failures: Optional[List[Dict[str, object]]],
    active_breaches: Dict[str, datetime],
    fired_alert_keys: Set[str],
    detected_at: datetime,
) -> DetectionEvaluation:
    current_alerts: List[AlertCandidate] = []
    new_alerts: List[AlertCandidate] = []
    active_keys: Set[str] = set()

    for vmid, failure_count in ssh_failure_counts.items():
        vm_status = vm_statuses.get(vmid, {"name": f"VM {vmid}", "cpu": 0.0})
        target_name = str(vm_status.get("name") or f"VM {vmid}")
        cpu_percent = float(vm_status.get("cpu", 0.0)) * 100

        correlated_key = f"{node_name}:{vmid}:ssh_cpu_correlated"
        brute_force_key = f"{node_name}:{vmid}:ssh_bruteforce_suspected"

        if failure_count >= settings.ssh_auth_failure_warn and cpu_percent >= settings.ssh_correlation_cpu_threshold:
            active_since = active_breaches.setdefault(correlated_key, detected_at)
            severity = "critical" if failure_count >= settings.ssh_auth_failure_critical else "medium"
            score = 95 if severity == "critical" else 82
            alert = build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ssh_cpu_correlated",
                metric="ssh_cpu_correlation",
                value=failure_count,
                threshold=settings.ssh_auth_failure_warn,
                severity=severity,
                score=score,
                message=(
                    f"Correlation suspecte: {failure_count} echecs SSH recents "
                    f"et CPU VM a {cpu_percent:.2f}%"
                ),
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(correlated_key)
            if correlated_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(correlated_key)
        else:
            active_breaches.pop(correlated_key, None)
            fired_alert_keys.discard(correlated_key)

        if failure_count >= settings.ssh_auth_failure_warn:
            active_since = active_breaches.setdefault(brute_force_key, detected_at)
            severity = "critical" if failure_count >= settings.ssh_auth_failure_critical else "medium"
            score = min(100, 60 + int((failure_count / settings.ssh_auth_failure_critical) * 35))
            alert = build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ssh_bruteforce_suspected",
                metric="ssh_failed_count",
                value=failure_count,
                threshold=settings.ssh_auth_failure_warn,
                severity=severity,
                score=score,
                message=f"Brute-force SSH probable: {failure_count} echecs SSH recents",
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(brute_force_key)
            if brute_force_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(brute_force_key)
        else:
            active_breaches.pop(brute_force_key, None)
            fired_alert_keys.discard(brute_force_key)

    if ssh_source_failure_counts:
        for (vmid, source_ip), failure_count in ssh_source_failure_counts.items():
            if failure_count < settings.ssh_source_failure_warn:
                continue
            vm_status = vm_statuses.get(vmid, {"name": f"VM {vmid}"})
            target_name = str(vm_status.get("name") or f"VM {vmid}")
            alert_key = f"{node_name}:{vmid}:ssh_bruteforce_source:{source_ip}"
            active_since = active_breaches.setdefault(alert_key, detected_at)
            severity = "critical" if failure_count >= settings.ssh_auth_failure_critical else "medium"
            score = min(100, 68 + int((failure_count / settings.ssh_auth_failure_critical) * 27))
            alert = build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ssh_bruteforce_source",
                metric="ssh_failed_count_source",
                value=failure_count,
                threshold=settings.ssh_source_failure_warn,
                severity=severity,
                score=score,
                message=f"Brute-force SSH probable depuis {source_ip}: {failure_count} echecs recents",
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(alert_key)
            if alert_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(alert_key)

    if ssh_distributed_counts:
        for vmid, counters in ssh_distributed_counts.items():
            source_count = int(counters.get("source_count", 0))
            failure_count = int(counters.get("failure_count", 0))
            if source_count < settings.ssh_distributed_source_warn or failure_count < settings.ssh_auth_failure_warn:
                continue
            vm_status = vm_statuses.get(vmid, {"name": f"VM {vmid}"})
            target_name = str(vm_status.get("name") or f"VM {vmid}")
            alert_key = f"{node_name}:{vmid}:ssh_bruteforce_distributed"
            active_since = active_breaches.setdefault(alert_key, detected_at)
            severity = "critical" if failure_count >= settings.ssh_auth_failure_critical else "medium"
            score = min(100, 72 + (source_count * 4) + int((failure_count / settings.ssh_auth_failure_critical) * 16))
            alert = build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ssh_bruteforce_distributed",
                metric="ssh_source_count",
                value=source_count,
                threshold=settings.ssh_distributed_source_warn,
                severity=severity,
                score=score,
                message=(
                    f"Brute-force SSH distribue probable: {failure_count} echecs "
                    f"depuis {source_count} sources"
                ),
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(alert_key)
            if alert_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(alert_key)

    if ssh_success_after_failures:
        for signal in ssh_success_after_failures:
            vmid = int(signal["vmid"])
            source_ip = str(signal.get("source_ip") or "unknown")
            username = str(signal.get("username") or "unknown")
            failure_count = int(signal.get("failure_count", 0))
            if failure_count < settings.ssh_success_after_failure_warn:
                continue
            vm_status = vm_statuses.get(vmid, {"name": f"VM {vmid}"})
            target_name = str(vm_status.get("name") or f"VM {vmid}")
            alert_key = f"{node_name}:{vmid}:ssh_success_after_failures:{source_ip}:{username}"
            active_since = active_breaches.setdefault(alert_key, detected_at)
            alert = build_signal_alert(
                node_name=node_name,
                vmid=vmid,
                target_name=target_name,
                event_type="ssh_success_after_failures",
                metric="ssh_success_after_failures",
                value=failure_count,
                threshold=settings.ssh_success_after_failure_warn,
                severity="critical",
                score=98,
                message=(
                    f"Connexion SSH reussie apres {failure_count} echecs "
                    f"pour {username} depuis {source_ip}"
                ),
                active_since=active_since,
                detected_at=detected_at,
            )
            current_alerts.append(alert)
            active_keys.add(alert_key)
            if alert_key not in fired_alert_keys:
                new_alerts.append(alert)
                fired_alert_keys.add(alert_key)

    return DetectionEvaluation(current_alerts=current_alerts, new_alerts=new_alerts, active_keys=active_keys)


def evaluate_detection(
    settings: AppConfig,
    node_name: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    active_breaches: Dict[str, datetime],
    fired_alert_keys: Set[str],
    ssh_failure_counts: Optional[Dict[int, int]] = None,
    ssh_source_failure_counts: Optional[Dict[Tuple[int, str], int]] = None,
    ssh_distributed_counts: Optional[Dict[int, Dict[str, int]]] = None,
    ssh_success_after_failures: Optional[List[Dict[str, object]]] = None,
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

    if ssh_failure_counts is not None:
        ssh_evaluation = evaluate_ssh_signals(
            settings,
            node_name,
            vm_statuses,
            ssh_failure_counts,
            ssh_source_failure_counts,
            ssh_distributed_counts,
            ssh_success_after_failures,
            active_breaches,
            fired_alert_keys,
            detected_at,
        )
        current_alerts.extend(ssh_evaluation.current_alerts)
        new_alerts.extend(ssh_evaluation.new_alerts)
        active_keys.update(ssh_evaluation.active_keys)

    current_alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.score), reverse=True)
    new_alerts.sort(key=lambda alert: (SEVERITY_ORDER[alert.severity], alert.score), reverse=True)
    return DetectionEvaluation(current_alerts=current_alerts, new_alerts=new_alerts, active_keys=active_keys)
