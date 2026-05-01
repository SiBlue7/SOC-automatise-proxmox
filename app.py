from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st

from actions import get_net0_state, is_protected_vmid, set_vm_network_state
from config import AppConfig, read_settings
from detection import AlertCandidate, evaluate_detection
from proxmox_client import (
    connect_proxmox_with_token,
    fetch_node_status,
    fetch_nodes,
    fetch_qemu_vms,
    fetch_vm_statuses,
)
from storage import (
    fetch_actions,
    fetch_alerts,
    fetch_latest_collector_run,
    fetch_recent_ssh_events,
    fetch_soc_metrics,
    init_db,
    insert_action,
    insert_host_metric,
    insert_vm_metric,
    resolve_alerts_for_node,
    upsert_alert,
)


def bytes_to_gib(value: int) -> float:
    return value / (1024 ** 3)


def percent_ratio(used: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return (used / total) * 100


def format_used_total_gib(used: int, total: int) -> str:
    return f"{bytes_to_gib(used):.2f} / {bytes_to_gib(total):.2f} GiB"


def format_uptime(seconds: int) -> str:
    if seconds <= 0:
        return "0m"

    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}j")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def format_duration(seconds: float) -> str:
    if seconds <= 0:
        return "0s"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, remainder = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {remainder}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def severity_badge(severity: str) -> str:
    labels = {
        "critical": "Critique",
        "medium": "Moyen",
        "low": "Faible",
    }
    return labels.get(severity, severity)


def ensure_session_state() -> None:
    st.session_state.setdefault("node_history", {})
    st.session_state.setdefault("vm_history", {})
    st.session_state.setdefault("action_feedback", None)
    st.session_state.setdefault("selected_node", None)
    st.session_state.setdefault("selected_vmid", None)
    st.session_state.setdefault("active_breaches", {})
    st.session_state.setdefault("fired_alert_keys", set())


def append_history(settings: AppConfig, bucket_name: str, key: str, sample: Dict[str, object]) -> None:
    bucket = st.session_state[bucket_name]
    history = bucket.setdefault(key, [])
    history.append(sample)
    if len(history) > settings.max_history_points:
        del history[:-settings.max_history_points]


def history_frame(bucket_name: str, key: str) -> pd.DataFrame:
    history = st.session_state[bucket_name].get(key, [])
    frame = pd.DataFrame(history)
    if frame.empty:
        return frame
    return frame.set_index("timestamp")


def capture_node_history(settings: AppConfig, node_name: str, node_status: Dict[str, object]) -> None:
    memory = node_status.get("memory", {})
    swap = node_status.get("swap", {})
    append_history(
        settings,
        "node_history",
        node_name,
        {
            "timestamp": datetime.now(),
            "CPU %": round(float(node_status.get("cpu", 0.0)) * 100, 2),
            "RAM utilisee (GiB)": round(bytes_to_gib(int(memory.get("used", 0))), 2),
            "SWAP utilisee (GiB)": round(bytes_to_gib(int(swap.get("used", 0))), 2),
        },
    )


def capture_vm_history(settings: AppConfig, node_name: str, vm_statuses: Dict[int, Dict[str, object]]) -> None:
    timestamp = datetime.now()
    for vmid, vm in vm_statuses.items():
        history_key = f"{node_name}:{vmid}"
        append_history(
            settings,
            "vm_history",
            history_key,
            {
                "timestamp": timestamp,
                "CPU %": round(float(vm.get("cpu", 0.0)) * 100, 2),
                "RAM utilisee (GiB)": round(bytes_to_gib(int(vm.get("mem", 0))), 2),
            },
        )


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


def format_vm_table(vm_statuses: Dict[int, Dict[str, object]]) -> pd.DataFrame:
    rows = []
    for vmid in sorted(vm_statuses):
        vm = vm_statuses[vmid]
        maxmem = int(vm.get("maxmem", 0))
        mem = int(vm.get("mem", 0))
        rows.append(
            {
                "VMID": vmid,
                "Nom": vm.get("name") or f"VM {vmid}",
                "Etat": vm.get("status", "unknown"),
                "CPU %": round(float(vm.get("cpu", 0.0)) * 100, 2),
                "RAM %": round(percent_ratio(mem, maxmem), 2),
                "RAM utilisee (GiB)": round(bytes_to_gib(mem), 2),
                "RAM max (GiB)": round(bytes_to_gib(maxmem), 2),
                "Uptime": format_uptime(int(vm.get("uptime", 0))),
            }
        )
    return pd.DataFrame(rows)


def render_line_chart(frame: pd.DataFrame, columns: List[str], height: int = 180) -> None:
    if frame.empty:
        st.caption("Historique en attente de donnees...")
        return
    st.line_chart(frame[columns], height=height, use_container_width=True)


def render_alert_banner(current_alerts: List[AlertCandidate]) -> None:
    if not current_alerts:
        st.success("Aucune alerte active selon les regles configurees.")
        return

    for alert in current_alerts[:3]:
        text = f"{severity_badge(alert.severity)} | score {alert.score}/100 | {alert.message}"
        if alert.severity == "critical":
            st.error(text)
        elif alert.severity == "medium":
            st.warning(text)
        else:
            st.info(text)


def render_soc_metrics(settings: AppConfig) -> None:
    metrics = fetch_soc_metrics(settings.db_path)
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Alertes actives", metrics["active_alerts"])
    col2.metric("Alertes total", metrics["total_alerts"])
    col3.metric("Actions journalisees", metrics["total_actions"])
    col4.metric("Evenements SSH", metrics["total_ssh_events"])
    col5.metric("MTTD moyen", format_duration(metrics["avg_mttd"]))
    st.caption(f"MTTR moyen observe: {format_duration(metrics['avg_mttr'])}")


def render_collector_status(settings: AppConfig) -> None:
    latest_run = fetch_latest_collector_run(settings.db_path)
    if latest_run is None:
        st.info("Collecteur: aucun cycle journalise.")
        return

    try:
        last_seen = datetime.fromisoformat(str(latest_run["timestamp"]))
        age_seconds = (datetime.now() - last_seen).total_seconds()
    except ValueError:
        st.warning("Collecteur: horodatage illisible.")
        return

    status = str(latest_run["status"])
    message = str(latest_run["message"])
    details = (
        f"Dernier passage: {format_duration(age_seconds)} | "
        f"noeuds={latest_run['nodes_seen']} vms={latest_run['vm_count']} "
        f"alertes={latest_run['alerts_seen']}"
    )

    if status == "error":
        st.error(f"Collecteur: erreur. {details}")
        st.caption(message)
    elif status == "warning":
        st.warning(f"Collecteur: attention. {details}")
        st.caption(message)
    elif age_seconds <= settings.collector_heartbeat_seconds:
        st.success(f"Collecteur: actif. {details}")
    elif age_seconds <= settings.collector_heartbeat_seconds * 3:
        st.warning(f"Collecteur: en retard. {details}")
    else:
        st.error(f"Collecteur: inactif ou bloque. {details}")


def format_alerts_dataframe(alerts: List[Dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(alerts)
    if frame.empty:
        return frame
    frame = frame.rename(
        columns={
            "id": "ID",
            "first_seen": "Detection",
            "last_seen": "Derniere vue",
            "resolved_at": "Resolution",
            "node": "Noeud",
            "vmid": "VMID",
            "scope": "Portee",
            "event_type": "Type",
            "metric": "Metrique",
            "value": "Valeur",
            "threshold": "Seuil",
            "severity": "Severite",
            "score": "Score",
            "status": "Statut",
            "message": "Message",
        }
    )
    return frame


def format_actions_dataframe(actions: List[Dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(actions)
    if frame.empty:
        return frame
    frame = frame.rename(
        columns={
            "id": "ID",
            "timestamp": "Horodatage",
            "node": "Noeud",
            "vmid": "VMID",
            "action": "Action",
            "result": "Resultat",
            "protected": "VM protegee",
            "message": "Message",
        }
    )
    return frame


def format_ssh_events_dataframe(events: List[Dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(events)
    if frame.empty:
        return frame
    frame = frame.rename(
        columns={
            "id": "ID",
            "timestamp": "Horodatage",
            "collected_at": "Collecte",
            "node": "Noeud",
            "vmid": "VMID",
            "target_host": "Cible",
            "source_ip": "Source",
            "username": "Utilisateur",
            "event_type": "Evenement",
            "raw_line": "Log brut",
        }
    )
    return frame


def render_incidents_tab(settings: AppConfig, node_names: List[str], vm_statuses: Dict[int, Dict[str, object]]) -> None:
    render_soc_metrics(settings)
    st.divider()

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
    node_filter = filter_col1.selectbox("Filtre noeud", options=["Tous", *node_names])
    vm_choices = {"Toutes": None}
    for vmid in sorted(vm_statuses):
        vm_choices[f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}"] = vmid
    vm_filter_label = filter_col2.selectbox("Filtre VM", options=list(vm_choices.keys()))
    severity_filter = filter_col3.selectbox("Severite", options=["Toutes", "critical", "medium", "low"])
    status_filter = filter_col4.selectbox("Statut", options=["Tous", "active", "resolved"])

    alerts = fetch_alerts(
        settings.db_path,
        node=node_filter,
        vmid=vm_choices[vm_filter_label],
        severity=severity_filter,
        status=status_filter,
    )
    alerts_frame = format_alerts_dataframe(alerts)
    if alerts_frame.empty:
        st.info("Aucune alerte ne correspond aux filtres.")
        return

    st.dataframe(alerts_frame, use_container_width=True, hide_index=True)

    alert_ids = [int(alert["id"]) for alert in alerts]
    selected_alert_id = st.selectbox("Timeline incident", options=alert_ids)
    selected_alert = next(alert for alert in alerts if int(alert["id"]) == selected_alert_id)
    actions = fetch_actions(settings.db_path, limit=200)

    timeline_rows = [
        {
            "Horodatage": selected_alert["first_seen"],
            "Evenement": "Detection",
            "Detail": selected_alert["message"],
        }
    ]
    if selected_alert.get("resolved_at"):
        timeline_rows.append(
            {
                "Horodatage": selected_alert["resolved_at"],
                "Evenement": "Resolution metrique",
                "Detail": "La condition d'alerte n'est plus observee.",
            }
        )

    for action in actions:
        same_node = action["node"] == selected_alert["node"]
        same_vmid = action["vmid"] == selected_alert["vmid"]
        after_detection = action["timestamp"] >= selected_alert["first_seen"]
        if same_node and same_vmid and after_detection:
            timeline_rows.append(
                {
                    "Horodatage": action["timestamp"],
                    "Evenement": action["action"],
                    "Detail": action["message"],
                }
            )

    timeline_frame = pd.DataFrame(timeline_rows).sort_values("Horodatage")
    st.dataframe(timeline_frame, use_container_width=True, hide_index=True)


def render_host_tab(
    settings: AppConfig,
    selected_node: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    current_alerts: List[AlertCandidate],
) -> None:
    node_history = history_frame("node_history", selected_node)

    st.subheader("Vue globale du serveur Proxmox")
    st.caption(f"Noeud surveille: {selected_node}")

    memory = node_status.get("memory", {})
    swap = node_status.get("swap", {})
    cpu_percent = float(node_status.get("cpu", 0.0)) * 100
    memory_used = int(memory.get("used", 0))
    memory_total = int(memory.get("total", 0))
    swap_used = int(swap.get("used", 0))
    swap_total = int(swap.get("total", 0))

    metric_cpu, metric_ram, metric_swap = st.columns(3)
    metric_cpu.metric("CPU host", f"{cpu_percent:.2f}%")
    metric_ram.metric(
        "RAM host",
        format_used_total_gib(memory_used, memory_total),
        f"{percent_ratio(memory_used, memory_total):.1f}%",
    )
    metric_swap.metric(
        "SWAP host",
        format_used_total_gib(swap_used, swap_total),
        f"{percent_ratio(swap_used, swap_total):.1f}%",
    )

    chart_cpu, chart_ram, chart_swap = st.columns(3)
    with chart_cpu:
        render_line_chart(node_history, ["CPU %"])
    with chart_ram:
        render_line_chart(node_history, ["RAM utilisee (GiB)"])
    with chart_swap:
        render_line_chart(node_history, ["SWAP utilisee (GiB)"])

    render_alert_banner(current_alerts)

    st.divider()
    st.subheader("Inventaire QEMU")
    if vm_statuses:
        st.dataframe(format_vm_table(vm_statuses), use_container_width=True, hide_index=True)
    else:
        st.info("Aucune VM QEMU detectee sur ce noeud.")

    st.subheader("Statistiques par VM QEMU")
    if not vm_statuses:
        st.warning("Aucune VM disponible pour afficher une telemetrie detaillee.")
        return

    sorted_vmids = sorted(vm_statuses)
    stored_vmid = st.session_state.get("selected_vmid")
    if stored_vmid not in sorted_vmids:
        stored_vmid = sorted_vmids[0]
    st.session_state["selected_vmid"] = stored_vmid

    for vmid in sorted_vmids:
        vm = vm_statuses[vmid]
        vm_history = history_frame("vm_history", f"{selected_node}:{vmid}")
        vm_title = f"{vmid} - {vm.get('name') or f'VM {vmid}'}"

        with st.expander(vm_title, expanded=(vmid == stored_vmid)):
            info_col1, info_col2, info_col3 = st.columns(3)
            info_col1.metric("Etat", str(vm.get("status", "unknown")).upper())
            info_col2.metric("CPU", f"{float(vm.get('cpu', 0.0)) * 100:.2f}%")
            info_col3.metric(
                "RAM",
                format_used_total_gib(int(vm.get("mem", 0)), int(vm.get("maxmem", 0))),
                f"{percent_ratio(int(vm.get('mem', 0)), int(vm.get('maxmem', 0))):.1f}%",
            )

            extra_left, extra_right = st.columns(2)
            extra_left.caption(f"Uptime: {format_uptime(int(vm.get('uptime', 0)))}")
            if vm.get("status_error"):
                extra_right.caption(f"Details API partiels: {vm['status_error']}")

            chart_left, chart_right = st.columns(2)
            with chart_left:
                render_line_chart(vm_history, ["CPU %"], height=160)
            with chart_right:
                render_line_chart(vm_history, ["RAM utilisee (GiB)"], height=160)


def render_response_tab(settings: AppConfig, proxmox, selected_node: str, vm_statuses: Dict[int, Dict[str, object]]) -> None:
    st.subheader("Reponse active human-in-the-loop")
    st.caption("Perimetre volontaire du POC: VM QEMU uniquement, interface net0 uniquement.")

    if not vm_statuses:
        st.warning("Aucune VM disponible pour lancer une action d'isolement.")
        return

    vm_options = {
        f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}": vmid
        for vmid in sorted(vm_statuses)
    }
    selected_label = st.selectbox(
        "VM a isoler ou restaurer",
        options=list(vm_options.keys()),
        index=list(vm_options.values()).index(st.session_state["selected_vmid"])
        if st.session_state["selected_vmid"] in vm_options.values()
        else 0,
        key="vm_action_select",
    )
    selected_vmid = vm_options[selected_label]
    st.session_state["selected_vmid"] = selected_vmid
    protected = is_protected_vmid(selected_vmid, settings.protected_vmids)

    action_feedback = st.session_state.get("action_feedback")
    if action_feedback:
        getattr(st, action_feedback["level"])(action_feedback["message"])

    try:
        network_state = get_net0_state(proxmox, selected_node, selected_vmid)
    except Exception as exc:
        network_state = None
        st.error(f"Impossible de lire l'etat de net0: {exc}")

    if network_state:
        if network_state.isolated is True:
            st.warning(network_state.message)
        elif network_state.isolated is False:
            st.info(network_state.message)
        else:
            st.error(network_state.message)

    if protected:
        st.warning("Cette VM est protegee par PROTECTED_VMIDS: l'isolement est bloque.")

    confirm_key = f"confirm_isolate_{selected_node}_{selected_vmid}"
    confirmed = st.checkbox(
        f"Je confirme l'isolement reseau de la VM {selected_vmid} sur net0.",
        key=confirm_key,
        disabled=protected,
    )

    isolate_col, restore_col = st.columns(2)
    action_result = None

    can_isolate = bool(network_state and network_state.isolated is False and confirmed and not protected)
    can_restore = bool(network_state and network_state.isolated is True)

    with isolate_col:
        if st.button(
            "ISOLER (couper net0)",
            type="primary",
            use_container_width=True,
            disabled=not can_isolate,
        ):
            if protected:
                message = f"Isolation bloquee: VM {selected_vmid} protegee."
                insert_action(settings.db_path, selected_node, selected_vmid, "isolate", "blocked", message, True)
                action_result = ("error", message)
            else:
                try:
                    success, message = set_vm_network_state(proxmox, selected_node, selected_vmid, isolated=True)
                    result = "success" if success else "error"
                    insert_action(settings.db_path, selected_node, selected_vmid, "isolate", result, message, protected)
                    action_result = ("success" if success else "error", message)
                except Exception as exc:
                    message = f"Echec de l'isolement sur la VM {selected_vmid}: {exc}"
                    insert_action(settings.db_path, selected_node, selected_vmid, "isolate", "error", message, protected)
                    action_result = ("error", message)

    with restore_col:
        if st.button(
            "RESTAURER LE RESEAU",
            use_container_width=True,
            disabled=not can_restore,
        ):
            try:
                success, message = set_vm_network_state(proxmox, selected_node, selected_vmid, isolated=False)
                result = "success" if success else "error"
                insert_action(settings.db_path, selected_node, selected_vmid, "restore", result, message, protected)
                action_result = ("success" if success else "error", message)
            except Exception as exc:
                message = f"Echec de la restauration reseau sur la VM {selected_vmid}: {exc}"
                insert_action(settings.db_path, selected_node, selected_vmid, "restore", "error", message, protected)
                action_result = ("error", message)

    if action_result:
        level, message = action_result
        st.session_state["action_feedback"] = {"level": level, "message": message}
        st.rerun()

    st.divider()
    st.subheader("Journal d'audit recent")
    actions_frame = format_actions_dataframe(fetch_actions(settings.db_path, limit=50))
    if actions_frame.empty:
        st.info("Aucune action journalisee pour le moment.")
    else:
        st.dataframe(actions_frame, use_container_width=True, hide_index=True)


def render_audit_tab(settings: AppConfig) -> None:
    st.subheader("Journal d'audit des actions")
    actions_frame = format_actions_dataframe(fetch_actions(settings.db_path, limit=200))
    if actions_frame.empty:
        st.info("Aucune action de reponse active n'a encore ete journalisee.")
    else:
        st.dataframe(actions_frame, use_container_width=True, hide_index=True)


def render_ssh_events_tab(settings: AppConfig, node_names: List[str], vm_statuses: Dict[int, Dict[str, object]]) -> None:
    st.subheader("Evenements SSH collectes")
    if not settings.ssh_log_targets:
        st.info("Aucune cible SSH configuree. Renseigne SSH_LOG_TARGETS pour activer cette vue.")
        return

    filter_col1, filter_col2 = st.columns(2)
    node_filter = filter_col1.selectbox("Noeud logs SSH", options=["Tous", *node_names])
    vm_choices = {"Toutes": None}
    for vmid in sorted(vm_statuses):
        vm_choices[f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}"] = vmid
    vm_filter_label = filter_col2.selectbox("VM logs SSH", options=list(vm_choices.keys()))

    events = fetch_recent_ssh_events(
        settings.db_path,
        limit=200,
        node=node_filter,
        vmid=vm_choices[vm_filter_label],
    )
    events_frame = format_ssh_events_dataframe(events)
    if events_frame.empty:
        st.info("Aucun evenement SSH collecte pour les filtres selectionnes.")
    else:
        st.dataframe(events_frame, use_container_width=True, hide_index=True)


def get_fragment_decorator(run_every: Optional[str]):
    fragment_api = getattr(st, "fragment", None)
    if fragment_api is None:
        def passthrough(func):
            return func
        return passthrough
    return fragment_api(run_every=run_every)


@st.cache_resource(show_spinner=False)
def cached_connect(host: str, user: str, token_id: str, token_secret: str, verify_ssl: bool):
    return connect_proxmox_with_token(host, user, token_id, token_secret, verify_ssl)


def get_connection(settings: AppConfig):
    try:
        return (
            cached_connect(
                settings.host,
                settings.user,
                settings.token_id,
                settings.token_secret,
                settings.verify_ssl,
            ),
            "",
        )
    except Exception as exc:
        return None, str(exc)


st.set_page_config(page_title="Proxmox Sentinel - SOC Interface", layout="wide")

st.markdown(
    """
    <style>
    div.stButton > button[kind="primary"] {
        background-color: #b91c1c;
        border: 1px solid #991b1b;
        color: white;
    }
    div.stButton > button[kind="primary"]:hover {
        background-color: #991b1b;
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

ensure_session_state()

st.title("Proxmox Sentinel - SOC Interface")
st.caption(
    "Supervision Proxmox, detection comportementale explicable, persistence SQLite "
    "et reponse active controlee par analyste."
)

try:
    settings = read_settings()
    init_db(settings.db_path)
    settings_error = ""
except Exception as exc:
    settings = None
    settings_error = str(exc)

with st.sidebar:
    st.header("Etat de la plateforme")
    if settings is None:
        st.error(f"Configuration invalide: {settings_error}")
    else:
        st.caption(f"Base SQLite: {settings.db_path}")
        if not settings.verify_ssl:
            st.warning("VERIFY_SSL=False est adapte au lab, pas a la production.")
        if settings.protected_vmids:
            protected_list = ", ".join(str(vmid) for vmid in sorted(settings.protected_vmids))
            st.info(f"VM protegees: {protected_list}")
        render_collector_status(settings)
        if settings.ssh_log_targets:
            targets = ", ".join(f"{target.vmid}@{target.host}" for target in settings.ssh_log_targets)
            st.caption(f"Logs SSH: {targets}")
        if settings.app_persist_on_render:
            st.warning("APP_PERSIST_ON_RENDER=True: Streamlit ecrit aussi les metriques.")
        else:
            st.caption("Persistance UI desactivee: collecte assuree par proxmox-collector.")

if settings is None:
    st.info("Complete le fichier .env avec des identifiants API valides pour afficher le dashboard.")
    st.stop()

proxmox, connection_error = get_connection(settings)

with st.sidebar:
    if proxmox:
        st.success("Connecte a l'API Proxmox")
    else:
        st.error(f"Erreur de connexion: {connection_error}")

if not proxmox:
    st.stop()

try:
    nodes = fetch_nodes(proxmox)
except Exception as exc:
    st.error(f"Impossible de recuperer les noeuds Proxmox: {exc}")
    st.stop()

node_names = [node["node"] for node in nodes if node.get("node")]
if not node_names:
    st.warning("Aucun noeud Proxmox n'a ete retourne par l'API.")
    st.stop()

default_node = st.session_state["selected_node"]
default_node_index = node_names.index(default_node) if default_node in node_names else 0

refresh_options = {
    "Manuel": None,
    "5 secondes": "5s",
    "10 secondes": "10s",
    "30 secondes": "30s",
}

with st.sidebar:
    selected_node = st.selectbox("Noeud", options=node_names, index=default_node_index)
    refresh_label = st.selectbox("Rafraichissement", options=list(refresh_options.keys()), index=1)
    st.divider()
    st.caption("Regles actives")
    st.write(f"CPU host: {settings.host_cpu_warn:.0f}% / {settings.host_cpu_critical:.0f}%")
    st.write(f"CPU VM: {settings.vm_cpu_warn:.0f}% / {settings.vm_cpu_critical:.0f}%")
    st.write(f"RAM VM: {settings.vm_ram_warn:.0f}% / {settings.vm_ram_critical:.0f}%")
    st.write(f"Duree min: {settings.alert_min_duration_seconds}s")
    if not hasattr(st, "fragment"):
        st.info("Cette version de Streamlit ne supporte pas le rafraichissement automatique fragment.")

st.session_state["selected_node"] = selected_node
refresh_every = refresh_options[refresh_label]


@get_fragment_decorator(refresh_every)
def render_dashboard() -> None:
    sample_time = datetime.now()
    try:
        node_status = fetch_node_status(proxmox, selected_node)
        qemu_vms = fetch_qemu_vms(proxmox, selected_node)
        vm_statuses = fetch_vm_statuses(proxmox, selected_node, qemu_vms)
    except Exception as exc:
        st.error(f"Impossible de charger les donnees du noeud {selected_node}: {exc}")
        return

    capture_node_history(settings, selected_node, node_status)
    capture_vm_history(settings, selected_node, vm_statuses)
    if settings.app_persist_on_render:
        persist_metrics(settings, selected_node, node_status, vm_statuses, sample_time)

    evaluation = evaluate_detection(
        settings,
        selected_node,
        node_status,
        vm_statuses,
        st.session_state["active_breaches"],
        st.session_state["fired_alert_keys"],
        now=sample_time,
    )
    if settings.app_persist_on_render:
        for alert in evaluation.current_alerts:
            upsert_alert(settings.db_path, alert)
        resolve_alerts_for_node(settings.db_path, selected_node, evaluation.active_keys, sample_time)

    tab_supervision, tab_incidents, tab_response, tab_ssh, tab_audit = st.tabs(
        ["Supervision", "Incidents / Alertes", "Reponse active", "Logs SSH", "Audit"]
    )

    with tab_supervision:
        render_host_tab(settings, selected_node, node_status, vm_statuses, evaluation.current_alerts)

    with tab_incidents:
        render_incidents_tab(settings, node_names, vm_statuses)

    with tab_response:
        render_response_tab(settings, proxmox, selected_node, vm_statuses)

    with tab_ssh:
        render_ssh_events_tab(settings, node_names, vm_statuses)

    with tab_audit:
        render_audit_tab(settings)


render_dashboard()
