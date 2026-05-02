from datetime import datetime
from html import escape
import json
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st

from actions import get_net0_state, is_protected_vmid, set_vm_network_state
from config import AppConfig, read_settings
from detection import AlertCandidate, evaluate_detection
from ml_model import MODEL_NAME, MODEL_VERSION, train_and_save_model
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
    fetch_incident_alerts,
    fetch_incident_timeline,
    fetch_incidents,
    fetch_latest_collector_run,
    fetch_latest_ml_model_run,
    fetch_latest_ml_scores,
    fetch_latest_ssh_event,
    fetch_latest_syslog_run,
    fetch_recent_ml_scores,
    fetch_recent_ssh_events,
    fetch_soc_metrics,
    init_db,
    insert_action,
    insert_host_metric,
    insert_vm_metric,
    record_ml_model_run,
    resolve_alerts_for_node,
    update_incident_status,
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


INCIDENT_STATUS_LABELS = {
    "open": "Nouveau",
    "acknowledged": "Pris en charge",
    "contained": "Contenu",
    "resolved": "Clos",
}

INCIDENT_STATUS_VALUES = {label: value for value, label in INCIDENT_STATUS_LABELS.items()}

SEVERITY_LABELS = {
    "critical": "Critique",
    "medium": "Moyen",
    "low": "Faible",
}

STATUS_TONE = {
    "open": "danger",
    "acknowledged": "warning",
    "contained": "info",
    "resolved": "success",
    "active": "danger",
    "success": "success",
    "warning": "warning",
    "error": "danger",
}
TONE_LABELS = {
    "danger": "Prioritaire",
    "warning": "Attention",
    "success": "OK",
    "info": "Info",
}


def css_for_theme(theme: str) -> str:
    if theme == "Clair":
        tokens = {
            "bg": "#f6f8fb",
            "surface": "#ffffff",
            "surface_alt": "#eef2f7",
            "text": "#111827",
            "muted": "#667085",
            "border": "#d7dde7",
            "primary": "#2563eb",
            "primary_soft": "#dbeafe",
            "danger": "#b91c1c",
            "danger_soft": "#fee2e2",
            "warning": "#b45309",
            "warning_soft": "#fef3c7",
            "success": "#047857",
            "success_soft": "#d1fae5",
            "info": "#0369a1",
            "info_soft": "#e0f2fe",
        }
    else:
        tokens = {
            "bg": "#0f141b",
            "surface": "#171d26",
            "surface_alt": "#202836",
            "text": "#f3f6fb",
            "muted": "#a8b3c7",
            "border": "#2e3848",
            "primary": "#60a5fa",
            "primary_soft": "#172d49",
            "danger": "#f87171",
            "danger_soft": "#3a1b22",
            "warning": "#fbbf24",
            "warning_soft": "#3b2f16",
            "success": "#34d399",
            "success_soft": "#17382d",
            "info": "#38bdf8",
            "info_soft": "#153244",
        }

    return f"""
    <style>
    :root {{
        --soc-bg: {tokens['bg']};
        --soc-surface: {tokens['surface']};
        --soc-surface-alt: {tokens['surface_alt']};
        --soc-text: {tokens['text']};
        --soc-muted: {tokens['muted']};
        --soc-border: {tokens['border']};
        --soc-primary: {tokens['primary']};
        --soc-primary-soft: {tokens['primary_soft']};
        --soc-danger: {tokens['danger']};
        --soc-danger-soft: {tokens['danger_soft']};
        --soc-warning: {tokens['warning']};
        --soc-warning-soft: {tokens['warning_soft']};
        --soc-success: {tokens['success']};
        --soc-success-soft: {tokens['success_soft']};
        --soc-info: {tokens['info']};
        --soc-info-soft: {tokens['info_soft']};
    }}
    .stApp {{
        background: var(--soc-bg);
        color: var(--soc-text);
    }}
    [data-testid="stSidebar"] {{
        background: var(--soc-surface);
        border-right: 1px solid var(--soc-border);
    }}
    [data-testid="stHeader"] {{
        background: rgba(0,0,0,0);
    }}
    h1, h2, h3, h4, p, label, span {{
        color: var(--soc-text);
    }}
    [data-testid="stSidebar"] h1,
    [data-testid="stSidebar"] h2,
    [data-testid="stSidebar"] h3,
    [data-testid="stSidebar"] p,
    [data-testid="stSidebar"] label,
    [data-testid="stSidebar"] span,
    [data-testid="stSidebar"] div {{
        color: var(--soc-text);
    }}
    [data-testid="stSidebar"] [data-baseweb="select"] span,
    [data-testid="stSidebar"] [data-baseweb="radio"] span {{
        color: var(--soc-text);
    }}
    .soc-nav-panel {{
        background: var(--soc-primary-soft);
        border: 1px solid var(--soc-primary);
        border-radius: 8px;
        padding: 12px;
        margin: 8px 0 14px 0;
    }}
    .soc-nav-title {{
        color: var(--soc-primary);
        font-size: 12px;
        font-weight: 850;
        text-transform: uppercase;
        margin-bottom: 4px;
    }}
    .soc-nav-copy {{
        color: var(--soc-text);
        font-size: 13px;
        line-height: 1.35;
    }}
    [data-testid="stSidebar"] [role="radiogroup"] {{
        gap: 6px;
    }}
    [data-testid="stSidebar"] [role="radiogroup"] label {{
        background: var(--soc-surface-alt);
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 8px 10px;
        margin: 0 0 6px 0;
    }}
    [data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{
        background: var(--soc-primary-soft);
        border-color: var(--soc-primary);
    }}
    div[data-testid="stMetric"] {{
        background: var(--soc-surface);
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 14px 16px;
        box-shadow: 0 10px 24px rgba(0,0,0,0.08);
    }}
    div[data-testid="stDataFrame"] {{
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        overflow: hidden;
    }}
    div.stButton > button {{
        border-radius: 8px;
        border: 1px solid var(--soc-border);
        background: var(--soc-surface-alt);
        color: var(--soc-text);
        font-weight: 650;
    }}
    div.stButton > button[kind="primary"] {{
        background: var(--soc-danger);
        border: 1px solid var(--soc-danger);
        color: white;
    }}
    div.stButton > button[kind="primary"]:hover {{
        background: var(--soc-danger);
        color: white;
        filter: brightness(0.92);
    }}
    .soc-hero {{
        background: linear-gradient(135deg, var(--soc-surface), var(--soc-surface-alt));
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 20px 22px;
        margin: 4px 0 18px 0;
    }}
    .soc-eyebrow {{
        color: var(--soc-primary);
        font-size: 12px;
        text-transform: uppercase;
        font-weight: 800;
        letter-spacing: 0;
        margin-bottom: 6px;
    }}
    .soc-title {{
        color: var(--soc-text);
        font-size: 28px;
        font-weight: 850;
        line-height: 1.2;
        margin: 0;
    }}
    .soc-subtitle {{
        color: var(--soc-muted);
        margin-top: 8px;
        font-size: 14px;
        line-height: 1.5;
    }}
    .soc-card {{
        background: var(--soc-surface);
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 16px;
        min-height: 116px;
        margin-bottom: 14px;
        box-shadow: 0 10px 24px rgba(0,0,0,0.08);
    }}
    .soc-card-title {{
        color: var(--soc-muted);
        font-size: 12px;
        text-transform: uppercase;
        font-weight: 800;
        letter-spacing: 0;
        margin-bottom: 10px;
    }}
    .soc-card-value {{
        color: var(--soc-text);
        font-size: 26px;
        font-weight: 850;
        line-height: 1.1;
    }}
    .soc-card-caption {{
        color: var(--soc-muted);
        font-size: 13px;
        margin-top: 8px;
        line-height: 1.35;
    }}
    .soc-panel {{
        background: var(--soc-surface);
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 18px;
        margin: 14px 0 20px 0;
    }}
    .soc-band {{
        background: var(--soc-surface);
        border: 1px solid var(--soc-border);
        border-radius: 8px;
        padding: 18px;
        margin: 18px 0 24px 0;
    }}
    .soc-section-title {{
        color: var(--soc-text);
        font-size: 18px;
        font-weight: 800;
        margin: 0 0 4px 0;
    }}
    .soc-section-subtitle {{
        color: var(--soc-muted);
        font-size: 13px;
        margin: 0 0 12px 0;
    }}
    .soc-pill {{
        display: inline-flex;
        align-items: center;
        border-radius: 999px;
        padding: 4px 10px;
        font-size: 12px;
        font-weight: 800;
        margin-right: 6px;
        border: 1px solid transparent;
    }}
    .soc-pill.danger {{
        color: var(--soc-danger);
        background: var(--soc-danger-soft);
        border-color: var(--soc-danger);
    }}
    .soc-pill.warning {{
        color: var(--soc-warning);
        background: var(--soc-warning-soft);
        border-color: var(--soc-warning);
    }}
    .soc-pill.success {{
        color: var(--soc-success);
        background: var(--soc-success-soft);
        border-color: var(--soc-success);
    }}
    .soc-pill.info {{
        color: var(--soc-info);
        background: var(--soc-info-soft);
        border-color: var(--soc-info);
    }}
    .soc-pill.neutral {{
        color: var(--soc-muted);
        background: var(--soc-surface-alt);
        border-color: var(--soc-border);
    }}
    .soc-incident-title {{
        color: var(--soc-text);
        font-size: 17px;
        font-weight: 800;
        margin-bottom: 8px;
    }}
    .soc-muted {{
        color: var(--soc-muted);
    }}
    </style>
    """


def render_theme_css(theme: str) -> None:
    st.markdown(css_for_theme(theme), unsafe_allow_html=True)


def render_hero(title: str, subtitle: str, eyebrow: str = "Proxmox Sentinel") -> None:
    st.markdown(
        f"""
        <div class="soc-hero">
          <div class="soc-eyebrow">{escape(eyebrow)}</div>
          <div class="soc-title">{escape(title)}</div>
          <div class="soc-subtitle">{escape(subtitle)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_section(title: str, subtitle: str = "") -> None:
    st.markdown(
        f"""
        <div class="soc-section-title">{escape(title)}</div>
        <div class="soc-section-subtitle">{escape(subtitle)}</div>
        """,
        unsafe_allow_html=True,
    )


def render_nav_hint(current_page: str) -> None:
    st.caption(f"Page active: {current_page}")


def tone_for_severity(severity: str) -> str:
    return {"critical": "danger", "medium": "warning", "low": "info"}.get(severity, "neutral")


def tone_for_status(status: str) -> str:
    return STATUS_TONE.get(status, "neutral")


def pill_html(label: str, tone: str = "neutral") -> str:
    return f'<span class="soc-pill {tone}">{escape(label)}</span>'


def render_kpi_card(title: str, value: object, caption: str = "", tone: str = "neutral") -> None:
    tone_label = TONE_LABELS.get(tone, "")
    st.markdown(
        f"""
        <div class="soc-card">
          <div class="soc-card-title">{escape(title)}</div>
          <div class="soc-card-value">{escape(str(value))}</div>
          <div class="soc-card-caption">{pill_html(tone_label, tone) if tone_label else ""}{escape(caption)}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def compact_incidents_frame(incidents: List[Dict[str, object]]) -> pd.DataFrame:
    frame = format_incidents_dataframe(incidents)
    if frame.empty:
        return frame
    wanted = [
        "ID",
        "Statut",
        "Severite",
        "Score",
        "VMID",
        "Titre",
        "Source",
        "Utilisateur",
        "Derniere activite",
        "Synthese",
    ]
    return frame[[column for column in wanted if column in frame.columns]]


def compact_alerts_frame(alerts: List[Dict[str, object]]) -> pd.DataFrame:
    frame = format_alerts_dataframe(alerts)
    if frame.empty:
        return frame
    wanted = ["ID", "Severite", "Score", "VMID", "Type", "Valeur", "Statut", "Derniere vue", "Message"]
    return frame[[column for column in wanted if column in frame.columns]]


def compact_actions_frame(actions: List[Dict[str, object]]) -> pd.DataFrame:
    frame = format_actions_dataframe(actions)
    if frame.empty:
        return frame
    wanted = ["Horodatage", "VMID", "Action", "Resultat", "Message"]
    return frame[[column for column in wanted if column in frame.columns]]


def open_incident_workspace(incident_id: int) -> None:
    st.session_state["active_incident_id"] = incident_id
    st.session_state["navigation"] = "Poste incident"


def render_incident_cards(incidents: List[Dict[str, object]], limit: int = 3) -> None:
    if not incidents:
        st.success("Aucun incident ouvert a traiter.")
        return

    for incident in incidents[:limit]:
        status = str(incident.get("status", "unknown"))
        severity = str(incident.get("severity", "unknown"))
        title = str(incident.get("title", "Incident"))
        summary = str(incident.get("summary", ""))
        meta = (
            f"VM {incident.get('vmid', '-')} | "
            f"score {incident.get('score', '-')} | "
            f"source {incident.get('source_ip') or '-'}"
        )
        st.markdown(
            f"""
            <div class="soc-panel">
              <div>
                {pill_html(incident_status_label(status), tone_for_status(status))}
                {pill_html(severity_badge(severity), tone_for_severity(severity))}
              </div>
              <div class="soc-incident-title">{escape(title)}</div>
              <div class="soc-muted">{escape(meta)}</div>
              <div class="soc-card-caption">{escape(summary)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        action_col, _ = st.columns([1, 2])
        with action_col:
            if st.button(
                "Traiter",
                key=f"soc_open_incident_{incident['id']}",
                use_container_width=True,
            ):
                open_incident_workspace(int(incident["id"]))
                st.rerun()


def incident_status_label(status: str) -> str:
    return INCIDENT_STATUS_LABELS.get(status, status)


def incident_next_step(status: str) -> Dict[str, str]:
    steps = {
        "open": {
            "label": "Prendre en charge",
            "target": "acknowledged",
            "message": "Incident detecte automatiquement. L'etape suivante est de confirmer qu'il est vu par l'analyste.",
        },
        "acknowledged": {
            "label": "Marquer comme contenu",
            "target": "contained",
            "message": "Incident pris en compte. Marque-le comme contenu apres une isolation, un blocage ou une decision de confinement.",
        },
        "contained": {
            "label": "Clore l'incident",
            "target": "resolved",
            "message": "Incident contenu. Cloture-le quand les alertes sont resolues et que la situation est revenue au calme.",
        },
        "resolved": {
            "label": "Reouvrir",
            "target": "open",
            "message": "Incident clos. Reouvre-le seulement si une nouvelle analyse montre que le traitement doit continuer.",
        },
    }
    return steps.get(status, steps["open"])


def render_incident_workflow_controls(
    settings: AppConfig,
    incident: Dict[str, object],
    key_prefix: str,
    show_workspace_button: bool = True,
) -> None:
    incident_id = int(incident["id"])
    status = str(incident["status"])
    next_step = incident_next_step(status)
    linked_alerts = fetch_incident_alerts(settings.db_path, incident_id)
    active_alert_count = sum(1 for alert in linked_alerts if alert.get("status") == "active")
    closure_blocked = next_step["target"] == "resolved" and active_alert_count > 0
    st.caption(next_step["message"])
    if closure_blocked:
        st.warning(
            "Cloture indisponible: une alerte liee est encore active. "
            f"Attends la resolution du signal ou la fin de la fenetre SSH "
            f"({settings.ssh_correlation_window_seconds}s)."
        )

    if show_workspace_button:
        action_col, workspace_col, secondary_col = st.columns([1.5, 1.5, 1])
    else:
        action_col, secondary_col = st.columns([2, 1])
        workspace_col = None
    with action_col:
        if st.button(
            next_step["label"],
            type="primary" if status != "resolved" else "secondary",
            use_container_width=True,
            key=f"{key_prefix}_incident_next_{incident_id}_{next_step['target']}",
            disabled=closure_blocked,
        ):
            st.session_state["active_incident_id"] = incident_id
            update_incident_status(settings.db_path, incident_id, next_step["target"])
            st.rerun()
    if workspace_col is not None:
        with workspace_col:
            if st.button(
                "Ouvrir dans le poste incident",
                use_container_width=True,
                key=f"{key_prefix}_incident_workspace_{incident_id}",
            ):
                open_incident_workspace(incident_id)
                st.rerun()
    with secondary_col:
        if status in {"acknowledged", "contained"}:
            if st.button(
                "Revenir a nouveau",
                use_container_width=True,
                key=f"{key_prefix}_incident_back_open_{incident_id}",
            ):
                st.session_state["active_incident_id"] = incident_id
                update_incident_status(settings.db_path, incident_id, "open")
                st.rerun()


def render_network_response_controls(
    settings: AppConfig,
    proxmox,
    node_name: str,
    vm_statuses: Dict[int, Dict[str, object]],
    selected_vmid: Optional[int],
    key_prefix: str,
    incident_id: Optional[int] = None,
) -> None:
    if selected_vmid is None:
        st.info("Cet incident n'est pas rattache a une VM: aucune action reseau directe n'est proposee.")
        return

    vm_name = str(vm_statuses.get(selected_vmid, {}).get("name") or f"VM {selected_vmid}")
    selected_label = f"{selected_vmid} - {vm_name}"
    protected = is_protected_vmid(selected_vmid, settings.protected_vmids)

    action_feedback = st.session_state.get("action_feedback")
    if action_feedback:
        getattr(st, action_feedback["level"])(action_feedback["message"])

    try:
        network_state = get_net0_state(proxmox, node_name, selected_vmid)
    except Exception as exc:
        network_state = None
        st.error(f"Impossible de lire l'etat de net0: {exc}")

    state_col1, state_col2, state_col3 = st.columns(3)
    if network_state:
        if network_state.isolated is True:
            state_value = "Isole"
            state_tone = "danger"
        elif network_state.isolated is False:
            state_value = "Connecte"
            state_tone = "success"
        else:
            state_value = "Inconnu"
            state_tone = "warning"
        with state_col1:
            render_kpi_card("Etat net0", state_value, network_state.message, state_tone)
    else:
        with state_col1:
            render_kpi_card("Etat net0", "Erreur", "Lecture impossible", "danger")
    with state_col2:
        render_kpi_card("VM cible", selected_vmid, selected_label, "neutral")
    with state_col3:
        render_kpi_card(
            "Protection",
            "Protegee" if protected else "Action possible",
            "PROTECTED_VMIDS" if protected else "Confirmation requise",
            "warning" if protected else "info",
        )

    if protected:
        st.warning("Cette VM est protegee par PROTECTED_VMIDS: l'isolement est bloque.")

    confirm_key = f"{key_prefix}_confirm_isolate_{node_name}_{selected_vmid}"
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
            "Isoler net0",
            type="primary",
            use_container_width=True,
            disabled=not can_isolate,
            key=f"{key_prefix}_isolate_{node_name}_{selected_vmid}",
        ):
            if protected:
                message = f"Isolation bloquee: VM {selected_vmid} protegee."
                insert_action(settings.db_path, node_name, selected_vmid, "isolate", "blocked", message, True)
                action_result = ("error", message)
            else:
                try:
                    success, message = set_vm_network_state(proxmox, node_name, selected_vmid, isolated=True)
                    result = "success" if success else "error"
                    insert_action(settings.db_path, node_name, selected_vmid, "isolate", result, message, protected)
                    action_result = ("success" if success else "error", message)
                    if success and incident_id is not None:
                        st.session_state["incident_action_suggestion"] = {
                            "incident_id": incident_id,
                            "target": "contained",
                        }
                except Exception as exc:
                    message = f"Echec de l'isolement sur la VM {selected_vmid}: {exc}"
                    insert_action(settings.db_path, node_name, selected_vmid, "isolate", "error", message, protected)
                    action_result = ("error", message)

    with restore_col:
        if st.button(
            "Restaurer net0",
            use_container_width=True,
            disabled=not can_restore,
            key=f"{key_prefix}_restore_{node_name}_{selected_vmid}",
        ):
            try:
                success, message = set_vm_network_state(proxmox, node_name, selected_vmid, isolated=False)
                result = "success" if success else "error"
                insert_action(settings.db_path, node_name, selected_vmid, "restore", result, message, protected)
                action_result = ("success" if success else "error", message)
            except Exception as exc:
                message = f"Echec de la restauration reseau sur la VM {selected_vmid}: {exc}"
                insert_action(settings.db_path, node_name, selected_vmid, "restore", "error", message, protected)
                action_result = ("error", message)

    if action_result:
        level, message = action_result
        st.session_state["action_feedback"] = {"level": level, "message": message}
        st.rerun()


def ensure_session_state() -> None:
    st.session_state.setdefault("theme", "Sombre")
    st.session_state.setdefault("navigation", "Vue SOC")
    st.session_state.setdefault("refresh_label", "5 secondes")
    st.session_state.setdefault("active_incident_id", None)
    st.session_state.setdefault("incident_action_suggestion", None)
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


def collector_snapshot(settings: AppConfig) -> Dict[str, object]:
    latest_run = fetch_latest_collector_run(settings.db_path)
    if latest_run is None:
        return {"label": "Collecteur", "value": "Aucun cycle", "caption": "En attente du backend", "tone": "warning"}
    try:
        last_seen = datetime.fromisoformat(str(latest_run["timestamp"]))
        age_seconds = (datetime.now() - last_seen).total_seconds()
    except ValueError:
        return {"label": "Collecteur", "value": "Timestamp illisible", "caption": "Verifier collector_runs", "tone": "warning"}

    status = str(latest_run["status"])
    if status == "error":
        return {"label": "Collecteur", "value": "Erreur", "caption": str(latest_run["message"]), "tone": "danger"}
    if status == "warning":
        return {"label": "Collecteur", "value": "Attention", "caption": str(latest_run["message"]), "tone": "warning"}
    if age_seconds <= settings.collector_heartbeat_seconds:
        return {
            "label": "Collecteur",
            "value": "Actif",
            "caption": f"Dernier cycle il y a {format_duration(age_seconds)}",
            "tone": "success",
        }
    return {
        "label": "Collecteur",
        "value": "En retard",
        "caption": f"Dernier cycle il y a {format_duration(age_seconds)}",
        "tone": "warning",
    }


def syslog_snapshot(settings: AppConfig) -> Dict[str, object]:
    if not settings.syslog_enabled:
        return {"label": "Syslog", "value": "Desactive", "caption": "SYSLOG_ENABLED=False", "tone": "neutral"}
    latest_run = fetch_latest_syslog_run(settings.db_path)
    latest_event = fetch_latest_ssh_event(settings.db_path)
    if latest_run is None:
        return {"label": "Syslog", "value": "En attente", "caption": "Aucun statut soc-syslog", "tone": "warning"}

    status = str(latest_run["status"])
    if status == "error":
        return {"label": "Syslog", "value": "Erreur", "caption": str(latest_run["message"]), "tone": "danger"}
    if status == "warning":
        return {"label": "Syslog", "value": "Attention", "caption": str(latest_run["message"]), "tone": "warning"}
    if latest_event and str(latest_event.get("ingest_method", "")).startswith("syslog"):
        return {
            "label": "Syslog",
            "value": "Actif",
            "caption": f"Dernier evenement: VM {latest_event['vmid']} | {latest_event['event_type']}",
            "tone": "success",
        }
    return {"label": "Syslog", "value": "Ecoute", "caption": "Aucun evenement SSH recent", "tone": "info"}


def render_soc_metrics(settings: AppConfig) -> None:
    metrics = fetch_soc_metrics(settings.db_path)
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Alertes actives", metrics["active_alerts"])
    col2.metric("Incidents ouverts", metrics["active_incidents"])
    col3.metric("Alertes total", metrics["total_alerts"])
    col4.metric("Actions journalisees", metrics["total_actions"])
    col5.metric("Evenements SSH", metrics["total_ssh_events"])
    st.caption(
        f"Incidents total: {metrics['total_incidents']} | "
        f"MTTD moyen: {format_duration(metrics['avg_mttd'])} | "
        f"MTTR moyen observe: {format_duration(metrics['avg_mttr'])}"
    )


def render_soc_overview(
    settings: AppConfig,
    selected_node: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    current_alerts: List[AlertCandidate],
) -> None:
    render_section(
        "Vue SOC",
        "Priorite aux incidents ouverts, a la sante des collecteurs et aux actions recentes.",
    )
    metrics = fetch_soc_metrics(settings.db_path)
    active_incidents = metrics["active_incidents"]
    active_alerts = metrics["active_alerts"]

    render_section("Posture SOC", "Ce groupe resume ce que l'analyste doit traiter maintenant.")
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        render_kpi_card(
            "Incidents ouverts",
            active_incidents,
            "A traiter par l'analyste",
            "danger" if active_incidents else "success",
        )
    with kpi2:
        render_kpi_card(
            "Alertes actives",
            active_alerts,
            f"{metrics['total_alerts']} alertes journalisees",
            "warning" if active_alerts else "success",
        )
    with kpi3:
        render_kpi_card("Evenements SSH", metrics["total_ssh_events"], "Logs normalises en SQLite", "info")
    with kpi4:
        render_kpi_card("Actions", metrics["total_actions"], "Isolements/restaurations audites", "neutral")

    st.markdown("<br>", unsafe_allow_html=True)
    render_section("Sante plateforme", "Etat du collecteur Proxmox, de l'ingestion Syslog et du noeud surveille.")
    service_col1, service_col2, service_col3 = st.columns(3)
    collector_state = collector_snapshot(settings)
    syslog_state = syslog_snapshot(settings)
    cpu_percent = float(node_status.get("cpu", 0.0)) * 100
    with service_col1:
        render_kpi_card(
            str(collector_state["label"]),
            collector_state["value"],
            str(collector_state["caption"]),
            str(collector_state["tone"]),
        )
    with service_col2:
        render_kpi_card(
            str(syslog_state["label"]),
            syslog_state["value"],
            str(syslog_state["caption"]),
            str(syslog_state["tone"]),
        )
    with service_col3:
        render_kpi_card(
            f"Noeud {selected_node}",
            f"{cpu_percent:.1f}% CPU",
            f"{len(vm_statuses)} VM QEMU observees",
            "warning" if cpu_percent >= settings.host_cpu_warn else "success",
        )

    st.markdown("<br>", unsafe_allow_html=True)
    render_section("Traitement", "Incidents a analyser et dernieres actions de reponse.")
    left, right = st.columns([1.2, 1])
    with left:
        render_section("Incidents prioritaires", "Incidents non clos, tries par severite et date.")
        incidents = [
            incident
            for incident in fetch_incidents(settings.db_path, limit=10, node=selected_node)
            if incident["status"] != "resolved"
        ]
        render_incident_cards(incidents, limit=4)

    with right:
        render_section("Alertes live", "Alertes observees sur le rendu courant.")
        render_alert_banner(current_alerts)
        recent_actions = fetch_actions(settings.db_path, limit=5)
        st.markdown("<br>", unsafe_allow_html=True)
        render_section("Actions recentes", "Dernieres operations de reponse active.")
        actions_frame = compact_actions_frame(recent_actions)
        if actions_frame.empty:
            st.info("Aucune action recente.")
        else:
            st.dataframe(actions_frame, use_container_width=True, hide_index=True)


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


def render_syslog_status(settings: AppConfig) -> None:
    if not settings.syslog_enabled:
        st.caption("Syslog: desactive.")
        return

    latest_run = fetch_latest_syslog_run(settings.db_path)
    latest_event = fetch_latest_ssh_event(settings.db_path)

    if latest_run is None:
        st.info("Syslog: en attente du service soc-syslog.")
        return

    try:
        last_seen = datetime.fromisoformat(str(latest_run["timestamp"]))
        age_seconds = (datetime.now() - last_seen).total_seconds()
    except ValueError:
        st.warning("Syslog: horodatage illisible.")
        return

    status = str(latest_run["status"])
    details = (
        f"Dernier statut: {format_duration(age_seconds)} | "
        f"vus={latest_run['events_seen']} inseres={latest_run['events_inserted']}"
    )
    message = str(latest_run["message"])

    if status == "error":
        st.error(f"Syslog: erreur. {details}")
        st.caption(message)
    elif status == "warning":
        st.warning(f"Syslog: attention. {details}")
        st.caption(message)
    elif status == "disabled":
        st.caption("Syslog: desactive.")
    elif latest_event and str(latest_event.get("ingest_method", "")).startswith("syslog"):
        st.success(f"Syslog: actif. {details}")
        st.caption(
            f"Dernier log: VM {latest_event['vmid']} | "
            f"{latest_event['event_type']} | {latest_event['timestamp']}"
        )
    else:
        st.success(f"Syslog: en ecoute. {details}")
        st.caption("Aucun evenement Syslog SSH recu pour le moment.")


def render_platform_tab(
    settings: AppConfig,
    proxmox,
    connection_error: str,
    node_names: List[str],
    refresh_options: Dict[str, Optional[str]],
) -> None:
    render_section(
        "Plateforme",
        "Configuration d'exploitation, etat des collecteurs et regles de detection actives.",
    )

    if st.session_state.get("refresh_label") not in refresh_options:
        st.session_state["refresh_label"] = "5 secondes"
    if node_names and st.session_state.get("selected_node") not in node_names:
        st.session_state["selected_node"] = node_names[0]

    settings_cols = st.columns([1, 1, 1])
    with settings_cols[0]:
        if node_names:
            st.selectbox("Noeud Proxmox actif", options=node_names, key="selected_node")
        else:
            st.info("Aucun noeud Proxmox disponible pour le moment.")
    with settings_cols[1]:
        refresh_labels = list(refresh_options.keys())
        refresh_index = refresh_labels.index(st.session_state["refresh_label"])
        selected_refresh_label = st.selectbox(
            "Rafraichissement interface",
            options=refresh_labels,
            index=refresh_index,
        )
        st.session_state["refresh_label"] = selected_refresh_label
    with settings_cols[2]:
        st.radio("Theme interface", options=["Sombre", "Clair"], key="theme", horizontal=True)

    if not hasattr(st, "fragment"):
        st.info("Cette version de Streamlit ne supporte pas le rafraichissement automatique fragment.")

    st.divider()
    render_section("Etat des services", "Sante technique du POC et des flux de collecte.")
    service_cols = st.columns(3)
    with service_cols[0]:
        render_kpi_card(
            "API Proxmox",
            "Connectee" if proxmox else "Erreur",
            "" if proxmox else connection_error,
            "success" if proxmox else "danger",
        )
    with service_cols[1]:
        render_kpi_card(
            "Mode SSL",
            "Verification active" if settings.verify_ssl else "Lab sans verification",
            "VERIFY_SSL=False reste reserve au lab." if not settings.verify_ssl else "Configuration durcie.",
            "success" if settings.verify_ssl else "warning",
        )
    with service_cols[2]:
        render_kpi_card(
            "Persistance",
            "Collecteur" if not settings.app_persist_on_render else "UI + collecteur",
            "SQLite alimente par le backend continu."
            if not settings.app_persist_on_render
            else "Streamlit persiste aussi au rendu.",
            "success" if not settings.app_persist_on_render else "warning",
        )

    collector_col, syslog_col = st.columns(2)
    with collector_col:
        render_section("Collecteur Proxmox", "Collecte continue des metriques hote et VM.")
        render_collector_status(settings)
        st.caption(f"Intervalle configure: {settings.collect_interval_seconds}s")
    with syslog_col:
        render_section("Collecteur Syslog", "Reception centralisee des evenements SSH/auth.")
        render_syslog_status(settings)
        protocols = ", ".join(sorted(settings.syslog_protocols))
        st.caption(f"Ecoute: {settings.syslog_bind_host}:{settings.syslog_port} ({protocols})")

    st.divider()
    render_section("Sources surveillees", "Mapping des VM et protections appliquees avant action active.")
    source_cols = st.columns(2)
    with source_cols[0]:
        if settings.syslog_vm_map:
            syslog_rows = [
                {
                    "VMID": mapping.vmid,
                    "IP / host": mapping.host,
                    "Nom": mapping.name,
                    "Noeud": mapping.node,
                }
                for mapping in settings.syslog_vm_map
            ]
            st.dataframe(pd.DataFrame(syslog_rows), use_container_width=True, hide_index=True)
        else:
            st.info("Aucun mapping SYSLOG_VM_MAP configure.")
    with source_cols[1]:
        protected = ", ".join(str(vmid) for vmid in sorted(settings.protected_vmids)) or "Aucune"
        render_kpi_card("VM protegees", protected, "Ces VM ne peuvent pas etre isolees depuis l'interface.", "info")
        if settings.ssh_log_targets:
            fallback_rows = [
                {
                    "VMID": target.vmid,
                    "IP / host": target.host,
                    "Utilisateur": target.user,
                    "Log": target.log_path,
                }
                for target in settings.ssh_log_targets
            ]
            st.dataframe(pd.DataFrame(fallback_rows), use_container_width=True, hide_index=True)
        else:
            st.caption("Fallback SSH desactive: collecte perenne assuree par Syslog.")

    st.divider()
    render_section("Regles de detection", "Seuils explicables utilises pour prioriser les alertes.")
    rule_cols = st.columns(4)
    with rule_cols[0]:
        render_kpi_card(
            "CPU hote",
            f"{settings.host_cpu_warn:.0f}% / {settings.host_cpu_critical:.0f}%",
            "warning / critical",
            "warning",
        )
    with rule_cols[1]:
        render_kpi_card(
            "CPU VM",
            f"{settings.vm_cpu_warn:.0f}% / {settings.vm_cpu_critical:.0f}%",
            "pression ressource VM",
            "warning",
        )
    with rule_cols[2]:
        render_kpi_card(
            "RAM VM",
            f"{settings.vm_ram_warn:.0f}% / {settings.vm_ram_critical:.0f}%",
            "pression memoire VM",
            "warning",
        )
    with rule_cols[3]:
        render_kpi_card(
            "SSH",
            f"{settings.ssh_auth_failure_warn} / {settings.ssh_auth_failure_critical}",
            "echecs warning / critical",
            "info",
        )

    correlation_cols = st.columns(3)
    with correlation_cols[0]:
        render_kpi_card(
            "Correlation",
            f"{settings.ssh_correlation_window_seconds}s",
            "fenetre SSH + CPU",
            "info",
        )
    with correlation_cols[1]:
        render_kpi_card(
            "CPU correlation",
            f"{settings.ssh_correlation_cpu_threshold:.0f}%",
            "seuil de renforcement SSH",
            "info",
        )
    with correlation_cols[2]:
        render_kpi_card(
            "Duree minimale",
            f"{settings.alert_min_duration_seconds}s",
            "avant ouverture d'alerte",
            "neutral",
        )


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


def format_incidents_dataframe(incidents: List[Dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(incidents)
    if frame.empty:
        return frame
    frame["status"] = frame["status"].map(incident_status_label)
    frame["severity"] = frame["severity"].map(severity_badge)
    frame = frame.rename(
        columns={
            "id": "ID",
            "first_seen": "Premiere detection",
            "last_seen": "Derniere activite",
            "resolved_at": "Resolution",
            "node": "Noeud",
            "vmid": "VMID",
            "category": "Categorie",
            "title": "Titre",
            "severity": "Severite",
            "score": "Score",
            "status": "Statut",
            "source_ip": "Source",
            "username": "Utilisateur",
            "summary": "Synthese",
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
            "ingest_method": "Collecteur",
            "hostname": "Hostname",
            "raw_line": "Log brut",
        }
    )
    return frame


def format_ml_scores_dataframe(scores: List[Dict[str, object]]) -> pd.DataFrame:
    frame = pd.DataFrame(scores)
    if frame.empty:
        return frame
    if "is_anomaly" in frame:
        frame["is_anomaly"] = frame["is_anomaly"].map(lambda value: "Oui" if int(value) else "Non")
    if "feature_json" in frame:
        def compact_features(raw: object) -> str:
            try:
                data = json.loads(str(raw))
            except Exception:
                return str(raw)
            return (
                f"CPU {float(data.get('cpu_percent', 0.0)):.1f}% | "
                f"RAM {float(data.get('ram_percent', 0.0)):.1f}% | "
                f"SSH {float(data.get('ssh_failed_count', 0.0)):.0f}"
            )

        frame["feature_json"] = frame["feature_json"].map(compact_features)
    frame = frame.rename(
        columns={
            "id": "ID",
            "timestamp": "Horodatage",
            "node": "Noeud",
            "vmid": "VMID",
            "model_name": "Modele",
            "model_version": "Version",
            "anomaly_score": "Score anomalie",
            "raw_score": "Score brut",
            "is_anomaly": "Anomalie",
            "severity": "Severite",
            "feature_json": "Features",
            "message": "Message",
        }
    )
    return frame


def render_incidents_tab(settings: AppConfig, node_names: List[str], vm_statuses: Dict[int, Dict[str, object]]) -> None:
    render_soc_metrics(settings)
    st.divider()

    filter_col1, filter_col2, filter_col3, filter_col4, filter_col5 = st.columns(5)
    node_filter = filter_col1.selectbox("Filtre noeud", options=["Tous", *node_names])
    vm_choices = {"Toutes": None}
    for vmid in sorted(vm_statuses):
        vm_choices[f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}"] = vmid
    vm_filter_label = filter_col2.selectbox("Filtre VM", options=list(vm_choices.keys()))
    severity_filter = filter_col3.selectbox("Severite", options=["Toutes", "critical", "medium", "low"])
    incident_status_label_filter = filter_col4.selectbox(
        "Statut incident",
        options=["Tous", *INCIDENT_STATUS_VALUES.keys()],
    )
    incident_status_filter = INCIDENT_STATUS_VALUES.get(incident_status_label_filter)
    status_filter = filter_col5.selectbox("Statut alerte", options=["Tous", "active", "resolved"])

    incidents = fetch_incidents(
        settings.db_path,
        node=node_filter,
        vmid=vm_choices[vm_filter_label],
        severity=severity_filter,
        status=incident_status_filter,
    )
    incidents_frame = compact_incidents_frame(incidents)
    st.subheader("Incidents correles")
    if incidents_frame.empty:
        st.info("Aucun incident correle ne correspond aux filtres.")
    else:
        st.dataframe(incidents_frame, use_container_width=True, hide_index=True)
        incident_options = {
            f"#{incident['id']} | {incident_status_label(str(incident['status']))} | "
            f"{severity_badge(str(incident['severity']))} | {incident['title']}": int(incident["id"])
            for incident in incidents
        }
        incident_labels = list(incident_options.keys())
        stored_incident_id = st.session_state.get("active_incident_id")
        default_index = next(
            (
                index
                for index, label in enumerate(incident_labels)
                if incident_options[label] == stored_incident_id
            ),
            0,
        )
        selected_incident_label = st.selectbox(
            "Incident a analyser",
            options=incident_labels,
            index=default_index,
        )
        selected_incident_id = incident_options[selected_incident_label]
        st.session_state["active_incident_id"] = selected_incident_id
        selected_incident = next(incident for incident in incidents if int(incident["id"]) == selected_incident_id)

        detail_col1, detail_col2, detail_col3, detail_col4 = st.columns(4)
        detail_col1.metric("Statut", incident_status_label(str(selected_incident["status"])))
        detail_col2.metric("Severite", severity_badge(str(selected_incident["severity"])))
        detail_col3.metric("Score", selected_incident["score"])
        detail_col4.metric("Categorie", selected_incident["category"])

        st.info(str(selected_incident["summary"]))
        render_incident_workflow_controls(settings, selected_incident, "incident_list")
        timeline = fetch_incident_timeline(settings.db_path, selected_incident_id)
        timeline_frame = pd.DataFrame(timeline).rename(
            columns={"timestamp": "Horodatage", "event": "Evenement", "detail": "Detail"}
        )
        st.dataframe(timeline_frame, use_container_width=True, hide_index=True)

    with st.expander("Alertes brutes liees au moteur", expanded=False):
        alerts = fetch_alerts(
            settings.db_path,
            node=node_filter,
            vmid=vm_choices[vm_filter_label],
            severity=severity_filter,
            status=status_filter,
        )
        alerts_frame = compact_alerts_frame(alerts)
        if alerts_frame.empty:
            st.info("Aucune alerte ne correspond aux filtres.")
            return

        st.dataframe(alerts_frame, use_container_width=True, hide_index=True)

        alert_ids = [int(alert["id"]) for alert in alerts]
        selected_alert_id = st.selectbox("Timeline alerte brute", options=alert_ids)
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


def render_incident_workspace_tab(
    settings: AppConfig,
    proxmox,
    selected_node: str,
    vm_statuses: Dict[int, Dict[str, object]],
) -> None:
    render_section(
        "Poste incident",
        "Qualification, prise en charge, reponse active et preuves associees depuis un seul ecran.",
    )

    incidents = fetch_incidents(settings.db_path, limit=100)
    if not incidents:
        st.success("Aucun incident n'est disponible pour le moment.")
        return

    active_incident_id = st.session_state.get("active_incident_id")
    known_ids = {int(incident["id"]) for incident in incidents}
    if active_incident_id not in known_ids:
        first_open = next((incident for incident in incidents if incident["status"] != "resolved"), incidents[0])
        active_incident_id = int(first_open["id"])
        st.session_state["active_incident_id"] = active_incident_id

    incident_options = {
        f"#{incident['id']} | {incident_status_label(str(incident['status']))} | "
        f"{severity_badge(str(incident['severity']))} | {incident['title']}": int(incident["id"])
        for incident in incidents
    }
    option_labels = list(incident_options.keys())
    default_index = next(
        (index for index, label in enumerate(option_labels) if incident_options[label] == active_incident_id),
        0,
    )
    selected_incident_label = st.selectbox("Incident actif", options=option_labels, index=default_index)
    selected_incident_id = incident_options[selected_incident_label]
    st.session_state["active_incident_id"] = selected_incident_id
    incident = next(incident for incident in incidents if int(incident["id"]) == selected_incident_id)

    incident_node = str(incident["node"])
    incident_vmid = int(incident["vmid"]) if incident.get("vmid") is not None else None
    incident_vm_statuses = vm_statuses
    if incident_node != selected_node:
        try:
            incident_qemu_vms = fetch_qemu_vms(proxmox, incident_node)
            incident_vm_statuses = fetch_vm_statuses(proxmox, incident_node, incident_qemu_vms)
        except Exception as exc:
            incident_vm_statuses = {}
            st.warning(f"Impossible de charger les VM du noeud {incident_node}: {exc}")

    kpi_cols = st.columns(5)
    with kpi_cols[0]:
        render_kpi_card(
            "Statut",
            incident_status_label(str(incident["status"])),
            "etat du dossier",
            tone_for_status(str(incident["status"])),
        )
    with kpi_cols[1]:
        render_kpi_card(
            "Severite",
            severity_badge(str(incident["severity"])),
            f"score {incident['score']}",
            tone_for_severity(str(incident["severity"])),
        )
    with kpi_cols[2]:
        render_kpi_card("VMID", incident_vmid if incident_vmid is not None else "-", incident_node, "neutral")
    with kpi_cols[3]:
        render_kpi_card("Source", incident.get("source_ip") or "-", incident.get("username") or "utilisateur inconnu", "info")
    with kpi_cols[4]:
        render_kpi_card("Categorie", incident["category"], str(incident["title"]), "neutral")

    st.info(str(incident["summary"]))

    workflow_col, response_col = st.columns([1, 1.2])
    with workflow_col:
        render_section("Decision analyste", "Changer l'etat de l'incident sans quitter le dossier.")
        render_incident_workflow_controls(settings, incident, "incident_workspace", show_workspace_button=False)

        suggestion = st.session_state.get("incident_action_suggestion")
        if (
            suggestion
            and suggestion.get("incident_id") == selected_incident_id
            and str(incident["status"]) not in {"contained", "resolved"}
        ):
            st.success("Isolement journalise. Tu peux maintenant marquer l'incident comme contenu.")
            if st.button(
                "Marquer comme contenu",
                type="primary",
                use_container_width=True,
                key=f"workspace_mark_contained_{selected_incident_id}",
            ):
                update_incident_status(settings.db_path, selected_incident_id, "contained")
                st.session_state["incident_action_suggestion"] = None
                st.rerun()

    with response_col:
        render_section("Reponse active", "Action Proxmox ciblee sur la VM de l'incident.")
        render_network_response_controls(
            settings,
            proxmox,
            incident_node,
            incident_vm_statuses,
            incident_vmid,
            key_prefix=f"incident_workspace_{selected_incident_id}",
            incident_id=selected_incident_id,
        )

    st.divider()
    evidence_col, audit_col = st.columns([1.15, 1])
    with evidence_col:
        render_section("Timeline", "Detection, alertes liees, actions et resolution.")
        timeline = fetch_incident_timeline(settings.db_path, selected_incident_id)
        timeline_frame = pd.DataFrame(timeline).rename(
            columns={"timestamp": "Horodatage", "event": "Evenement", "detail": "Detail"}
        )
        if timeline_frame.empty:
            st.info("Aucun evenement de timeline pour cet incident.")
        else:
            st.dataframe(timeline_frame, use_container_width=True, hide_index=True)

        linked_alerts = fetch_incident_alerts(settings.db_path, selected_incident_id)
        linked_alerts_frame = compact_alerts_frame(linked_alerts)
        with st.expander("Alertes liees", expanded=False):
            if linked_alerts_frame.empty:
                st.info("Aucune alerte liee a cet incident.")
            else:
                st.dataframe(linked_alerts_frame, use_container_width=True, hide_index=True)

    with audit_col:
        render_section("Audit VM", "Actions recentes concernant la VM de l'incident.")
        if incident_vmid is None:
            st.info("Aucune VM rattachee a cet incident.")
        else:
            vm_actions = [
                action
                for action in fetch_actions(settings.db_path, limit=200)
                if str(action.get("node")) == incident_node
                and action.get("vmid") is not None
                and int(action["vmid"]) == incident_vmid
            ]
            actions_frame = compact_actions_frame(vm_actions)
            if actions_frame.empty:
                st.info("Aucune action recente sur cette VM.")
            else:
                st.dataframe(actions_frame, use_container_width=True, hide_index=True)


def render_host_tab(
    settings: AppConfig,
    selected_node: str,
    node_status: Dict[str, object],
    vm_statuses: Dict[int, Dict[str, object]],
    current_alerts: List[AlertCandidate],
) -> None:
    node_history = history_frame("node_history", selected_node)

    render_section("Supervision Proxmox", f"Noeud surveille: {selected_node}")

    memory = node_status.get("memory", {})
    swap = node_status.get("swap", {})
    cpu_percent = float(node_status.get("cpu", 0.0)) * 100
    memory_used = int(memory.get("used", 0))
    memory_total = int(memory.get("total", 0))
    swap_used = int(swap.get("used", 0))
    swap_total = int(swap.get("total", 0))

    metric_cpu, metric_ram, metric_swap = st.columns(3)
    with metric_cpu:
        render_kpi_card(
            "CPU host",
            f"{cpu_percent:.2f}%",
            "Noeud Proxmox",
            "warning" if cpu_percent >= settings.host_cpu_warn else "success",
        )
    with metric_ram:
        render_kpi_card(
            "RAM host",
            format_used_total_gib(memory_used, memory_total),
            f"{percent_ratio(memory_used, memory_total):.1f}%",
            "neutral",
        )
    with metric_swap:
        render_kpi_card(
            "SWAP host",
            format_used_total_gib(swap_used, swap_total),
            f"{percent_ratio(swap_used, swap_total):.1f}%",
            "neutral",
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
    render_section("Inventaire QEMU", "Etat courant des VM observees via l'API Proxmox.")
    if vm_statuses:
        st.dataframe(format_vm_table(vm_statuses), use_container_width=True, hide_index=True)
    else:
        st.info("Aucune VM QEMU detectee sur ce noeud.")

    render_section("Statistiques par VM QEMU", "Historique quasi temps reel conserve en session Streamlit.")
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
    render_section(
        "Reponse active",
        "Confinement manuel et journalise. Perimetre du POC: VM QEMU uniquement, interface net0 uniquement.",
    )

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
    render_network_response_controls(
        settings,
        proxmox,
        selected_node,
        vm_statuses,
        selected_vmid,
        key_prefix="manual_response",
    )

    st.divider()
    st.subheader("Journal d'audit recent")
    actions_frame = format_actions_dataframe(fetch_actions(settings.db_path, limit=50))
    if actions_frame.empty:
        st.info("Aucune action journalisee pour le moment.")
    else:
        st.dataframe(actions_frame, use_container_width=True, hide_index=True)


def render_audit_tab(settings: AppConfig) -> None:
    render_section("Journal d'audit", "Historique des actions de reponse active et des blocages de protection.")
    actions_frame = format_actions_dataframe(fetch_actions(settings.db_path, limit=200))
    if actions_frame.empty:
        st.info("Aucune action de reponse active n'a encore ete journalisee.")
    else:
        st.dataframe(actions_frame, use_container_width=True, hide_index=True)


def render_ml_analysis_tab(settings: AppConfig, node_names: List[str], selected_node: str, vm_statuses: Dict[int, Dict[str, object]]) -> None:
    render_section(
        "Analyse ML",
        "Extension Isolation Forest pour scorer les anomalies comportementales a partir des metriques et logs SSH.",
    )
    if not settings.ml_enabled:
        st.info("Le module ML est desactive. Active ML_ENABLED=True dans le fichier .env.")
        return

    latest_run = fetch_latest_ml_model_run(settings.db_path)
    run_col1, run_col2, run_col3, run_col4 = st.columns(4)
    if latest_run:
        run_col1.metric("Modele", latest_run["model_name"])
        run_col2.metric("Statut", latest_run["status"])
        run_col3.metric("Lignes train", latest_run["training_rows"])
        accuracy = latest_run.get("accuracy")
        run_col4.metric("Exactitude eval.", f"{float(accuracy) * 100:.0f}%" if accuracy is not None else "n/a")
        st.caption(
            f"Dernier entrainement: {latest_run['timestamp']} | "
            f"Rappel: {float(latest_run.get('recall') or 0.0) * 100:.0f}% | "
            f"Precision: {float(latest_run.get('precision') or 0.0) * 100:.0f}% | "
            f"{latest_run['message']}"
        )
    else:
        run_col1.metric("Modele", MODEL_NAME)
        run_col2.metric("Statut", "non entraine")
        run_col3.metric("Lignes train", 0)
        run_col4.metric("Exactitude eval.", "n/a")
        st.info("Aucun entrainement ML journalise. Le collecteur peut entrainer automatiquement au demarrage.")

    with st.expander("Entrainer / regenerer le modele", expanded=False):
        st.write(
            "Le modele est entraine sur une baseline issue des metriques disponibles, augmentee par des "
            "scenarios normaux synthetiques. Cette etape sert a evaluer une extension ML sans remplacer "
            "la detection par regles."
        )
        if st.button("Entrainer Isolation Forest maintenant", type="primary"):
            try:
                with st.spinner("Entrainement du modele Isolation Forest..."):
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
                        message="Entrainement manuel depuis l'interface Streamlit.",
                    )
                st.success("Modele entraine et sauvegarde. Redemarre le collecteur pour charger ce modele.")
                st.rerun()
            except Exception as exc:
                record_ml_model_run(
                    settings.db_path,
                    model_name=MODEL_NAME,
                    model_version=MODEL_VERSION,
                    status="error",
                    message=str(exc),
                )
                st.error(f"Echec entrainement ML: {exc}")

    st.divider()
    render_section("Scores live", "Derniers scores Isolation Forest calcules par VM.")
    latest_scores = fetch_latest_ml_scores(settings.db_path, node=selected_node)
    if latest_scores:
        latest_frame = format_ml_scores_dataframe(latest_scores)
        st.dataframe(latest_frame, use_container_width=True, hide_index=True)
    else:
        st.info("Aucun score ML persiste pour le moment. Le collecteur doit tourner avec ML_ENABLED=True.")

    filter_col1, filter_col2 = st.columns(2)
    node_filter = filter_col1.selectbox("Noeud ML", options=["Tous", *node_names], index=node_names.index(selected_node) + 1 if selected_node in node_names else 0)
    vm_choices = {"Toutes": None}
    for vmid in sorted(vm_statuses):
        vm_choices[f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}"] = vmid
    vm_filter_label = filter_col2.selectbox("VM ML", options=list(vm_choices.keys()))

    scores = fetch_recent_ml_scores(
        settings.db_path,
        limit=400,
        node=node_filter,
        vmid=vm_choices[vm_filter_label],
    )
    if not scores:
        st.info("Aucun historique ML ne correspond aux filtres.")
        return

    scores_frame = pd.DataFrame(scores)
    scores_frame["timestamp"] = pd.to_datetime(scores_frame["timestamp"], errors="coerce")
    chart_frame = scores_frame.dropna(subset=["timestamp"]).sort_values("timestamp")
    if not chart_frame.empty:
        pivot = chart_frame.pivot_table(
            index="timestamp",
            columns="vmid",
            values="anomaly_score",
            aggfunc="max",
        )
        st.line_chart(pivot, height=260, use_container_width=True)
    st.dataframe(format_ml_scores_dataframe(scores), use_container_width=True, hide_index=True)


def render_ssh_events_tab(settings: AppConfig, node_names: List[str], vm_statuses: Dict[int, Dict[str, object]]) -> None:
    render_section("Logs SSH / Syslog", "Evenements normalises recus depuis rsyslog ou le fallback SSH.")
    if not settings.ssh_log_targets and not settings.syslog_vm_map:
        st.info("Aucune source de logs configuree. Renseigne SYSLOG_VM_MAP ou SSH_LOG_TARGETS.")

    filter_col1, filter_col2 = st.columns(2)
    node_filter = filter_col1.selectbox("Noeud logs", options=["Tous", *node_names])
    vm_choices = {"Toutes": None}
    for vmid in sorted(vm_statuses):
        vm_choices[f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}"] = vmid
    vm_filter_label = filter_col2.selectbox("VM logs", options=list(vm_choices.keys()))

    events = fetch_recent_ssh_events(
        settings.db_path,
        limit=200,
        node=node_filter,
        vmid=vm_choices[vm_filter_label],
    )
    events_frame = format_ssh_events_dataframe(events)
    if events_frame.empty:
        st.info("Aucun evenement SSH/Syslog collecte pour les filtres selectionnes.")
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

ensure_session_state()

navigation_options = [
    "Vue SOC",
    "Poste incident",
    "Incidents",
    "Supervision Proxmox",
    "Reponse active",
    "Logs SSH / Syslog",
    "Analyse ML",
    "Audit",
    "Plateforme",
]
refresh_options = {
    "5 secondes": "5s",
    "Manuel": None,
    "10 secondes": "10s",
    "30 secondes": "30s",
}
if st.session_state.get("navigation") not in navigation_options:
    st.session_state["navigation"] = "Vue SOC"
if st.session_state.get("refresh_label") not in refresh_options:
    st.session_state["refresh_label"] = "5 secondes"

render_theme_css(st.session_state["theme"])

render_hero(
    "SOC Dashboard",
    "Supervision Proxmox, detection comportementale explicable, incidents correles et reponse active human-in-the-loop.",
)

with st.sidebar:
    st.markdown(
        """
        <div class="soc-nav-panel">
          <div class="soc-nav-title">Proxmox Sentinel</div>
          <div class="soc-nav-copy">Navigation</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.radio("Page", options=navigation_options, key="navigation")

navigation = st.session_state["navigation"]

try:
    settings = read_settings()
    init_db(settings.db_path)
    settings_error = ""
except Exception as exc:
    settings = None
    settings_error = str(exc)

if settings is None:
    render_section("Configuration", "Le fichier .env doit etre valide avant de charger le dashboard.")
    st.error(f"Configuration invalide: {settings_error}")
    st.info("Complete le fichier .env avec des identifiants API valides pour afficher le dashboard.")
    st.stop()

proxmox, connection_error = get_connection(settings)

if not proxmox:
    if navigation == "Plateforme":
        render_platform_tab(settings, proxmox, connection_error, [], refresh_options)
    else:
        st.error(f"Erreur de connexion a l'API Proxmox: {connection_error}")
        st.info("La page Plateforme contient le detail de configuration et l'etat des services.")
    st.stop()

try:
    nodes = fetch_nodes(proxmox)
except Exception as exc:
    if navigation == "Plateforme":
        st.error(f"Impossible de recuperer les noeuds Proxmox: {exc}")
        render_platform_tab(settings, proxmox, connection_error, [], refresh_options)
    else:
        st.error(f"Impossible de recuperer les noeuds Proxmox: {exc}")
    st.stop()

node_names = [node["node"] for node in nodes if node.get("node")]
if not node_names:
    if navigation == "Plateforme":
        render_platform_tab(settings, proxmox, connection_error, [], refresh_options)
    else:
        st.warning("Aucun noeud Proxmox n'a ete retourne par l'API.")
    st.stop()

if st.session_state.get("selected_node") not in node_names:
    st.session_state["selected_node"] = node_names[0]

selected_node = st.session_state["selected_node"]
refresh_every = refresh_options[st.session_state["refresh_label"]]


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

    if navigation == "Vue SOC":
        render_soc_overview(settings, selected_node, node_status, vm_statuses, evaluation.current_alerts)
    elif navigation == "Poste incident":
        render_incident_workspace_tab(settings, proxmox, selected_node, vm_statuses)
    elif navigation == "Incidents":
        render_incidents_tab(settings, node_names, vm_statuses)
    elif navigation == "Supervision Proxmox":
        render_host_tab(settings, selected_node, node_status, vm_statuses, evaluation.current_alerts)
    elif navigation == "Reponse active":
        render_response_tab(settings, proxmox, selected_node, vm_statuses)
    elif navigation == "Logs SSH / Syslog":
        render_ssh_events_tab(settings, node_names, vm_statuses)
    elif navigation == "Analyse ML":
        render_ml_analysis_tab(settings, node_names, selected_node, vm_statuses)
    elif navigation == "Audit":
        render_audit_tab(settings)
    elif navigation == "Plateforme":
        render_platform_tab(settings, proxmox, connection_error, node_names, refresh_options)


render_dashboard()
