import os
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from proxmoxer import ProxmoxAPI


MAX_HISTORY_POINTS = 30

load_dotenv()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def sanitize_host(raw_host: str) -> str:
    host = raw_host.strip()
    host = host.removeprefix("https://").removeprefix("http://")
    return host.rstrip("/")


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


def read_settings() -> Dict[str, object]:
    settings = {
        "host": os.getenv("PROXMOX_HOST", "").strip(),
        "user": os.getenv("PROXMOX_USER", "").strip(),
        "token_id": os.getenv("PROXMOX_TOKEN_ID", "").strip(),
        "token_secret": os.getenv("PROXMOX_SECRET", "").strip(),
        "verify_ssl": parse_bool(os.getenv("VERIFY_SSL"), default=False),
    }

    missing = [key for key, value in settings.items() if key != "verify_ssl" and not value]
    if missing:
        env_names = {
            "host": "PROXMOX_HOST",
            "user": "PROXMOX_USER",
            "token_id": "PROXMOX_TOKEN_ID",
            "token_secret": "PROXMOX_SECRET",
        }
        missing_vars = ", ".join(env_names[name] for name in missing)
        raise ValueError(
            f"Variables d'environnement manquantes: {missing_vars}. "
            "Complete le fichier .env avant de lancer l'application."
        )

    settings["host"] = sanitize_host(str(settings["host"]))
    return settings


@st.cache_resource(show_spinner=False)
def connect_proxmox(host: str, user: str, token_id: str, token_secret: str, verify_ssl: bool):
    proxmox = ProxmoxAPI(
        host,
        user=user,
        token_name=token_id,
        token_value=token_secret,
        verify_ssl=verify_ssl,
    )
    proxmox.version.get()
    return proxmox


def get_connection() -> Tuple[object, str]:
    try:
        settings = read_settings()
        proxmox = connect_proxmox(
            host=str(settings["host"]),
            user=str(settings["user"]),
            token_id=str(settings["token_id"]),
            token_secret=str(settings["token_secret"]),
            verify_ssl=bool(settings["verify_ssl"]),
        )
        return proxmox, ""
    except Exception as exc:
        return None, str(exc)


def fetch_nodes(proxmox) -> List[Dict[str, object]]:
    return list(proxmox.nodes.get())


def fetch_node_status(proxmox, node_name: str) -> Dict[str, object]:
    return dict(proxmox.nodes(node_name).status.get())


def fetch_qemu_vms(proxmox, node_name: str) -> List[Dict[str, object]]:
    vms = proxmox.nodes(node_name).qemu.get()
    return sorted(vms, key=lambda vm: vm.get("vmid", 0))


def fetch_vm_statuses(proxmox, node_name: str, vms: List[Dict[str, object]]) -> Dict[int, Dict[str, object]]:
    statuses: Dict[int, Dict[str, object]] = {}
    for vm in vms:
        vmid = int(vm["vmid"])
        vm_status = {
            "vmid": vmid,
            "name": vm.get("name") or f"VM {vmid}",
            "status": vm.get("status", "unknown"),
            "cpu": float(vm.get("cpu", 0.0)),
            "mem": int(vm.get("mem", 0)),
            "maxmem": int(vm.get("maxmem", 0)),
            "uptime": int(vm.get("uptime", 0)),
        }
        try:
            current_status = dict(proxmox.nodes(node_name).qemu(vmid).status.current.get())
            vm_status.update(
                {
                    "status": current_status.get("status", vm_status["status"]),
                    "cpu": float(current_status.get("cpu", vm_status["cpu"])),
                    "mem": int(current_status.get("mem", vm_status["mem"])),
                    "maxmem": int(current_status.get("maxmem", vm_status["maxmem"])),
                    "uptime": int(current_status.get("uptime", vm_status["uptime"])),
                    "name": current_status.get("name", vm_status["name"]),
                }
            )
        except Exception as exc:
            vm_status["status_error"] = str(exc)

        statuses[vmid] = vm_status

    return statuses


def format_vm_table(vm_statuses: Dict[int, Dict[str, object]]) -> pd.DataFrame:
    rows = []
    for vmid in sorted(vm_statuses):
        vm = vm_statuses[vmid]
        rows.append(
            {
                "VMID": vmid,
                "Nom": vm.get("name") or f"VM {vmid}",
                "Etat": vm.get("status", "unknown"),
                "CPU %": round(float(vm.get("cpu", 0.0)) * 100, 2),
                "RAM utilisee (GiB)": round(bytes_to_gib(int(vm.get("mem", 0))), 2),
                "RAM max (GiB)": round(bytes_to_gib(int(vm.get("maxmem", 0))), 2),
                "Uptime": format_uptime(int(vm.get("uptime", 0))),
            }
        )
    return pd.DataFrame(rows)


def parse_network_config(config_value: str) -> Dict[str, str]:
    parts = [part.strip() for part in config_value.split(",") if part.strip()]
    parsed: Dict[str, str] = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key] = value
    return parsed


def build_network_config(config: Dict[str, str]) -> str:
    return ",".join(f"{key}={value}" for key, value in config.items())


def get_net0_state(proxmox, node_name: str, vmid: int) -> Tuple[Optional[bool], str]:
    config = proxmox.nodes(node_name).qemu(vmid).config.get()
    net0 = config.get("net0")

    if not net0:
        return None, f"La VM {vmid} ne possede pas d'interface net0 configurable."

    net0_config = parse_network_config(net0)
    is_isolated = net0_config.get("link_down") == "1"
    status_label = "isolee" if is_isolated else "connectee"
    return is_isolated, f"Etat actuel de net0: {status_label}."


def set_vm_network_state(proxmox, node_name: str, vmid: int, isolated: bool) -> Tuple[bool, str]:
    config = proxmox.nodes(node_name).qemu(vmid).config.get()
    net0 = config.get("net0")

    if not net0:
        return False, f"La VM {vmid} ne possede pas d'interface net0 configurable."

    net0_config = parse_network_config(net0)
    current_state = net0_config.get("link_down") == "1"

    if isolated and current_state:
        return True, f"La VM {vmid} est deja isolee sur net0."
    if not isolated and not current_state:
        return True, f"Le reseau de la VM {vmid} est deja actif sur net0."

    if isolated:
        net0_config["link_down"] = "1"
        success_message = f"Isolation reseau appliquee a la VM {vmid} sur net0."
    else:
        net0_config.pop("link_down", None)
        success_message = f"Reseau restaure pour la VM {vmid} sur net0."

    updated_net0 = build_network_config(net0_config)
    proxmox.nodes(node_name).qemu(vmid).config.put(net0=updated_net0)
    return True, success_message


def ensure_session_state() -> None:
    st.session_state.setdefault("node_history", {})
    st.session_state.setdefault("vm_history", {})
    st.session_state.setdefault("action_feedback", None)
    st.session_state.setdefault("selected_node", None)
    st.session_state.setdefault("selected_vmid", None)


def append_history(bucket_name: str, key: str, sample: Dict[str, object]) -> None:
    bucket = st.session_state[bucket_name]
    history = bucket.setdefault(key, [])
    history.append(sample)
    if len(history) > MAX_HISTORY_POINTS:
        del history[:-MAX_HISTORY_POINTS]


def history_frame(bucket_name: str, key: str) -> pd.DataFrame:
    history = st.session_state[bucket_name].get(key, [])
    frame = pd.DataFrame(history)
    if frame.empty:
        return frame
    return frame.set_index("timestamp")


def capture_node_history(node_name: str, node_status: Dict[str, object]) -> None:
    memory = node_status.get("memory", {})
    swap = node_status.get("swap", {})
    append_history(
        "node_history",
        node_name,
        {
            "timestamp": datetime.now(),
            "CPU %": round(float(node_status.get("cpu", 0.0)) * 100, 2),
            "RAM utilisee (GiB)": round(bytes_to_gib(int(memory.get("used", 0))), 2),
            "SWAP utilisee (GiB)": round(bytes_to_gib(int(swap.get("used", 0))), 2),
        },
    )


def capture_vm_history(node_name: str, vm_statuses: Dict[int, Dict[str, object]]) -> None:
    timestamp = datetime.now()
    for vmid, vm in vm_statuses.items():
        history_key = f"{node_name}:{vmid}"
        append_history(
            "vm_history",
            history_key,
            {
                "timestamp": timestamp,
                "CPU %": round(float(vm.get("cpu", 0.0)) * 100, 2),
                "RAM utilisee (GiB)": round(bytes_to_gib(int(vm.get("mem", 0))), 2),
            },
        )


def render_line_chart(frame: pd.DataFrame, columns: List[str], height: int = 180) -> None:
    if frame.empty:
        st.caption("Historique en attente de donnees...")
        return
    st.line_chart(frame[columns], height=height, use_container_width=True)


def get_fragment_decorator(run_every: Optional[str]):
    fragment_api = getattr(st, "fragment", None)
    if fragment_api is None:
        def passthrough(func):
            return func
        return passthrough
    return fragment_api(run_every=run_every)


st.set_page_config(page_title="Proxmox Sentinel - SOC Interface", page_icon="🛡️", layout="wide")

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

st.title("🛡️ Proxmox Sentinel - SOC Interface")
st.caption(
    "Vue temps reel du serveur Proxmox, telemetry QEMU par VM, et reponse active "
    "d'isolement/restauration reseau."
)

proxmox, connection_error = get_connection()

with st.sidebar:
    st.header("Etat de la plateforme")
    if proxmox:
        st.success("Connecte a l'API Proxmox")
    else:
        st.error(f"Erreur de connexion: {connection_error}")

    verify_ssl = parse_bool(os.getenv("VERIFY_SSL"), default=False)
    if not verify_ssl:
        st.warning("VERIFY_SSL=False est adapte au lab, mais pas recommande en production.")

if not proxmox:
    st.info("Complete le fichier .env avec des identifiants API valides pour afficher le dashboard.")
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
    if not hasattr(st, "fragment"):
        st.info("La version de Streamlit ne supporte pas le rafraichissement automatique fragment.")

st.session_state["selected_node"] = selected_node
refresh_every = refresh_options[refresh_label]


@get_fragment_decorator(refresh_every)
def render_dashboard() -> None:
    try:
        node_status = fetch_node_status(proxmox, selected_node)
        qemu_vms = fetch_qemu_vms(proxmox, selected_node)
        vm_statuses = fetch_vm_statuses(proxmox, selected_node, qemu_vms)
    except Exception as exc:
        st.error(f"Impossible de charger les donnees du noeud {selected_node}: {exc}")
        return

    capture_node_history(selected_node, node_status)
    capture_vm_history(selected_node, vm_statuses)

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

    if cpu_percent > 80:
        st.error("⚠️ ANOMALIE DETECTEE : Surcharge CPU suspecte")
    else:
        st.success("Aucune anomalie CPU detectee sur le serveur Proxmox.")

    st.divider()
    st.subheader("Inventaire QEMU")
    if vm_statuses:
        st.dataframe(format_vm_table(vm_statuses), use_container_width=True, hide_index=True)
    else:
        st.info("Aucune VM QEMU detectee sur ce noeud.")

    st.subheader("Statistiques par VM QEMU")
    if not vm_statuses:
        st.warning("Aucune VM disponible pour afficher une telemetry detaillee.")
    else:
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

    st.divider()
    st.subheader("Reponse active")

    if not vm_statuses:
        st.warning("Aucune VM disponible pour lancer une action d'isolement.")
        return

    vm_options = {
        f"{vmid} - {vm_statuses[vmid].get('name') or f'VM {vmid}'}": vmid
        for vmid in sorted(vm_statuses)
    }
    selected_vmid = st.selectbox(
        "VM a isoler ou restaurer",
        options=list(vm_options.keys()),
        index=list(vm_options.values()).index(st.session_state["selected_vmid"])
        if st.session_state["selected_vmid"] in vm_options.values()
        else 0,
        key="vm_action_select",
    )
    st.session_state["selected_vmid"] = vm_options[selected_vmid]
    selected_vmid_value = st.session_state["selected_vmid"]

    action_feedback = st.session_state.get("action_feedback")
    if action_feedback:
        getattr(st, action_feedback["level"])(action_feedback["message"])

    try:
        network_isolated, network_message = get_net0_state(proxmox, selected_node, selected_vmid_value)
    except Exception as exc:
        network_isolated, network_message = None, f"Impossible de lire l'etat de net0: {exc}"

    if network_isolated is True:
        st.warning(network_message)
    elif network_isolated is False:
        st.info(network_message)
    else:
        st.error(network_message)

    isolate_col, restore_col = st.columns(2)
    action_result = None

    with isolate_col:
        if st.button(
            "🔥 ISOLER (Couper reseau)",
            type="primary",
            use_container_width=True,
            disabled=(network_isolated is not False),
        ):
            try:
                success, message = set_vm_network_state(proxmox, selected_node, selected_vmid_value, isolated=True)
                action_result = ("success" if success else "error", message)
            except Exception as exc:
                action_result = ("error", f"Echec de l'action d'isolement sur la VM {selected_vmid_value}: {exc}")

    with restore_col:
        if st.button(
            "🟢 RESTAURER LE RESEAU",
            use_container_width=True,
            disabled=(network_isolated is not True),
        ):
            try:
                success, message = set_vm_network_state(proxmox, selected_node, selected_vmid_value, isolated=False)
                action_result = ("success" if success else "error", message)
            except Exception as exc:
                action_result = ("error", f"Echec de la restauration reseau sur la VM {selected_vmid_value}: {exc}")

    if action_result:
        level, message = action_result
        st.session_state["action_feedback"] = {"level": level, "message": message}
        st.rerun()


render_dashboard()
