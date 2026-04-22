import os
from typing import Dict, List, Tuple

import pandas as pd
import streamlit as st
from dotenv import load_dotenv
from proxmoxer import ProxmoxAPI


load_dotenv()


def parse_bool(value: str, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def sanitize_host(raw_host: str) -> str:
    host = raw_host.strip()
    host = host.removeprefix("https://").removeprefix("http://")
    return host.rstrip("/")


def bytes_to_gib(value: int) -> float:
    return value / (1024 ** 3)


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
            "Complète le fichier .env avant de lancer l'application."
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


def format_vm_table(vms: List[Dict[str, object]]) -> pd.DataFrame:
    rows = []
    for vm in vms:
        rows.append(
            {
                "VMID": vm.get("vmid"),
                "Nom": vm.get("name") or "Sans nom",
                "Etat": vm.get("status", "unknown"),
                "CPU %": round(float(vm.get("cpu", 0)) * 100, 2),
                "RAM utilisée (GiB)": round(bytes_to_gib(int(vm.get("mem", 0))), 2),
                "RAM max (GiB)": round(bytes_to_gib(int(vm.get("maxmem", 0))), 2),
            }
        )
    return pd.DataFrame(rows)


def parse_network_config(config_value: str) -> Dict[str, str]:
    parts = [part.strip() for part in config_value.split(",") if part.strip()]
    parsed = {}
    for part in parts:
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        parsed[key] = value
    return parsed


def build_network_config(config: Dict[str, str]) -> str:
    return ",".join(f"{key}={value}" for key, value in config.items())


def isolate_vm_network(proxmox, node_name: str, vmid: int) -> Tuple[bool, str]:
    config = proxmox.nodes(node_name).qemu(vmid).config.get()
    net0 = config.get("net0")

    if not net0:
        return False, f"La VM {vmid} ne possède pas d'interface net0 configurable."

    net0_config = parse_network_config(net0)
    if net0_config.get("link_down") == "1":
        return True, f"La VM {vmid} est déjà isolée sur net0."

    net0_config["link_down"] = "1"
    updated_net0 = build_network_config(net0_config)
    proxmox.nodes(node_name).qemu(vmid).config.put(net0=updated_net0)
    return True, f"Isolation réseau appliquée à la VM {vmid} sur net0."


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

st.title("🛡️ Proxmox Sentinel - SOC Interface")
st.caption("POC SOC conteneurisé pour la supervision d'un serveur Proxmox et l'isolement d'une VM QEMU.")

proxmox, connection_error = get_connection()

with st.sidebar:
    st.header("Etat de la plateforme")
    if proxmox:
        st.success("Connecté à l'API Proxmox")
    else:
        st.error(f"Erreur de connexion: {connection_error}")

    verify_ssl = parse_bool(os.getenv("VERIFY_SSL"), default=False)
    if not verify_ssl:
        st.warning("VERIFY_SSL=False est adapté au lab, mais pas recommandé en production.")

if not proxmox:
    st.info("Complète le fichier .env avec des identifiants API valides pour afficher le dashboard.")
    st.stop()

try:
    nodes = fetch_nodes(proxmox)
except Exception as exc:
    st.error(f"Impossible de récupérer les nœuds Proxmox: {exc}")
    st.stop()

node_names = [node["node"] for node in nodes if node.get("node")]
if not node_names:
    st.warning("Aucun nœud Proxmox n'a été retourné par l'API.")
    st.stop()

with st.sidebar:
    selected_node = st.selectbox("Noeud", options=node_names)

try:
    node_status = fetch_node_status(proxmox, selected_node)
    qemu_vms = fetch_qemu_vms(proxmox, selected_node)
except Exception as exc:
    st.error(f"Impossible de charger les données du nœud {selected_node}: {exc}")
    st.stop()

cpu_percent = float(node_status.get("cpu", 0)) * 100
memory_used = int(node_status.get("memory", {}).get("used", 0))
memory_total = int(node_status.get("memory", {}).get("total", 0))
swap_used = int(node_status.get("swap", {}).get("used", 0))
swap_total = int(node_status.get("swap", {}).get("total", 0))

metric_cpu, metric_ram, metric_swap = st.columns(3)
metric_cpu.metric("CPU", f"{cpu_percent:.2f}%")
metric_ram.metric(
    "RAM",
    f"{bytes_to_gib(memory_used):.2f} / {bytes_to_gib(memory_total):.2f} GiB",
)
metric_swap.metric(
    "SWAP",
    f"{bytes_to_gib(swap_used):.2f} / {bytes_to_gib(swap_total):.2f} GiB",
)

if cpu_percent > 80:
    st.error("⚠️ ANOMALIE DÉTECTÉE : Surcharge CPU suspecte")
else:
    st.success("Aucune anomalie CPU détectée sur le nœud sélectionné.")

st.subheader("Inventaire des VM QEMU")

if qemu_vms:
    st.dataframe(format_vm_table(qemu_vms), use_container_width=True, hide_index=True)
else:
    st.info("Aucune VM QEMU détectée sur ce nœud.")

st.subheader("Réponse active")

if not qemu_vms:
    st.warning("Aucune VM disponible pour lancer une action d'isolement.")
    st.stop()

vm_options = {
    f"{vm.get('vmid')} - {vm.get('name') or 'Sans nom'}": int(vm["vmid"])
    for vm in qemu_vms
    if "vmid" in vm
}
selected_vm_label = st.selectbox("VM à isoler", options=list(vm_options.keys()))
selected_vmid = vm_options[selected_vm_label]

if st.button("🔥 ISOLER (Couper Réseau)", type="primary", use_container_width=True):
    try:
        success, message = isolate_vm_network(proxmox, selected_node, selected_vmid)
        if success and "déjà isolée" in message:
            st.info(message)
        elif success:
            st.success(message)
        else:
            st.error(message)
    except Exception as exc:
        st.error(f"Echec de l'action d'isolement sur la VM {selected_vmid}: {exc}")
