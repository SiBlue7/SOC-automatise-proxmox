from dataclasses import dataclass
from typing import Dict, Optional, Set, Tuple


@dataclass(frozen=True)
class NetworkState:
    isolated: Optional[bool]
    label: str
    message: str


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


def is_protected_vmid(vmid: int, protected_vmids: Set[int]) -> bool:
    return vmid in protected_vmids


def get_net0_state(proxmox, node_name: str, vmid: int) -> NetworkState:
    config = proxmox.nodes(node_name).qemu(vmid).config.get()
    net0 = config.get("net0")

    if not net0:
        return NetworkState(
            isolated=None,
            label="net0 absent",
            message=f"La VM {vmid} ne possede pas d'interface net0 configurable.",
        )

    net0_config = parse_network_config(net0)
    is_isolated = net0_config.get("link_down") == "1"
    status_label = "isole" if is_isolated else "connecte"
    return NetworkState(
        isolated=is_isolated,
        label=status_label,
        message=f"Etat actuel de net0: {status_label}.",
    )


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
