from typing import Dict, List

from proxmoxer import ProxmoxAPI

from config import AppConfig


def connect_proxmox_with_token(host: str, user: str, token_id: str, token_secret: str, verify_ssl: bool):
    proxmox = ProxmoxAPI(
        host,
        user=user,
        token_name=token_id,
        token_value=token_secret,
        verify_ssl=verify_ssl,
    )
    proxmox.version.get()
    return proxmox


def connect_proxmox(settings: AppConfig):
    return connect_proxmox_with_token(
        settings.host,
        settings.user,
        settings.token_id,
        settings.token_secret,
        settings.verify_ssl,
    )


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
