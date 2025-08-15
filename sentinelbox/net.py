import ipaddress
import subprocess
from pathlib import Path
from typing import Iterator, Optional

def get_interface_cidr(interface: str) -> Optional[str]:
    try:
        out = subprocess.check_output(["ip", "-o", "-4", "addr", "show", "dev", interface], text=True)
    except Exception:
        return None
    parts = out.strip().split()
    for p in parts:
        if "/" in p and p.count(".") == 3:
            return p
    return None

def iter_ipv4_hosts(cidr: str) -> Iterator[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    for ip in net.hosts():
        yield str(ip)

def read_arp_cache(interface: Optional[str] = None) -> list[tuple[str, Optional[str], Optional[str]]]:
    args = ["ip", "neigh", "show"]
    if interface:
        args += ["dev", interface]
    try:
        out = subprocess.check_output(args, text=True)
    except Exception:
        return []
    res = []
    for line in out.strip().splitlines():
        tokens = line.split()
        ip = tokens[0] if tokens else None
        mac = None
        state = None
        for i, t in enumerate(tokens):
            if t == "lladdr" and i + 1 < len(tokens):
                mac = tokens[i + 1]
            if t in {"REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "PERMANENT", "NOARP", "INCOMPLETE"}:
                state = t
        if ip:
            res.append((ip, mac, state))
    return res

def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
