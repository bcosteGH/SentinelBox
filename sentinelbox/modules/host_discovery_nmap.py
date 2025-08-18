import json
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional
import shutil
import time
import nmap
from ..module import Module
from ..net import get_interface_cidr, ensure_dir

def is_interface_up(interface: str) -> bool:
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show", "dev", interface], text=True)
    except Exception:
        return False
    return " state UP " in f" {out} "

def parse_nmap_xml(xml_text: str) -> list[dict[str, Any]]:
    res = []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return res
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        ip = None
        mac = None
        vendor = None
        hostname = None
        hn = h.find("hostnames")
        if hn is not None:
            for n in hn.findall("hostname"):
                name = n.get("name")
                if name:
                    hostname = name
                    break
        for addr in h.findall("address"):
            at = addr.get("addrtype")
            if at == "ipv4":
                ip = addr.get("addr")
            elif at == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
        if ip:
            res.append({"ip": ip, "mac": mac, "vendor": vendor, "hostname": hostname, "source": "nmap", "rtt_ms": None})
    res.sort(key=lambda x: x["ip"])
    return res

def resolve_avahi(ip: str, timeout_s: float) -> Optional[str]:
    if shutil.which("avahi-resolve-address") is None:
        return None
    try:
        p = subprocess.run(["avahi-resolve-address", ip], capture_output=True, text=True, timeout=max(0.05, timeout_s))
    except Exception:
        return None
    if p.returncode != 0:
        return None
    parts = p.stdout.strip().split()
    if len(parts) >= 2:
        return parts[-1].rstrip(".")
    return None

def merge_hosts(a: list[dict[str, Any]], b: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_ip: dict[str, dict[str, Any]] = {}
    for src in (a, b):
        for h in src:
            ip = h["ip"]
            if ip not in by_ip:
                by_ip[ip] = dict(h)
            else:
                cur = by_ip[ip]
                for k in ("mac", "vendor", "hostname"):
                    if not cur.get(k) and h.get(k):
                        cur[k] = h[k]
    out = list(by_ip.values())
    out.sort(key=lambda x: x["ip"])
    return out

class HostDiscoveryNmap(Module):
    name = "HostDiscoveryNmap"

    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        interface = context.get("interface")
        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        ensure_dir(data_dir)
        hosts_path = data_dir / "hosts.json"
        disc = context.get("discovery") or {}
        log = context.get("log")
        store = context.get("store")

        if callable(log):
            log("DEBUG", self.name, "start", {"interface": interface})

        cidr = context.get("target_cidr")
        if not cidr:
            cidr = get_interface_cidr(interface)

        if callable(log):
            log("DEBUG", self.name, "cidr_resolved", {"cidr": cidr})

        if not cidr:
            if callable(log):
                log("ERROR", self.name, "no_cidr", None)
            return False, True, "no_cidr", None

        if not is_interface_up(interface):
            if callable(log):
                log("ERROR", self.name, "interface_down", {"interface": interface})
            return False, True, "interface_down", {"interface": interface}

        if store:
            store.set_cidr(cidr)

        try:
            net = ipaddress.ip_network(cidr, strict=False)
            prefix = net.prefixlen
        except Exception:
            prefix = 24

        if callable(log):
            host_count = net.num_addresses - 2 if net.version == 4 and net.prefixlen < 31 else net.num_addresses
            log("DEBUG", self.name, "cidr_size", {"cidr": cidr, "hosts": host_count, "threshold": int(disc.get("large_hosts_threshold", 4096))})

        icmp_results: list[dict[str, Any]] = []
        arp_results: list[dict[str, Any]] = []
        truncated = False

        if prefix <= 24:
            cmd_icmp = ["nmap", "-sn", "-n", "-T5", "--send-ip"]
            if interface:
                cmd_icmp += ["-e", interface]
            cmd_icmp += ["-oX", "-", str(cidr)]
            if callable(log):
                log("DEBUG", self.name, "icmp_scan_start", {"cmd": " ".join(cmd_icmp)})
            try:
                p = subprocess.run(cmd_icmp, capture_output=True, text=True, timeout=300)
                if p.returncode == 0:
                    icmp_results = parse_nmap_xml(p.stdout)
                else:
                    if callable(log):
                        log("WARNING", self.name, "icmp_scan_failed", {"stderr": p.stderr.strip()})
            except subprocess.TimeoutExpired:
                if callable(log):
                    log("WARNING", self.name, "icmp_scan_timeout", {"timeout_s": 300})
            if callable(log):
                log("DEBUG", self.name, "icmp_scan_done", {"count": len(icmp_results)})

        cmd_arp = ["nmap", "-sn", "-n", "-PR"]
        if interface:
            cmd_arp += ["-e", interface]
        cmd_arp += ["-oX", "-", str(cidr)]
        if callable(log):
            log("DEBUG", self.name, "arp_scan_start", {"cmd": " ".join(cmd_arp)})
        try:
            p2 = subprocess.run(cmd_arp, capture_output=True, text=True, timeout=int(disc.get("arp_fallback_timeout_seconds", 300)))
            if p2.returncode != 0:
                msg = p2.stderr.strip() or "nmap_failed"
                if callable(log):
                    log("ERROR", self.name, "arp_scan_failed", {"stderr": msg})
                return False, True, "nmap_scan_failed", {"error": msg}
            arp_results = parse_nmap_xml(p2.stdout)
        except subprocess.TimeoutExpired:
            if callable(log):
                log("ERROR", self.name, "arp_scan_timeout", {"timeout_s": int(disc.get("arp_fallback_timeout_seconds", 300))})
            return True, False, "partial_timeout", {"cidr": cidr, "interface": interface, "mode": "arp_timeout"}
        if callable(log):
            log("DEBUG", self.name, "arp_scan_done", {"count": len(arp_results)})

        found = merge_hosts(icmp_results, arp_results)

        if store:
            for x in found:
                store.put_host(x["ip"], x.get("mac"), x.get("vendor"), x.get("hostname"))

        no_name_ips = [x["ip"] for x in found if not x.get("hostname")]
        if no_name_ips and bool(disc.get("resolve_hostnames", True)):
            budget = 180.0
            start = time.monotonic()
            resolved = 0
            for ip in no_name_ips:
                remaining = budget - (time.monotonic() - start)
                if remaining <= 0:
                    break
                per_call = min(2.0, remaining)
                name = resolve_avahi(ip, per_call)
                if name:
                    for h in found:
                        if h["ip"] == ip and not h.get("hostname"):
                            h["hostname"] = name
                            if store:
                                store.put_host(h["ip"], h.get("mac"), h.get("vendor"), h.get("hostname"))
                            resolved += 1
                            break
            if callable(log):
                log("DEBUG", self.name, "resolve_avahi_done", {"requested": len(no_name_ips), "resolved": resolved, "budget_s": 180})

        found.sort(key=lambda x: x["ip"])
        out = {"cidr": cidr, "interface": interface, "hosts": found, "truncated": truncated}
        with hosts_path.open("w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("DEBUG", self.name, "output_written", {"path": str(hosts_path), "count": len(found)})

        summary = {"count": len(found), "cidr": cidr, "interface": interface, "output": str(hosts_path), "truncated": truncated, "mode": "icmp+arp" if prefix <= 24 else "arp"}
        return True, False, "ok", summary
