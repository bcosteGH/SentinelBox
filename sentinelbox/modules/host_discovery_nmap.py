import json
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Optional
import shutil
import nmap
from ..module import Module
from ..net import get_interface_cidr, ensure_dir

def is_interface_up(interface: str) -> bool:
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show", "dev", interface], text=True)
    except Exception:
        return False
    return " state UP " in f" {out} "

def count_hosts(cidr: str) -> int:
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version == 4 and net.prefixlen < 31:
        return max(0, net.num_addresses - 2)
    return net.num_addresses

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

def resolve_getent(ip: str, timeout_s: float) -> Optional[str]:
    try:
        p = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=timeout_s)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    line = p.stdout.strip().splitlines()
    if not line:
        return None
    parts = line[0].split()
    if len(parts) >= 2:
        return parts[1].rstrip(".")
    return None

def resolve_avahi(ip: str, timeout_s: float) -> Optional[str]:
    if shutil.which("avahi-resolve-address") is None:
        return None
    try:
        p = subprocess.run(["avahi-resolve-address", ip], capture_output=True, text=True, timeout=timeout_s)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    parts = p.stdout.strip().split()
    if len(parts) >= 2:
        return parts[-1].rstrip(".")
    return None

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
        large_threshold = int(disc.get("large_hosts_threshold", 4096))
        host_count = count_hosts(cidr)
        truncated = False
        if callable(log):
            log("DEBUG", self.name, "cidr_size", {"cidr": cidr, "hosts": host_count, "threshold": large_threshold})
        try:
            if host_count <= large_threshold:
                nm = nmap.PortScanner()
                args = []
                base = str(disc.get("nmap_args", "-sn")).strip()
                if base:
                    args.append(base)
                timing = str(disc.get("nmap_timing", "T3")).strip()
                if timing:
                    if not timing.startswith("-"):
                        args.append(f"-{timing}")
                    else:
                        args.append(timing)
                min_rate = int(disc.get("nmap_min_rate", 0))
                max_rate = int(disc.get("nmap_max_rate", 0))
                if min_rate > 0:
                    args.append(f"--min-rate {min_rate}")
                if max_rate > 0:
                    args.append(f"--max-rate {max_rate}")
                if interface:
                    args.append(f"-e {interface}")
                arg_str = " ".join(args)
                if callable(log):
                    log("DEBUG", self.name, "nmap_args", {"args": arg_str, "targets": str(cidr)})
                nm.scan(hosts=str(cidr), arguments=arg_str)
                found = []
                for host in nm.all_hosts():
                    h = nm[host]
                    st = "unknown"
                    try:
                        st = h.state()
                    except Exception:
                        try:
                            st = h.get("status", {}).get("state", "unknown")
                        except Exception:
                            st = "unknown"
                    if st != "up":
                        continue
                    mac = None
                    vendor = None
                    hostname = None
                    try:
                        hn_list = h.get("hostnames", [])
                        if hn_list:
                            first = hn_list[0]
                            if isinstance(first, dict):
                                name = first.get("name")
                            else:
                                name = str(first)
                            if name:
                                hostname = name
                    except Exception:
                        pass
                    if not hostname:
                        try:
                            hn2 = h.hostname()
                            if hn2:
                                hostname = hn2
                        except Exception:
                            pass
                    try:
                        if isinstance(h, dict):
                            mac = h.get("addresses", {}).get("mac")
                            if mac:
                                vendor = h.get("vendor", {}).get(mac)
                    except Exception:
                        pass
                    found.append({"ip": host, "mac": mac, "vendor": vendor, "hostname": hostname, "source": "nmap", "rtt_ms": None})
                    if store:
                        store.put_host(host, mac, vendor, hostname)
                if callable(log):
                    log("DEBUG", self.name, "nmap_found", {"count": len(found)})
                no_name_ips = [x["ip"] for x in found if not x.get("hostname")]
                if no_name_ips and bool(disc.get("resolve_hostnames", True)):
                    timeout_s = max(0.05, float(int(disc.get("resolver_timeout_ms", 300)))/1000.0)
                    threads = max(1, int(disc.get("resolver_threads", 32)))
                    if callable(log):
                        log("DEBUG", self.name, "resolve_hostnames_start", {"ips": len(no_name_ips), "threads": threads, "timeout_s": timeout_s})
                    results = {}
                    with ThreadPoolExecutor(max_workers=threads) as ex:
                        futs = {ex.submit(resolve_getent, ip, timeout_s): ip for ip in no_name_ips}
                        if bool(disc.get("enable_avahi", True)):
                            for ip in list(no_name_ips):
                                futs[ex.submit(resolve_avahi, ip, timeout_s)] = ip
                        for fut in as_completed(futs):
                            ip = futs[fut]
                            try:
                                name = fut.result()
                            except Exception:
                                name = None
                            if name and ip not in results:
                                results[ip] = name
                    for x in found:
                        if not x.get("hostname") and x["ip"] in results:
                            x["hostname"] = results[x["ip"]]
                            if store:
                                store.put_host(x["ip"], x.get("mac"), x.get("vendor"), x.get("hostname"))
                    if callable(log):
                        log("DEBUG", self.name, "resolve_hostnames_done", {"resolved": len(results)})
                found.sort(key=lambda x: x["ip"])
                out = {"cidr": cidr, "interface": interface, "hosts": found, "truncated": truncated}
                with hosts_path.open("w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, separators=(",", ":"), indent=2)
                if callable(log):
                    log("DEBUG", self.name, "output_written", {"path": str(hosts_path), "count": len(found)})
                summary = {"count": len(found), "cidr": cidr, "interface": interface, "output": str(hosts_path), "truncated": truncated, "mode": "nmap"}
                return True, False, "ok", summary
            else:
                cmd = ["nmap", "-sn", "-PR"]
                if interface:
                    cmd += ["-e", interface]
                cmd += ["-oX", "-", str(cidr)]
                timeout_s = int(disc.get("arp_fallback_timeout_seconds", 300))
                if callable(log):
                    log("DEBUG", self.name, "fallback_arp_start", {"timeout_s": timeout_s, "targets": str(cidr)})
                try:
                    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
                except subprocess.TimeoutExpired:
                    found = []
                    truncated = True
                    out = {"cidr": cidr, "interface": interface, "hosts": found, "truncated": truncated, "timeout": True}
                    with hosts_path.open("w", encoding="utf-8") as f:
                        json.dump(out, f, ensure_ascii=False, separators=(",", ":"), indent=2)
                    if callable(log):
                        log("ERROR", self.name, "fallback_arp_timeout", {"timeout_s": timeout_s})
                    summary = {"count": len(found), "cidr": cidr, "interface": interface, "output": str(hosts_path), "truncated": truncated, "mode": "nmap_arp_timeout", "timeout_s": timeout_s}
                    return True, False, "partial_timeout", summary
                if p.returncode != 0:
                    msg = p.stderr.strip() or "nmap_failed"
                    if callable(log):
                        log("ERROR", self.name, "fallback_arp_failed", {"stderr": msg})
                    if "Failed to resolve" in msg or "Failed to open device" in msg:
                        return False, True, "nmap_scan_failed", {"error": msg}
                    if "not found" in msg.lower():
                        return False, True, "nmap_not_found", {"error": msg}
                    return False, True, "nmap_scan_failed", {"error": msg}
                xml_text = p.stdout
                found = parse_nmap_xml(xml_text)
                truncated = True
                if store:
                    for x in found:
                        store.put_host(x["ip"], x.get("mac"), x.get("vendor"), x.get("hostname"))
                no_name_ips = [x["ip"] for x in found if not x.get("hostname")]
                if no_name_ips and bool(disc.get("resolve_hostnames", True)):
                    timeout_s = max(0.05, float(int(disc.get("resolver_timeout_ms", 300)))/1000.0)
                    threads = max(1, int(disc.get("resolver_threads", 32)))
                    if no_name_ips and callable(log):
                        log("DEBUG", self.name, "resolve_hostnames_start", {"ips": len(no_name_ips), "threads": threads, "timeout_s": timeout_s})
                    if no_name_ips:
                        results = {}
                        with ThreadPoolExecutor(max_workers=threads) as ex:
                            futs = {ex.submit(resolve_getent, ip, timeout_s): ip for ip in no_name_ips}
                            if bool(disc.get("enable_avahi", True)):
                                for ip in list(no_name_ips):
                                    futs[ex.submit(resolve_avahi, ip, timeout_s)] = ip
                            for fut in as_completed(futs):
                                ip = futs[fut]
                                try:
                                    name = fut.result()
                                except Exception:
                                    name = None
                                if name and ip not in results:
                                    results[ip] = name
                        for x in found:
                            if not x.get("hostname") and x["ip"] in results:
                                x["hostname"] = results[x["ip"]]
                                if store:
                                    store.put_host(x["ip"], x.get("mac"), x.get("vendor"), x.get("hostname"))
                        if callable(log):
                            log("DEBUG", self.name, "resolve_hostnames_done", {"resolved": len(results)})
                out = {"cidr": cidr, "interface": interface, "hosts": found, "truncated": truncated}
                with hosts_path.open("w", encoding="utf-8") as f:
                    json.dump(out, f, ensure_ascii=False, separators=(",", ":"), indent=2)
                if callable(log):
                    log("DEBUG", self.name, "output_written", {"path": str(hosts_path), "count": len(found)})
                summary = {"count": len(found), "cidr": cidr, "interface": interface, "output": str(hosts_path), "truncated": truncated, "mode": "nmap_arp_fallback"}
                return True, False, "ok", summary
        except nmap.PortScannerError as e:
            msg = str(e)
            if callable(log):
                log("ERROR", self.name, "nmap_exception", {"error": msg})
            if "nmap program was not found" in msg.lower():
                return False, True, "nmap_not_found", {"error": msg}
            if "failed to open device" in msg.lower():
                return False, True, "interface_down", {"interface": interface, "error": msg}
            return False, True, "nmap_scan_failed", {"error": msg}
        except Exception as e:
            if callable(log):
                log("ERROR", self.name, "module_exception", {"error": str(e)})
            return False, True, "nmap_scan_exception", {"error": str(e)}
