import json
import ipaddress
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional
import shutil
import time
import csv
import nmap
from ..module import Module
from ..net import get_interface_cidr, ensure_dir

def is_interface_up(interface: str) -> bool:
    try:
        out = subprocess.check_output(["ip", "-o", "link", "show", "dev", interface], text=True)
    except Exception:
        return False
    return " state UP " in f" {out} "

def _norm_hostname(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    return str(name).strip().rstrip(".").lower() or None

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
                    hostname = _norm_hostname(name)
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
        return _norm_hostname(parts[-1])
    return None

def resolve_dns_getent(ip: str, timeout_s: float) -> Optional[str]:
    if shutil.which("getent") is None:
        return None
    try:
        p = subprocess.run(["getent", "hosts", ip], capture_output=True, text=True, timeout=max(0.05, timeout_s))
    except Exception:
        return None
    if p.returncode != 0:
        return None
    line = (p.stdout or "").splitlines()
    if not line:
        return None
    parts = line[0].split()
    if len(parts) >= 2:
        return _norm_hostname(parts[1])
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
        logs_dir = audit_dir / "logs" / self.name
        resolve_dir = logs_dir / "resolve"
        ensure_dir(resolve_dir)
        commands_path = logs_dir / "commands.txt"
        nmap_icmp_xml = logs_dir / "nmap_icmp.xml"
        nmap_arp_xml = logs_dir / "nmap_arp.xml"
        discovery_json = logs_dir / "discovery.json"
        hosts_csv = logs_dir / "hosts.csv"
        disc = context.get("discovery") or {}
        log = context.get("log")
        store = context.get("store")

        if callable(log):
            log("DEBUG", self.name, "start", {"interface": interface, "logs_dir": str(logs_dir)})

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
            host_count = net.num_addresses - 2 if net.version == 4 and net.prefixlen < 31 else net.num_addresses
        except Exception:
            prefix = 24
            host_count = 0

        if callable(log):
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
                with commands_path.open("a", encoding="utf-8") as cf:
                    cf.write(" ".join(cmd_icmp) + "\n")
                p = subprocess.run(cmd_icmp, capture_output=True, text=True, timeout=300)
                if p.returncode == 0:
                    icmp_xml = p.stdout or ""
                    try:
                        nmap_icmp_xml.write_text(icmp_xml, encoding="utf-8")
                    except Exception:
                        pass
                    icmp_results = parse_nmap_xml(icmp_xml)
                else:
                    if callable(log):
                        log("WARNING", self.name, "icmp_scan_failed", {"stderr": (p.stderr or "").strip()})
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
            with commands_path.open("a", encoding="utf-8") as cf:
                cf.write(" ".join(cmd_arp) + "\n")
            p2 = subprocess.run(cmd_arp, capture_output=True, text=True, timeout=int(disc.get("arp_fallback_timeout_seconds", 300)))
            if p2.returncode != 0:
                msg = (p2.stderr or "").strip() or "nmap_failed"
                if callable(log):
                    log("ERROR", self.name, "arp_scan_failed", {"stderr": msg})
                return False, True, "nmap_scan_failed", {"error": msg}
            arp_xml = p2.stdout or ""
            try:
                nmap_arp_xml.write_text(arp_xml, encoding="utf-8")
            except Exception:
                pass
            arp_results = parse_nmap_xml(arp_xml)
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

        dns_timeout_s = max(0.05, float(int(disc.get("resolver_timeout_ms", 300))) / 1000.0)
        budget_s = 180.0
        started = time.monotonic()
        dns_named = 0
        mdns_named = 0
        skipped_budget = 0

        for h in found:
            ip = h["ip"]
            if time.monotonic() - started >= budget_s:
                skipped_budget += 1
                break
            current = _norm_hostname(h.get("hostname"))
            name_dns = None
            name_mdns = None
            err_dns = None
            err_mdns = None
            t0 = time.monotonic()
            try:
                name_dns = resolve_dns_getent(ip, dns_timeout_s)
            except Exception as e:
                err_dns = str(e)
            t_dns = round((time.monotonic() - t0) * 1000)
            t1 = time.monotonic()
            try:
                name_mdns = resolve_avahi(ip, dns_timeout_s)
            except Exception as e:
                err_mdns = str(e)
            t_mdns = round((time.monotonic() - t1) * 1000)
            chosen = current
            chosen_src = None
            if name_dns:
                chosen = name_dns
                chosen_src = "dns"
            elif (not current or current.endswith(".local")) and name_mdns:
                chosen = name_mdns
                chosen_src = "mdns"
            else:
                if current:
                    if not current.endswith(".local"):
                        chosen_src = "nmap"
                    else:
                        if name_mdns:
                            chosen = name_mdns
                            chosen_src = "mdns"
                        else:
                            chosen_src = "nmap"
            if chosen and chosen != current:
                h["hostname"] = chosen
                if store:
                    store.put_host(h["ip"], h.get("mac"), h.get("vendor"), h.get("hostname"))
            if chosen_src == "dns":
                dns_named += 1
            elif chosen_src == "mdns":
                mdns_named += 1
            try:
                (resolve_dir / f"{ip}.json").write_text(json.dumps({
                    "ip": ip,
                    "nmap_hostname": current,
                    "dns": {"name": name_dns, "ok": bool(name_dns), "latency_ms": t_dns, "error": err_dns},
                    "mdns": {"name": name_mdns, "ok": bool(name_mdns), "latency_ms": t_mdns, "error": err_mdns},
                    "chosen": {"name": h.get("hostname"), "source": chosen_src}
                }, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
            except Exception:
                pass
            if callable(log):
                log("DEBUG", self.name, "resolve_ip_done", {"ip": ip, "dns": name_dns, "mdns": name_mdns, "chosen": h.get("hostname"), "source": chosen_src})

        if skipped_budget and callable(log):
            log("WARNING", self.name, "resolve_budget_exceeded", {"skipped": skipped_budget, "budget_s": budget_s})

        found.sort(key=lambda x: x["ip"])
        out = {"cidr": cidr, "interface": interface, "hosts": found, "truncated": truncated}
        with hosts_path.open("w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("DEBUG", self.name, "output_written", {"path": str(hosts_path), "count": len(found)})

        try:
            with hosts_csv.open("w", encoding="utf-8", newline="") as cf:
                w = csv.writer(cf)
                w.writerow(["ip", "mac", "vendor", "hostname"])
                for x in found:
                    w.writerow([x.get("ip"), x.get("mac") or "", x.get("vendor") or "", x.get("hostname") or ""])
        except Exception:
            pass

        try:
            discovery = {
                "cidr": cidr,
                "interface": interface,
                "scan_mode": "icmp+arp" if prefix <= 24 else "arp",
                "timings": {"duration_s": None},
                "counts": {"hosts_up": len(found), "dns_named": dns_named, "mdns_named": mdns_named},
                "resolver": {"timeout_ms": int(disc.get("resolver_timeout_ms", 300)), "budget_s": 180}
            }
            discovery_json.write_text(json.dumps(discovery, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
        except Exception:
            pass

        summary = {"count": len(found), "cidr": cidr, "interface": interface, "output": str(hosts_path), "truncated": truncated, "mode": "icmp+arp" if prefix <= 24 else "arp"}
        return True, False, "ok", summary
