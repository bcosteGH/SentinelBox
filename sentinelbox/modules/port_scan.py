from __future__ import annotations
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional
from ..module import Module

DEFAULT_TCP_TOP = "top-1000"
DEFAULT_UDP_WHITELIST = [53,67,69,123,137,138,161,162,500,514,520,631,1434,1701,1900,4500,5353,67,68]

class PortScanNmap(Module):
    name = "PortScanNmap"

    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        cfg = context.get("port_scan") or {}
        timing = str(cfg.get("nmap_timing", "T4"))
        host_timeout = int(cfg.get("host_timeout_seconds", 180))
        max_retries = int(cfg.get("max_retries", 1))
        min_rate = int(cfg.get("min_rate", 50))
        max_rate = int(cfg.get("max_rate", 150))
        tcp_mode = str(cfg.get("tcp_mode", DEFAULT_TCP_TOP))
        udp_list = list(cfg.get("udp_whitelist", DEFAULT_UDP_WHITELIST))
        hosts = store.list_hosts() if store else []
        ips = [h["ip"] for h in hosts]
        if callable(log):
            log("INFO", self.name, "start", {"hosts": len(ips)})
        if not ips:
            return True, False, "ok", {"count": 0, "output": None}
        results = []
        for ip in ips:
            t_tcp, t_udp = self._scan_host(ip, timing, host_timeout, max_retries, min_rate, max_rate, tcp_mode, udp_list, log)
            tcp_open = sorted(t_tcp)
            udp_open = sorted(t_udp)
            if store:
                for p in tcp_open:
                    store.put_port(ip, "tcp", int(p), "open")
                for p in udp_open:
                    store.put_port(ip, "udp", int(p), "open")
            cat, why = self._categorize(tcp_open, udp_open)
            results.append({"ip": ip, "tcp_open": tcp_open, "udp_open": udp_open, "category": cat, "matched_by": why})
        audit_dir = Path(context.get("audit_dir"))
        out_path = audit_dir / "data" / "port_scan.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"items": results, "duration_s": 0, "timed_out": False}, f, ensure_ascii=False, separators=(",", ":"), indent=2)
        if callable(log):
            log("INFO", self.name, "done", {"count": len(results), "output": str(out_path)})
        return True, False, "ok", {"count": len(results), "output": str(out_path)}

    def _scan_host(self, ip: str, timing: str, host_timeout: int, max_retries: int, min_rate: int, max_rate: int, tcp_mode: str, udp_list: list[int], log) -> tuple[set[int], set[int]]:
        tcp_args = ["-n", "-Pn", f"-{timing}", "--max-retries", str(max_retries), "--host-timeout", f"{host_timeout}s", "-sS"]
        if min_rate > 0:
            tcp_args += ["--min-rate", str(min_rate)]
        if max_rate > 0:
            tcp_args += ["--max-rate", str(max_rate)]
        if tcp_mode.startswith("top-"):
            tcp_args += ["--top-ports", tcp_mode.split("-", 1)[1]]
        else:
            tcp_args += ["-p", tcp_mode]
        tcp_cmd = ["nmap"] + tcp_args + ["-oX", "-", ip]
        udp_ports = ",".join(str(x) for x in sorted(set(int(p) for p in udp_list if int(p) > 0)))
        udp_cmd = ["nmap", "-n", "-Pn", f"-{timing}", "--max-retries", str(max_retries), "--host-timeout", f"{host_timeout}s", "-sU", "-p", udp_ports, "-oX", "-", ip]
        tcp_open = set()
        udp_open = set()
        try:
            p = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=max(30, host_timeout + 30))
            if p.stdout:
                tcp_open = self._parse_open_ports(p.stdout, "tcp")
        except subprocess.TimeoutExpired:
            pass
        try:
            p2 = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=max(30, host_timeout + 30))
            if p2.stdout:
                udp_open = self._parse_open_ports(p2.stdout, "udp")
        except subprocess.TimeoutExpired:
            pass
        return tcp_open, udp_open

    def _parse_open_ports(self, xml_text: str, proto: str) -> set[int]:
        out = set()
        try:
            root = ET.fromstring(xml_text)
        except Exception:
            return out
        for host in root.findall("host"):
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for p in ports_node.findall("port"):
                if p.get("protocol") != proto:
                    continue
                st = p.find("state")
                if st is None:
                    continue
                if st.get("state") == "open":
                    try:
                        out.add(int(p.get("portid")))
                    except Exception:
                        pass
        return out

    def _categorize(self, tcp_open: list[int], udp_open: list[int]) -> tuple[str, Optional[str]]:
        s_tcp = set(tcp_open)
        s_udp = set(udp_open)
        if {631, 515, 9100} & s_tcp or 631 in s_udp:
            return ("printer", "printer_ports")
        if {80, 443} & s_tcp and 53 in s_udp:
            return ("router", "udp_control_mix")
        if {554, 80, 8000, 8080} & s_tcp or {554, 3702} & s_udp:
            return ("camera", "rtsp_http_mix")
        if {37777, 8000, 554} & s_tcp:
            return ("nvr", "nvr_ports")
        return ("unknown", None)
