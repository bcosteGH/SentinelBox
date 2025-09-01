from __future__ import annotations
import json
import time
import csv
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
        tcp_mode = str(cfg.get("tcp_top_ports", DEFAULT_TCP_TOP))
        udp_list = list(cfg.get("udp_whitelist", DEFAULT_UDP_WHITELIST))

        hosts = store.list_hosts() if store else []
        targets = [{"ip": h["ip"], "name": h.get("hostname") or h["ip"]} for h in hosts]
        if callable(log):
            log("INFO", self.name, "start", {"targets": len(targets)})

        if not targets:
            return True, False, "ok", {"count": 0, "output": None}

        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        out_path = data_dir / "port_scan.json"

        logs_dir = audit_dir / "logs" / self.name
        host_xml_dir = logs_dir / "xml"
        stderr_dir = logs_dir / "stderr"
        logs_dir.mkdir(parents=True, exist_ok=True)
        host_xml_dir.mkdir(parents=True, exist_ok=True)
        stderr_dir.mkdir(parents=True, exist_ok=True)
        commands_path = logs_dir / "commands.txt"
        summary_csv = logs_dir / "ports.csv"

        started = time.time()
        results = []
        timeouts = 0

        for t in targets:
            ip = t["ip"]
            display = t["name"]
            tcp_open, udp_open, meta = self._scan_host(
                ip=ip,
                display=display,
                timing=timing,
                host_timeout=host_timeout,
                max_retries=max_retries,
                min_rate=min_rate,
                max_rate=max_rate,
                tcp_mode=tcp_mode,
                udp_list=udp_list,
                commands_path=commands_path,
                host_xml_dir=host_xml_dir,
                stderr_dir=stderr_dir,
                log=log,
            )
            if meta.get("tcp_timeout") or meta.get("udp_timeout"):
                timeouts += 1

            tcp_open_sorted = sorted(tcp_open)
            udp_open_sorted = sorted(udp_open)

            if store:
                for p in tcp_open_sorted:
                    store.put_port(ip, "tcp", int(p), "open")
                for p in udp_open_sorted:
                    store.put_port(ip, "udp", int(p), "open")

            cat, why = self._categorize(tcp_open_sorted, udp_open_sorted)
            results.append({
                "ip": ip,
                "name": display if display != ip else None,
                "tcp_open": tcp_open_sorted,
                "udp_open": udp_open_sorted,
                "category": cat,
                "matched_by": why
            })

            try:
                host_json = logs_dir / f"{ip.replace('.', '_')}.json"
                host_json.write_text(json.dumps({
                    "ip": ip,
                    "name": display if display != ip else None,
                    "tcp_open": tcp_open_sorted,
                    "udp_open": udp_open_sorted,
                    "category": cat,
                    "matched_by": why,
                    "timings": meta
                }, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
            except Exception:
                pass

        duration = round(time.time() - started, 3)

        try:
            with summary_csv.open("w", encoding="utf-8", newline="") as cf:
                w = csv.writer(cf)
                w.writerow(["ip", "name", "tcp_open", "udp_open", "category", "matched_by"])
                for r in results:
                    w.writerow([
                        r["ip"],
                        r.get("name") or "",
                        ",".join(str(x) for x in r["tcp_open"]),
                        ",".join(str(x) for x in r["udp_open"]),
                        r["category"],
                        r["matched_by"] or ""
                    ])
        except Exception:
            pass

        with out_path.open("w", encoding="utf-8") as f:
            json.dump(
                {"items": results, "duration_s": duration, "timed_out": bool(timeouts)},
                f, ensure_ascii=False, separators=(",", ":"), indent=2
            )

        if callable(log):
            log("INFO", self.name, "done", {"count": len(results), "output": str(out_path), "duration_s": duration, "timeouts": timeouts})
        return True, False, "ok", {"count": len(results), "output": str(out_path)}

    def _scan_host(
        self,
        ip: str,
        display: str,
        timing: str,
        host_timeout: int,
        max_retries: int,
        min_rate: int,
        max_rate: int,
        tcp_mode: str,
        udp_list: list[int],
        commands_path: Path,
        host_xml_dir: Path,
        stderr_dir: Path,
        log,
    ) -> tuple[set[int], set[int], dict]:
        tcp_args = ["-n", "-Pn", f"-{timing}", "--max-retries", str(max_retries), "--host-timeout", f"{host_timeout}s", "-sS"]
        if min_rate > 0:
            tcp_args += ["--min-rate", str(min_rate)]
        if max_rate > 0:
            tcp_args += ["--max-rate", str(max_rate)]

        tcp_spec = str(tcp_mode).strip()
        if tcp_spec.isdigit():
            tcp_args += ["--top-ports", tcp_spec]
            tcp_mode_resolved = f"top-{tcp_spec}"
        elif tcp_spec.lower().startswith("top-"):
            tcp_args += ["--top-ports", tcp_spec.split("-", 1)[1]]
            tcp_mode_resolved = tcp_spec
        else:
            tcp_args += ["-p", tcp_spec]
            tcp_mode_resolved = f"ports:{tcp_spec}"

        tcp_xml = host_xml_dir / f"tcp_{ip.replace('.', '_')}.xml"
        tcp_cmd = ["nmap"] + tcp_args + ["-oX", str(tcp_xml), ip]

        udp_ports = ",".join(str(x) for x in sorted(set(int(p) for p in udp_list if int(p) > 0)))
        udp_xml = host_xml_dir / f"udp_{ip.replace('.', '_')}.xml"
        udp_cmd = ["nmap", "-n", "-Pn", f"-{timing}", "--max-retries", str(max_retries), "--host-timeout", f"{host_timeout}s", "-sU", "-p", udp_ports, "-oX", str(udp_xml), ip]

        if callable(log):
            log("DEBUG", self.name, "scan_commands", {
                "ip": ip,
                "name": display if display != ip else None,
                "tcp_mode_resolved": tcp_mode_resolved,
                "tcp": " ".join(tcp_cmd),
                "udp": " ".join(udp_cmd)
            })
        try:
            with commands_path.open("a", encoding="utf-8") as cf:
                cf.write(" ".join(tcp_cmd) + "\n")
                cf.write(" ".join(udp_cmd) + "\n")
        except Exception:
            pass

        tcp_open: set[int] = set()
        udp_open: set[int] = set()
        meta = {"tcp_timeout": False, "udp_timeout": False, "tcp_s": None, "udp_s": None}

        t0 = time.time()
        try:
            p = subprocess.run(tcp_cmd, capture_output=True, text=True, timeout=max(30, host_timeout + 30))
            meta["tcp_s"] = round(time.time() - t0, 3)
            if tcp_xml.exists():
                tcp_open = self._parse_open_ports(tcp_xml.read_text(encoding="utf-8"), "tcp")
            else:
                if p.stdout:
                    tcp_open = self._parse_open_ports(p.stdout, "tcp")
            try:
                if p.stderr:
                    (stderr_dir / f"tcp_{ip.replace('.', '_')}.stderr.txt").write_text(p.stderr, encoding="utf-8")
            except Exception:
                pass
        except subprocess.TimeoutExpired:
            meta["tcp_timeout"] = True

        t1 = time.time()
        try:
            p2 = subprocess.run(udp_cmd, capture_output=True, text=True, timeout=max(30, host_timeout + 30))
            meta["udp_s"] = round(time.time() - t1, 3)
            if udp_xml.exists():
                udp_open = self._parse_open_ports(udp_xml.read_text(encoding="utf-8"), "udp")
            else:
                if p2.stdout:
                    udp_open = self._parse_open_ports(p2.stdout, "udp")
            try:
                if p2.stderr:
                    (stderr_dir / f"udp_{ip.replace('.', '_')}.stderr.txt").write_text(p2.stderr, encoding="utf-8")
            except Exception:
                pass
        except subprocess.TimeoutExpired:
            meta["udp_timeout"] = True

        return tcp_open, udp_open, meta

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

        def score(rules: list[tuple[str, int]]) -> int:
            sc = 0
            for kind, val in rules:
                if kind == "t" and val in s_tcp:
                    sc += 1
                elif kind == "u" and val in s_udp:
                    sc += 1
            return sc

        if 9100 in s_tcp or 515 in s_tcp or (631 in s_tcp and (161 in s_udp or 515 in s_tcp or 9100 in s_tcp)):
            return ("printer", "ports_printer")

        cam_rules = [("t", 554), ("u", 3702), ("t", 8000), ("t", 8554), ("t", 8899), ("t", 81), ("t", 8080)]
        cam_score = score(cam_rules)
        if 554 in s_tcp or 554 in s_udp:
            if cam_score >= 3:
                return ("camera", "ports_rtsp_combo")

        if 37777 in s_tcp and ((554 in s_tcp) or (554 in s_udp) or (8000 in s_tcp)):
            return ("nvr", "ports_nvr")

        router_rules = [("u", 53), ("u", 1900), ("t", 80), ("t", 443), ("t", 7547), ("t", 8291)]
        if score(router_rules) >= 4:
            return ("router", "ports_router_combo")

        voip_rules = [("t", 5060), ("u", 5060), ("t", 5061), ("t", 80), ("t", 443)]
        if score(voip_rules) >= 3:
            return ("voip", "ports_voip_combo")

        nas_rules = [("t", 445), ("t", 139), ("t", 2049), ("u", 2049), ("t", 111), ("t", 5000), ("t", 5001)]
        if score(nas_rules) >= 3 and ((445 in s_tcp) or (2049 in s_tcp) or (2049 in s_udp) or ({5000,5001} & s_tcp)):
            return ("nas", "ports_storage_combo")

        if {135,139,445} <= s_tcp or 3389 in s_tcp:
            return ("windows", "ports_ms")

        return ("unknown", None)
