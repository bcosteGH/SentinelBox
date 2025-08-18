import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module

VULN_SCRIPTS = {
    "ftp-anon","ftp-proftpd-backdoor","ftp-vsftpd-backdoor",
    "http-barracuda-dir-traversal","http-config-backup","http-default-accounts",
    "http-method-tamper","http-vuln-cve2017-5689","http-wordpress-users",
    "http-dlink-backdoor","http-phpmyadmin-dir-traversal","http-tplink-dir-traversal",
    "http-vuln-cve2012-1823","http-cookie-flags","http-frontpage-login","http-git",
    "http-slowloris-check","http-vuln-cve2015-1635","rdp-vuln-ms12-020",
    "smb-vuln-ms07-029","samba-vuln-cve-2012-1182","smb-double-pulsar-backdoor",
    "smb-vuln-cve-2017-7494","smb-vuln-ms10-061","smb-vuln-ms17-010","smb2-vuln-uptime",
    "ms-sql-empty-password","mysql-dump-hashes","mysql-empty-password",
    "sip-enum-users","krb5-enum-users","realvnc-auth-bypass","x11-access","afp-path-vuln",
    "firewall-bypass","dns-update","vulners"
}

CVE_MAP: Dict[str, Tuple[str, str, str]] = {
    "http-vuln-cve2017-5689": ("CVE-2017-5689","10.0","Authentication bypass via digest blank response digest"),
    "afp-path-vuln": ("CVE-2010-0533","7.5","AFP directory traversal allows listing parent of share root"),
    "realvnc-auth-bypass": ("CVE-2006-2369","7.5","RealVNC 4.1.1 auth bypass via insecure security type"),
    "smb2-vuln-uptime": ("CVE-2017-0147","","Missing Windows SMB Server security update"),
    "smb-vuln-ms17-010": ("CVE-2017-0143","9.0","Critical RCE in Microsoft SMBv1"),
    "smb-vuln-ms10-061": ("CVE-2010-2729","9.3","Print Spooler improper validation allows RCE"),
    "smb-vuln-cve-2017-7494": ("CVE-2017-7494","7.5","Samba 3.5.0+ RCE via uploaded shared library"),
    "smb-double-pulsar-backdoor": ("Malware","10.0","Double Pulsar SMB backdoor detected"),
    "samba-vuln-cve-2012-1182": ("CVE-2012-1182","10.0","Samba ≤3.6.3 anonymous RCE as root"),
    "smb-vuln-ms07-029": ("CVE-2007-1748","10.0","DNS Server RPC stack overflow RCE"),
    "rdp-vuln-ms12-020": ("CVE-2012-0152","4.3","RDP DoS vulnerability"),
    "http-vuln-cve2015-1635": ("CVE-2015-1635","10.0","HTTP.sys RCE via crafted HTTP requests"),
    "http-slowloris-check": ("CVE-2007-6750","5.0","Slowloris DoS via partial requests"),
    "http-vuln-cve2012-1823": ("CVE-2012-1823","7.5","PHP-CGI switches injection leads to RCE"),
    "http-phpmyadmin-dir-traversal": ("CVE-2005-3299","5.0","phpMyAdmin 2.6.4 file inclusion via $__redirect"),
    "http-dlink-backdoor": ("Backdoor","","D-Link firmware admin bypass via secret User-Agent"),
    "ftp-vsftpd-backdoor": ("CVE-2011-2523","9.8","vsFTPd 2.3.4 backdoor"),
    "http-tplink-dir-traversal": ("Bypass","","TP-Link path traversal reads config/any file")
}

SIMPLE_MAP: Dict[str, Tuple[str, str]] = {
    "ftp-proftpd-backdoor": ("Backdoor","Presence of ProFTP 1.3.3c backdoor"),
    "firewall-bypass": ("Bypass","Firewall vulnerable to FTP helper bypass"),
    "x11-access": ("GUI access","X server access is granted"),
    "dns-update": ("Insecure update","DNS record update allowed without permission"),
    "http-frontpage-login": ("Bypass","FrontPage extensions allow anonymous login"),
    "ftp-anon": ("Default authentication","Anonymous FTP login allowed")
}

VULNERS_LABEL = "Old version"
RX_VULNERS = re.compile(r"(CVE-\d+-\d+)\s+(\d+(?:\.\d+)?)")

class ServiceFingerprintNmap(Module):
    name = "ServiceFingerprintNmap"

    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        start = time.time()
        log = context.get("log")
        store = context.get("store")
        cfg = context.get("service_fingerprint") or {}
        timing = str(cfg.get("nmap_timing", "T4"))
        host_timeout = int(cfg.get("host_timeout_seconds", 180))
        max_retries = int(cfg.get("max_retries", 1))
        min_rate = int(cfg.get("min_rate", 50))
        max_rate = int(cfg.get("max_rate", 150))
        version_intensity = int(cfg.get("version_intensity", 2))
        script_timeout = int(cfg.get("script_timeout_seconds", 60))

        audit_dir = Path(context.get("audit_dir"))
        out_dir = audit_dir / "data"
        out_dir.mkdir(parents=True, exist_ok=True)
        services_json_path = out_dir / "service_inventory.json"
        hostvuln_json_path = out_dir / "host_vuln_summary.json"

        ports = store.list_ports() if store else []
        by_ip: Dict[str, Dict[str, List[int]]] = {}
        for p in ports:
            if str(p.get("state", "")).lower() != "open":
                continue
            ip = p["ip"]
            proto = p["proto"].lower()
            port = int(p["port"])
            if ip not in by_ip:
                by_ip[ip] = {"tcp": [], "udp": []}
            if proto in ("tcp","udp"):
                by_ip[ip][proto].append(port)

        if callable(log):
            log("INFO", self.name, "start", {"ips": len(by_ip)})

        scripts_list = [
            "afp-path-vuln","dns-update","firewall-bypass","ftp-anon","ftp-proftpd-backdoor","ftp-vsftpd-backdoor",
            "http-barracuda-dir-traversal","http-config-backup","http-cookie-flags","http-default-accounts",
            "http-dlink-backdoor","http-frontpage-login","http-git","http-method-tamper","http-phpmyadmin-dir-traversal",
            "http-slowloris-check","http-tplink-dir-traversal","http-vuln-cve2012-1823","http-vuln-cve2015-1635","http-vuln-cve2017-5689",
            "http-wordpress-users","krb5-enum-users","ms-sql-empty-password","mysql-dump-hashes","mysql-empty-password",
            "rdp-vuln-ms12-020","realvnc-auth-bypass","samba-vuln-cve-2012-1182","sip-enum-users","smb-double-pulsar-backdoor",
            "smb-vuln-cve-2017-7494","smb-vuln-ms07-029","smb-vuln-ms10-061","smb-vuln-ms17-010","smb2-vuln-uptime","vulners","x11-access"
        ]
        scripts_arg = ",".join(scripts_list)

        total_ports = 0
        for ip, d in by_ip.items():
            d["tcp"] = sorted(set(d["tcp"]))
            d["udp"] = sorted(set(d["udp"]))
            total_ports += len(d["tcp"]) + len(d["udp"])

        if callable(log):
            log("DEBUG", self.name, "targets", {"hosts": len(by_ip), "ports": total_ports})

        hits_total = 0
        outdated_total = 0
        services_items: List[Dict[str, Any]] = []
        hostvuln_items: List[Dict[str, Any]] = []

        for ip, d in by_ip.items():
            tcp_ports = d["tcp"]
            udp_ports = d["udp"]
            if not tcp_ports and not udp_ports:
                hostvuln_items.append({"ip": ip, "vulns": []})
                continue

            probes = []
            if tcp_ports:
                probes.append("-sS")
            if udp_ports:
                probes.append("-sU")
            base = ["nmap", "-Pn", "-n", f"-{timing}", "--max-retries", str(max_retries), "--host-timeout", f"{host_timeout}s", "--min-rate", str(min_rate), "--max-rate", str(max_rate), "-sV", "--version-intensity", str(version_intensity), "--script", scripts_arg, "--script-timeout", f"{script_timeout}s"]
            cmd = base + probes

            parts = []
            if tcp_ports:
                parts.append("T:" + ",".join(str(p) for p in tcp_ports))
            if udp_ports:
                parts.append("U:" + ",".join(str(p) for p in udp_ports))
            if parts:
                cmd += ["-p", ",".join(parts)]
            cmd += ["--script-args", "mincvss=7", "-oX", "-", ip]

            if callable(log):
                log("DEBUG", self.name, "exec", {"cmd": " ".join(cmd)})

            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=host_timeout + 60)
            except subprocess.TimeoutExpired:
                if callable(log):
                    log("WARNING", self.name, "timeout", {"ip": ip})
                hostvuln_items.append({"ip": ip, "vulns": []})
                continue
            if p.returncode != 0 and not p.stdout:
                if callable(log):
                    log("WARNING", self.name, "nmap_error", {"ip": ip, "code": p.returncode, "stderr": p.stderr})
                hostvuln_items.append({"ip": ip, "vulns": []})
                continue

            xml = p.stdout
            try:
                root = ET.fromstring(xml)
            except Exception:
                if callable(log):
                    log("WARNING", self.name, "xml_parse_error", {"ip": ip})
                hostvuln_items.append({"ip": ip, "vulns": []})
                continue

            hostnode = None
            for hn in root.findall("host"):
                addrs = hn.findall("address")
                ip_found = None
                for a in addrs:
                    if a.get("addrtype") == "ipv4":
                        ip_found = a.get("addr")
                        break
                if ip_found == ip:
                    hostnode = hn
                    break
            if hostnode is None:
                hostvuln_items.append({"ip": ip, "vulns": []})
                continue

            host_scripts = {}
            hs = hostnode.find("hostscript")
            if hs is not None:
                for s in hs.findall("script"):
                    sid = s.get("id")
                    if sid and sid in VULN_SCRIPTS:
                        out = s.get("output") or ""
                        host_scripts[sid] = out

            port_scripts: Dict[Tuple[str,int], Dict[str,str]] = {}
            for port in hostnode.findall("ports/port"):
                proto = port.get("protocol") or ""
                portid = int(port.get("portid") or "0")
                scripts_here = {}
                for s in port.findall("script"):
                    sid = s.get("id")
                    if sid and sid in VULN_SCRIPTS:
                        out = s.get("output") or ""
                        scripts_here[sid] = out
                if scripts_here:
                    port_scripts[(proto, portid)] = scripts_here

            port_states: Dict[Tuple[str,int], str] = {}
            for pnode in hostnode.findall("ports/port"):
                proto = pnode.get("protocol") or ""
                portid = int(pnode.get("portid") or "0")
                st = pnode.find("state")
                state = st.get("state") if st is not None else None
                if state:
                    port_states[(proto, portid)] = state

            service_data: Dict[Tuple[str,int], Dict[str, Optional[str]]] = {}
            service_conf: Dict[Tuple[str,int], Tuple[Optional[int], Optional[int]]] = {}
            for pnode in hostnode.findall("ports/port"):
                proto = pnode.get("protocol") or ""
                portid = int(pnode.get("portid") or "0")
                svc = pnode.find("service")
                name = svc.get("name") if svc is not None else None
                product = svc.get("product") if svc is not None else None
                version = svc.get("version") if svc is not None else None
                extrainfo = svc.get("extrainfo") if svc is not None else None
                tunnel = svc.get("tunnel") if svc is not None else None
                conf_raw = svc.get("conf") if svc is not None else None
                try:
                    conf = int(conf_raw) if conf_raw is not None else None
                except Exception:
                    conf = None
                name_conf = conf if name else None
                ver_conf = conf if version else None
                service_data[(proto, portid)] = {
                    "name": name,
                    "product": product,
                    "version": version,
                    "extrainfo": extrainfo,
                    "tunnel": tunnel
                }
                service_conf[(proto, portid)] = (name_conf, ver_conf)

            per_port_vulners: Dict[Tuple[str,int], int] = {}
            for key, scrs in list(port_scripts.items()):
                out = scrs.get("vulners") or ""
                if not out:
                    per_port_vulners[key] = 0
                    continue
                seen = set()
                cnt = 0
                for m in RX_VULNERS.finditer(out):
                    cve = m.group(1)
                    try:
                        score = float(m.group(2))
                    except Exception:
                        score = 0.0
                    if score >= 7.0 and cve not in seen:
                        seen.add(cve)
                        cnt += 1
                per_port_vulners[key] = cnt

            per_port_hits: Dict[str, Dict[str, Any]] = {}
            agg_by_label: Dict[str, Dict[str, Any]] = {}

            for (proto, portid), scrs in list(port_scripts.items()):
                for sid, out in scrs.items():
                    if sid == "vulners":
                        continue
                    label = None
                    desc = None
                    if sid in CVE_MAP:
                        state = ""
                        for line in out.splitlines():
                            if line.lower().startswith("state:"):
                                state = line.split(":",1)[1].strip().lower()
                                break
                        if state.startswith("vulnerable") or state.startswith("likely vuln"):
                            info = CVE_MAP[sid]
                            label = info[0] if info[0] else sid
                            desc = info[2] if len(info) > 2 else sid
                        else:
                            label = None
                    elif sid in SIMPLE_MAP:
                        if out.strip():
                            info2 = SIMPLE_MAP[sid]
                            label = info2[0]
                            desc = info2[1]
                    elif sid == "http-git":
                        first = out.strip().splitlines()[0] if out.strip() else ""
                        if first:
                            label = "Disclosure"
                            desc = f"Git repository found: {first}"
                    elif sid == "ms-sql-empty-password":
                        if "Login Success" in out:
                            label = "Default account"
                            desc = "Empty password in MS-SQL database"
                    elif sid == "mysql-dump-hashes":
                        if ":" in out:
                            label = "Hashes"
                            desc = "Database hash dump available"
                    elif sid == "mysql-empty-password":
                        if "account has empty password" in out:
                            label = "Default account"
                            desc = "Empty password in MySQL"
                    elif sid == "krb5-enum-users":
                        lines = [x for x in out.splitlines()[1:] if x.strip()]
                        if lines:
                            label = "Disclosure"
                            desc = "Kerberos user enumeration"
                    elif sid == "http-method-tamper":
                        if "suspected to be vulnerable" in out.lower() or "vulnerable" in out.lower():
                            label = "Bypass"
                            desc = "HTTP verb tampering suspected"
                    elif sid == "sip-enum-users":
                        if ":" in out:
                            label = "Disclosure"
                            desc = "SIP numbers enumeration"
                    elif sid == "http-config-backup":
                        if "/".encode() or "/" in out:
                            label = "Disclosure"
                            desc = "HTTP configuration files exposed"
                    elif sid == "http-cookie-flags":
                        if "httponly" in out.lower() or "secure" in out.lower() or "cookie" in out.lower():
                            label = "Vulnerability"
                            desc = "Security lacks in HTTP headers"
                    if label and desc:
                        k = f"{label}"
                        if k not in agg_by_label:
                            agg_by_label[k] = {"label": label, "description": desc, "ports": set()}
                        agg_by_label[k]["ports"].add(f"{proto}/{portid}")
                        per_port_hits.setdefault(f"{proto}/{portid}", {"labels": set()})
                        per_port_hits[f"{proto}/{portid}"]["labels"].add(label)

            outdated_ports = []
            for key, cnt in per_port_vulners.items():
                if cnt >= 3:
                    proto, portid = key
                    outdated_ports.append(f"{proto}/{portid}")

            if outdated_ports:
                total_cves7 = sum(per_port_vulners.get((p.split("/")[0], int(p.split("/")[1])), 0) for p in outdated_ports)
                if "Old version" not in agg_by_label:
                    agg_by_label["Old version"] = {"label": "Old version", "description": f"La version du logiciel semble ancienne, {total_cves7} CVE(s) avec CVSS ≥ 7 détectées", "ports": set()}
                else:
                    agg_by_label["Old version"]["description"] = f"La version du logiciel semble ancienne, {total_cves7} CVE(s) avec CVSS ≥ 7 détectées"
                for pstr in outdated_ports:
                    agg_by_label["Old version"]["ports"].add(pstr)

            for (proto, portid), svc in service_data.items():
                state = port_states.get((proto, portid), "open")
                name_conf, ver_conf = service_conf.get((proto, portid), (None, None))
                store.put_service_info(
                    ip=ip,
                    proto=proto,
                    port=portid,
                    state=state or "open",
                    service_name=svc.get("name"),
                    name_confidence=name_conf,
                    product=svc.get("product"),
                    version=svc.get("version"),
                    version_confidence=ver_conf,
                    extrainfo=svc.get("extrainfo"),
                    tunnel=svc.get("tunnel")
                )
                services_items.append({
                    "ip": ip,
                    "proto": proto,
                    "port": portid,
                    "state": state or "open",
                    "service_name": svc.get("name"),
                    "name_confidence": name_conf,
                    "product": svc.get("product"),
                    "version": svc.get("version"),
                    "version_confidence": ver_conf,
                    "extrainfo": svc.get("extrainfo"),
                    "tunnel": svc.get("tunnel")
                })

            items = []
            for v in agg_by_label.values():
                items.append({"label": v["label"], "ports": sorted(list(v["ports"])) if v["ports"] else [], "description": v["description"]})
            store.replace_host_vuln_summary(ip, json.dumps({"items": items}, ensure_ascii=False))
            hostvuln_items.append({"ip": ip, "vulns": items})
            if any(x["label"] == "Old version" for x in items):
                hits_total += 1
                outdated_total += 1
            elif items:
                hits_total += 1

        dur = round(time.time() - start, 3)
        with services_json_path.open("w", encoding="utf-8") as f:
            json.dump({"items": services_items, "duration_s": dur, "hosts": len(by_ip), "services": len(services_items)}, f, ensure_ascii=False, separators=(",", ":"), indent=2)
        with hostvuln_json_path.open("w", encoding="utf-8") as f:
            json.dump({"items": hostvuln_items, "duration_s": dur}, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("INFO", self.name, "done", {"hosts": len(by_ip), "services_out": str(services_json_path), "hostvuln_out": str(hostvuln_json_path)})

        return True, False, "ok", {"ips": len(by_ip), "ports": total_ports, "findings": hits_total, "outdated_ports": outdated_total, "services_out": str(services_json_path), "hostvuln_out": str(hostvuln_json_path)}
