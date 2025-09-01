import json
import time
import telnetlib
import ftplib
from ftplib import FTP, FTP_TLS
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module
import warnings

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        import paramiko
    except Exception:
        paramiko = None

try:
    from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
except Exception:
    SnmpEngine = None

ALLOWED_SERVICES = {"ssh", "ftp", "telnet", "snmp", "ftps"}

def load_pairs(path: Path) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#") or ":" not in t:
                continue
            u, pw = t.split(":", 1)
            out.append((u.strip(), pw.strip()))
    return out

def load_list(path: Path) -> List[str]:
    out: List[str] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            out.append(t)
    return out

def try_ssh(ip: str, port: int, user: str, password: str, timeout: float) -> Tuple[bool, str]:
    if paramiko is None:
        return False, "Paramiko indisponible"
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(ip, port=port, username=user, password=password, look_for_keys=False, allow_agent=False, timeout=timeout, auth_timeout=timeout, banner_timeout=timeout)
        stdin, stdout, stderr = c.exec_command("true", timeout=timeout)
        _ = stdout.read()
        return True, "Authentification SSH réussie"
    except Exception as e:
        return False, str(e)[:120]
    finally:
        try:
            c.close()
        except Exception:
            pass

def try_ftp(ip: str, port: int, user: str, password: str, timeout: float, tls: bool) -> Tuple[bool, str]:
    cls = FTP_TLS if tls else FTP
    try:
        ftp = cls()
        ftp.connect(ip, port, timeout=timeout)
        if tls:
            try:
                ftp.auth()
            except Exception:
                pass
        ftp.login(user, password)
        if tls:
            try:
                ftp.prot_p()
            except Exception:
                pass
        try:
            ftp.voidcmd("NOOP")
        except Exception:
            pass
        ftp.quit()
        return True, ("Authentification FTPS réussie" if tls else "Authentification FTP réussie")
    except Exception as e:
        return False, str(e)[:120]

def try_telnet(ip: str, port: int, user: str, password: str, timeout: float) -> Tuple[bool, str]:
    try:
        tn = telnetlib.Telnet(ip, port, timeout=timeout)
        prompts = [b"login:", b"username:", b"Login:", b"Username:"]
        got = False
        for p in prompts:
            try:
                tn.read_until(p, timeout=timeout)
                got = True
                break
            except Exception:
                continue
        if not got:
            tn.close()
            return False, "Aucun prompt de login"
        tn.write(user.encode("utf-8") + b"\n")
        try:
            tn.read_until(b"Password:", timeout=timeout)
        except Exception:
            tn.close()
            return False, "Aucun prompt de mot de passe"
        tn.write(password.encode("utf-8") + b"\n")
        time.sleep(0.5)
        data = tn.read_very_eager()
        txt = data.decode("utf-8", errors="ignore").lower()
        if "incorrect" in txt or "failed" in txt or "invalid" in txt:
            tn.close()
            return False, "Échec d'authentification telnet"
        if any(x in txt for x in ["last login", "#", "$", ">"]):
            tn.close()
            return True, "Authentification Telnet réussie"
        tn.close()
        return False, "Réponse incertaine"
    except Exception as e:
        return False, str(e)[:120]

def try_snmp(ip: str, port: int, community: str, timeout: float) -> Tuple[bool, str]:
    if SnmpEngine is None:
        return False, "pysnmp indisponible"
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),
            UdpTransportTarget((ip, port), timeout=max(1, int(timeout)), retries=0),
            ContextData(),
            ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0"))
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if errorIndication or errorStatus:
            return False, "SNMP échec"
        if varBinds:
            return True, "Communauté SNMP acceptée"
        return False, "SNMP vide"
    except Exception as e:
        return False, str(e)[:120]

def _slug(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in s)

class AuthBruteforce(Module):
    name = "AuthBruteforce"

    def run(self, context: dict[str, Any]) -> Tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        cfg = context.get("auth_bruteforce") or {}
        host_timeout = int(cfg.get("host_timeout_seconds", 20))
        per_target_max = int(cfg.get("per_target_max_attempts", 6))
        delay_ms = int(cfg.get("delay_ms", 200))
        allow_ssh = bool(cfg.get("enable_ssh", True))
        allow_ftp = bool(cfg.get("enable_ftp", True))
        allow_telnet = bool(cfg.get("enable_telnet", True))
        allow_snmp = bool(cfg.get("enable_snmp", True))

        if callable(log):
            log("DEBUG", self.name, "config_loaded", {
                "host_timeout": host_timeout,
                "per_target_max": per_target_max,
                "delay_ms": delay_ms,
                "enable": {"ssh": allow_ssh, "ftp": allow_ftp, "telnet": allow_telnet, "snmp": allow_snmp},
                "libs": {"paramiko": bool(paramiko), "pysnmp": bool(SnmpEngine)}
            })

        if allow_ssh and paramiko is None and callable(log):
            log("WARNING", self.name, "ssh_disabled_paramiko_missing", None)
            allow_ssh = False
        if allow_snmp and SnmpEngine is None and callable(log):
            log("WARNING", self.name, "snmp_disabled_pysnmp_missing", None)
            allow_snmp = False

        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        logs_dir = audit_dir / "logs" / self.name
        targets_dir = logs_dir / "targets"
        errors_dir = logs_dir / "errors"
        logs_dir.mkdir(parents=True, exist_ok=True)
        targets_dir.mkdir(parents=True, exist_ok=True)
        errors_dir.mkdir(parents=True, exist_ok=True)

        base_data = Path(context.get("audit_dir")).parent.parent / "data"
        wl_dir = base_data / "wordlists"
        ssh_pairs = load_pairs(wl_dir / "ssh.txt")
        ftp_pairs = load_pairs(wl_dir / "ftp.txt")
        telnet_pairs = load_pairs(wl_dir / "telnet.txt")
        snmp_comm = load_list(wl_dir / "snmp.txt")

        if callable(log):
            log("DEBUG", self.name, "wordlists_loaded", {
                "dir": str(wl_dir),
                "exists": wl_dir.exists(),
                "ssh_pairs": len(ssh_pairs),
                "ftp_pairs": len(ftp_pairs),
                "telnet_pairs": len(telnet_pairs),
                "snmp_comm": len(snmp_comm)
            })

        ip_name_map: Dict[str, Optional[str]] = {}
        try:
            for h in (store.list_hosts() if store else []):
                ip_name_map[h["ip"]] = h.get("hostname")
        except Exception:
            pass

        rows = store.list_services() if store else []
        if callable(log):
            log("DEBUG", self.name, "services_seen", {
                "count": len(rows),
                "sample": [
                    {
                        "ip": r.get("ip"),
                        "name": ip_name_map.get(r.get("ip")) or None,
                        "proto": r.get("proto"),
                        "port": r.get("port"),
                        "state": r.get("state"),
                        "service_name": r.get("service_name"),
                        "tunnel": r.get("tunnel"),
                        "extrainfo": r.get("extrainfo")
                    } for r in rows[:10]
                ]
            })

        targets: List[Dict[str, Any]] = []
        for r in rows:
            if str(r.get("state", "")).lower() != "open":
                continue
            svc = (r.get("service_name") or "").lower()
            proto = (r.get("proto") or "").lower()
            port = int(r.get("port") or 0)
            ip = r.get("ip")
            tls = str(r.get("tunnel") or "").lower() == "ssl" or "tls" in str(r.get("extrainfo") or "").lower()
            if not ip or not port or not proto:
                continue
            display = ip_name_map.get(ip) or ip

            if svc == "ssh":
                if allow_ssh:
                    targets.append({"ip": ip, "name": display if display != ip else None, "proto": proto, "port": port, "service": "ssh"})
                elif callable(log):
                    log("DEBUG", self.name, "skip_service_disabled", {"ip": ip, "name": display if display != ip else None, "service": "ssh"})
            elif svc == "ftp" and not tls:
                if allow_ftp:
                    targets.append({"ip": ip, "name": display if display != ip else None, "proto": proto, "port": port, "service": "ftp"})
                elif callable(log):
                    log("DEBUG", self.name, "skip_service_disabled", {"ip": ip, "name": display if display != ip else None, "service": "ftp"})
            elif svc == "ftp" and tls:
                if allow_ftp:
                    targets.append({"ip": ip, "name": display if display != ip else None, "proto": proto, "port": port, "service": "ftps"})
                elif callable(log):
                    log("DEBUG", self.name, "skip_service_disabled", {"ip": ip, "name": display if display != ip else None, "service": "ftps"})
            elif svc == "telnet":
                if allow_telnet:
                    targets.append({"ip": ip, "name": display if display != ip else None, "proto": proto, "port": port, "service": "telnet"})
                elif callable(log):
                    log("DEBUG", self.name, "skip_service_disabled", {"ip": ip, "name": display if display != ip else None, "service": "telnet"})
            elif svc == "snmp":
                if allow_snmp:
                    targets.append({"ip": ip, "name": display if display != ip else None, "proto": proto, "port": port, "service": "snmp"})
                elif callable(log):
                    log("DEBUG", self.name, "skip_service_disabled", {"ip": ip, "name": display if display != ip else None, "service": "snmp"})

        if callable(log):
            log("INFO", self.name, "start", {"targets": len(targets), "targets_sample": targets[:10], "logs_dir": str(logs_dir)})

        findings: List[Dict[str, Any]] = []
        total_attempts = 0

        for t in targets:
            ip = t["ip"]
            port = t["port"]
            svc = t["service"]
            display = t.get("name") or None
            attempts_here = 0
            success = False
            attempts_log: List[Dict[str, Any]] = []

            if svc == "ssh":
                if not ssh_pairs:
                    if callable(log):
                        log("DEBUG", self.name, "skip_no_wordlist", {"ip": ip, "name": display, "service": "ssh", "file": str((wl_dir / "ssh.txt"))})
                else:
                    for idx, (u, pw) in enumerate(ssh_pairs, start=1):
                        if attempts_here >= per_target_max:
                            break
                        if callable(log):
                            log("DEBUG", self.name, "attempt", {"ip": ip, "name": display, "service": "ssh", "user": u, "attempt_no": idx})
                        ok, note = try_ssh(ip, port, u, pw, host_timeout)
                        total_attempts += 1
                        attempts_here += 1
                        attempts_log.append({"no": idx, "user": u, "result": bool(ok), "note": note})
                        if ok:
                            store.put_auth_finding(ip, t["proto"], port, "ssh", u, pw, "SSH", True, "Authentification triviale")
                            findings.append({
                                "ip": ip, "proto": t["proto"], "port": port, "service": "ssh",
                                "username": u, "password": pw, "method": "SSH", "verified": True,
                                "note": "Authentification triviale", "name": display
                            })
                            success = True
                            break
                        time.sleep(delay_ms / 1000.0)

            elif svc in ("ftp", "ftps"):
                if not ftp_pairs:
                    if callable(log):
                        log("DEBUG", self.name, "skip_no_wordlist", {"ip": ip, "name": display, "service": svc, "file": str((wl_dir / "ftp.txt"))})
                else:
                    tls = svc == "ftps"
                    for idx, (u, pw) in enumerate(ftp_pairs, start=1):
                        if attempts_here >= per_target_max:
                            break
                        if callable(log):
                            log("DEBUG", self.name, "attempt", {"ip": ip, "name": display, "service": svc, "user": u, "attempt_no": idx})
                        ok, note = try_ftp(ip, port, u, pw, host_timeout, tls)
                        total_attempts += 1
                        attempts_here += 1
                        attempts_log.append({"no": idx, "user": u, "result": bool(ok), "note": note})
                        if ok:
                            lab = "FTPS" if tls else "FTP"
                            store.put_auth_finding(ip, t["proto"], port, svc, u, pw, lab, True, "Authentification triviale")
                            findings.append({
                                "ip": ip, "proto": t["proto"], "port": port, "service": svc,
                                "username": u, "password": pw, "method": lab, "verified": True,
                                "note": "Authentification triviale", "name": display
                            })
                            success = True
                            break
                        time.sleep(delay_ms / 1000.0)

            elif svc == "telnet":
                if not telnet_pairs:
                    if callable(log):
                        log("DEBUG", self.name, "skip_no_wordlist", {"ip": ip, "name": display, "service": "telnet", "file": str((wl_dir / "telnet.txt"))})
                else:
                    for idx, (u, pw) in enumerate(telnet_pairs, start=1):
                        if attempts_here >= per_target_max:
                            break
                        if callable(log):
                            log("DEBUG", self.name, "attempt", {"ip": ip, "name": display, "service": "telnet", "user": u, "attempt_no": idx})
                        ok, note = try_telnet(ip, port, u, pw, host_timeout)
                        total_attempts += 1
                        attempts_here += 1
                        attempts_log.append({"no": idx, "user": u, "result": bool(ok), "note": note})
                        if ok:
                            store.put_auth_finding(ip, t["proto"], port, "telnet", u, pw, "Telnet", True, "Authentification triviale")
                            findings.append({
                                "ip": ip, "proto": t["proto"], "port": port, "service": "telnet",
                                "username": u, "password": pw, "method": "Telnet", "verified": True,
                                "note": "Authentification triviale", "name": display
                            })
                            success = True
                            break
                        time.sleep(delay_ms / 1000.0)

            elif svc == "snmp":
                if not snmp_comm:
                    if callable(log):
                        log("DEBUG", self.name, "skip_no_wordlist", {"ip": ip, "name": display, "service": "snmp", "file": str((wl_dir / "snmp.txt"))})
                else:
                    for idx, comm in enumerate(snmp_comm, start=1):
                        if attempts_here >= per_target_max:
                            break
                        if callable(log):
                            log("DEBUG", self.name, "attempt", {"ip": ip, "name": display, "service": "snmp", "community": comm, "attempt_no": idx})
                        ok, note = try_snmp(ip, port, comm, host_timeout)
                        total_attempts += 1
                        attempts_here += 1
                        attempts_log.append({"no": idx, "community": comm, "result": bool(ok), "note": note})
                        if ok:
                            store.put_auth_finding(ip, t["proto"], port, "snmp", comm, None, "SNMPv2c", True, "Communauté SNMP par défaut acceptée")
                            findings.append({
                                "ip": ip, "proto": t["proto"], "port": port, "service": "snmp",
                                "community": comm, "method": "SNMPv2c", "verified": True,
                                "note": "Communauté SNMP par défaut acceptée", "name": display
                            })
                            success = True
                            break
                        time.sleep(delay_ms / 1000.0)

            if callable(log):
                log("DEBUG", self.name, "target_done", {"ip": ip, "name": display, "service": svc, "attempts": attempts_here, "success": success})

            try:
                tgt_slug = f"{_slug(ip)}_{t['proto']}_{t['port']}_{svc}"
                (targets_dir / f"{tgt_slug}.json").write_text(json.dumps({
                    "ip": ip,
                    "name": display,
                    "proto": t["proto"],
                    "port": t["port"],
                    "service": svc,
                    "attempts": attempts_log,
                    "success": success
                }, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
            except Exception as e:
                try:
                    (errors_dir / f"{_slug(ip)}.log").write_text(str(e)[:500], encoding="utf-8")
                except Exception:
                    pass

        out_path = data_dir / "weak_auth.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"items": findings, "attempts": total_attempts}, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("INFO", self.name, "done", {"targets": len(targets), "successes": len(findings), "attempts": total_attempts, "output": str(out_path), "logs_dir": str(logs_dir)})

        return True, False, "ok", {"targets": len(targets), "successes": len(findings), "attempts": total_attempts, "logs_dir": str(logs_dir)}
