from __future__ import annotations
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module

RX_INT_0_100 = re.compile(r"\b(\d{1,3})\b")

def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

def _lower(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)

def _find_testssl(audit_dir: Path, explicit: Optional[str]) -> Optional[Path]:
    if explicit:
        p = Path(explicit)
        if not p.is_absolute():
            p = (audit_dir.parent.parent / p).resolve()
        return p if p.exists() else None
    p = audit_dir.parent.parent / "outils" / "testssl.sh" / "testssl.sh"
    return p if p.exists() else None

def _build_target(host_for_sni: str, port: int) -> str:
    return f"{host_for_sni}:{int(port)}"

def _eligible(row: dict, enabled_services: set[str]) -> bool:
    if _lower(row.get("state")) != "open":
        return False
    if _lower(row.get("proto")) != "tcp":
        return False
    name = _lower(row.get("service_name"))
    tun = _lower(row.get("tunnel"))
    extra = _lower(row.get("extrainfo"))
    if "ssl" in tun or "tls" in tun:
        return True
    if name in enabled_services:
        return True
    if "https" in name or "https" in extra:
        return True
    return False

def _read_json_lines(path: Path) -> List[dict]:
    items: List[dict] = []
    if not path.exists():
        return items
    txt = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not txt:
        return items
    if txt.startswith("["):
        try:
            arr = json.loads(txt)
            if isinstance(arr, list):
                for x in arr:
                    if isinstance(x, dict):
                        items.append(x)
        except Exception:
            pass
        return items
    for line in txt.splitlines():
        t = line.strip()
        if not t:
            continue
        try:
            obj = json.loads(t)
            if isinstance(obj, dict):
                items.append(obj)
        except Exception:
            continue
    return items

def _match_id(i: str, target: str) -> bool:
    a = _lower(i).replace("-", "_").replace(" ", "_")
    b = _lower(target).replace("-", "_").replace(" ", "_")
    return a == b

def _parse_score(find_val: Optional[str]) -> Optional[int]:
    if find_val is None:
        return None
    m = RX_INT_0_100.search(str(find_val))
    if not m:
        return None
    try:
        v = int(m.group(1))
    except Exception:
        return None
    if v < 0:
        v = 0
    if v > 100:
        v = 100
    return v

def _extract_scores(json_items: List[dict]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    ps = None
    ke = None
    cs = None
    for it in json_items:
        fid = it.get("id")
        if not fid:
            continue
        fnd = it.get("finding")
        if ps is None and _match_id(fid, "protocol_support_score"):
            ps = _parse_score(fnd)
        elif ke is None and _match_id(fid, "key_exchange_score"):
            ke = _parse_score(fnd)
        elif cs is None and _match_id(fid, "cipher_strength_score"):
            cs = _parse_score(fnd)
        if ps is not None and ke is not None and cs is not None:
            break
    return ps, ke, cs

class TLSScanTestssl(Module):
    name = "TLSScanTestssl"

    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        audit_dir = Path(context.get("audit_dir"))

        cfg = context.get("tls_scan") or {}
        script_path = str(cfg.get("script_path") or "outils/testssl.sh/testssl.sh")
        timeout_seconds = int(cfg.get("timeout_seconds", 60))
        prefer_hostname = bool(cfg.get("prefer_hostname", True))
        enabled_services = set([_lower(x) for x in (cfg.get("enabled_services") or ["https","ftps","imaps","pop3s","smtps","ldaps","ircs","nntps","xmpps"])])
        connect_timeout = int(cfg.get("connect_timeout", 2))
        openssl_timeout = int(cfg.get("openssl_timeout", 2))

        testssl = _find_testssl(audit_dir, script_path)
        if testssl is None:
            if callable(log):
                log("ERROR", self.name, "testssl_not_found", {"hint": "place outils/testssl.sh/testssl.sh under code/ or set [tls_scan].script_path"})
            return False, True, "testssl_not_found", None

        data_dir = audit_dir / "data" / "tls"
        data_dir.mkdir(parents=True, exist_ok=True)
        logs_dir = audit_dir / "logs" / self.name
        logs_dir.mkdir(parents=True, exist_ok=True)
        cmd_log = logs_dir / "commands.txt"

        rows = store.list_services() if store else []
        hosts = store.list_hosts() if store else []
        host_by_ip = {h["ip"]: (h.get("hostname") or "").strip() for h in hosts}

        targets: List[Dict[str, Any]] = []
        seen: set[Tuple[str,int]] = set()
        for r in rows:
            if not _eligible(r, enabled_services):
                continue
            ip = r.get("ip")
            try:
                port = int(r.get("port") or 0)
            except Exception:
                continue
            if not ip or not port:
                continue
            name = host_by_ip.get(ip) or None
            host_for_sni = name if (prefer_hostname and name) else ip
            key = (host_for_sni, port)
            if key in seen:
                continue
            seen.add(key)
            targets.append({
                "ip": ip,
                "name": name,
                "proto": "tcp",
                "port": port,
                "service_name": r.get("service_name"),
                "host_for_sni": host_for_sni
            })

        if callable(log):
            log("INFO", self.name, "start", {"targets": len(targets), "script": str(testssl), "timeout_s": timeout_seconds})

        items: List[Dict[str, Any]] = []
        scored = 0

        for t in targets:
            ip = t["ip"]
            name = t["name"]
            port = t["port"]
            host_for_sni = t["host_for_sni"]
            uri = _build_target(host_for_sni, port)
            slug = f"{_slug(host_for_sni)}_{port}"
            html_path = data_dir / f"{slug}.html"
            json_path = data_dir / f"{slug}.json"
            out_path = logs_dir / f"{slug}.out"
            err_path = logs_dir / f"{slug}.err"

            cmd = [
                "bash", str(testssl),
                "--quiet", "--warnings", "off", "--append",
                "--connect-timeout", str(connect_timeout),
                "--openssl-timeout", str(openssl_timeout),
                "--jsonfile", str(json_path),
                "--htmlfile", str(html_path),
                uri
            ]

            if callable(log):
                log("DEBUG", self.name, "exec", {"ip": ip, "name": name, "port": port, "uri": uri, "cmd": " ".join(cmd)})

            try:
                with cmd_log.open("a", encoding="utf-8") as cf:
                    cf.write(" ".join(cmd) + "\n")
            except Exception:
                pass

            started = time.time()
            rc = None
            stdout_txt = ""
            stderr_txt = ""
            try:
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=max(5, timeout_seconds))
                rc = cp.returncode
                stdout_txt = cp.stdout or ""
                stderr_txt = cp.stderr or ""
                try:
                    out_path.write_text(stdout_txt, encoding="utf-8")
                    err_path.write_text(stderr_txt, encoding="utf-8")
                except Exception:
                    pass
            except subprocess.TimeoutExpired:
                if callable(log):
                    log("WARNING", self.name, "timeout", {"ip": ip, "name": name, "port": port, "uri": uri, "timeout_s": timeout_seconds})
                rc = None

            dt = round(time.time() - started, 3)
            if callable(log):
                log("DEBUG", self.name, "run_done", {"ip": ip, "name": name, "port": port, "rc": rc, "time_s": dt, "html": str(html_path), "json": str(json_path)})

            json_items = _read_json_lines(json_path) if json_path.exists() else []
            ps, ke, cs = _extract_scores(json_items)

            if callable(log):
                log("DEBUG", self.name, "scores_parsed", {"ip": ip, "name": name, "port": port, "protocol_support": ps, "key_exchange": ke, "cipher_strength": cs})

            try:
                if hasattr(store, "put_tls_result"):
                    store.put_tls_result(
                        ip=ip,
                        proto="tcp",
                        port=port,
                        service_name=t.get("service_name"),
                        hostname=name,
                        uri=uri,
                        html_path=str(html_path),
                        score_protocol_support=ps,
                        score_key_exchange=ke,
                        score_cipher_strength=cs
                    )
            except Exception:
                pass

            items.append({
                "ip": ip,
                "name": name,
                "proto": "tcp",
                "port": port,
                "service_name": t.get("service_name"),
                "uri": uri,
                "html_path": str(html_path),
                "protocol_support_score": ps,
                "key_exchange_score": ke,
                "cipher_strength_score": cs
            })

            if ps is not None or ke is not None or cs is not None:
                scored += 1

        summary_path = data_dir / "summary.json"
        try:
            summary_path.write_text(json.dumps({"items": items, "count": len(items)}, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
        except Exception:
            pass

        if callable(log):
            log("INFO", self.name, "done", {"targets": len(targets), "scored": scored, "summary": str(summary_path), "data_dir": str(data_dir)})

        return True, False, "ok", {"targets": len(targets), "scored": scored, "summary": str(summary_path)}
