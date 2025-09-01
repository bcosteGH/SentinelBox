import json
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module

def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

def _is_https(row: dict) -> bool:
    tun = str(row.get("tunnel") or "").lower()
    extra = str(row.get("extrainfo") or "").lower()
    svc = str(row.get("service_name") or "").lower()
    return ("ssl" in tun) or ("tls" in tun) or ("https" in svc) or ("https" in extra)

def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s or "")

def _build_url(host: str, port: int, https: bool) -> str:
    proto = "https" if https else "http"
    return f"{proto}://{host}:{port}/"

def _find_cmseek_script(audit_dir: Path, explicit_path: Optional[str]) -> Optional[Path]:
    if explicit_path:
        p = Path(explicit_path)
        if not p.is_absolute():
            p = (audit_dir.parent.parent / explicit_path).resolve()
        return p if p.exists() else None
    root = audit_dir.parent.parent
    p1 = root / "outils" / "cmseek" / "cmseek.py"
    return p1 if p1.exists() else None

def _split_csv_like(s: Optional[str]) -> List[str]:
    if not s:
        return []
    parts = [x.strip() for x in s.split(",")]
    return [x for x in parts if x]

def _parse_wp_pairs(raw: Optional[str]) -> List[Dict[str, Optional[str]]]:
    out: List[Dict[str, Optional[str]]] = []
    for item in _split_csv_like(raw):
        m = re.match(r"^(.*?)[\s]+[Vv]ersion[\s]+([^,\s]+)\s*$", item)
        if m:
            name = _norm(m.group(1))
            ver = _norm(m.group(2))
            if name:
                out.append({"name": name, "version": ver or None})
        else:
            if item:
                out.append({"name": item, "version": None})
    return out

def _parse_wp_users(raw: Optional[str]) -> List[str]:
    return [x for x in _split_csv_like(raw)]

def _extract_version_generic(d: dict) -> Optional[str]:
    for k in ("wp_version", "joomla_version", "drupal_version", "cms_version", "version"):
        v = _norm(d.get(k))
        if v:
            return v
    return None

class CMSeek(Module):
    name = "CMSeek"

    def run(self, context: dict[str, Any]) -> Tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data" / "cms"
        data_dir.mkdir(parents=True, exist_ok=True)

        logs_dir = audit_dir / "logs" / self.name
        stdout_dir = logs_dir / "stdout"
        stderr_dir = logs_dir / "stderr"
        results_dir = logs_dir / "results"
        meta_dir = logs_dir / "meta"
        for d in (logs_dir, stdout_dir, stderr_dir, results_dir, meta_dir):
            d.mkdir(parents=True, exist_ok=True)
        commands_path = logs_dir / "commands.txt"
        events_path = meta_dir / "events.jsonl"

        def _event(ev: Dict[str, Any]) -> None:
            ev2 = dict(ev)
            ev2["ts"] = _now_iso()
            try:
                with events_path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(ev2, ensure_ascii=False) + "\n")
            except Exception:
                pass

        cmcfg = context.get("cmseek") or {}
        script_path = cmcfg.get("script_path")
        timeout_s = int(cmcfg.get("timeout_seconds", 180))
        clear_between = bool(cmcfg.get("clear_between_scans", True))
        follow_redirect = bool(cmcfg.get("follow_redirect", True))
        random_agent = bool(cmcfg.get("random_agent", True))

        cmseek_py = _find_cmseek_script(audit_dir, script_path)
        if cmseek_py is None:
            if callable(log):
                log("ERROR", self.name, "cmseek_not_found", {"hint": "place outils/cmseek/cmseek.py under code/ or set [cmseek].script_path"})
            return False, True, "cmseek_not_found", None

        rows = store.list_services() if store else []
        ip_name_map: Dict[str, Optional[str]] = {}
        try:
            for h in (store.list_hosts() if store else []):
                ip_name_map[h["ip"]] = h.get("hostname")
        except Exception:
            pass

        targets: List[Dict[str, Any]] = []
        for r in rows:
            if str(r.get("state", "")).lower() != "open":
                continue
            svc = str(r.get("service_name") or "").lower()
            if "http" not in svc:
                continue
            ip = r.get("ip")
            proto = str(r.get("proto") or "").lower()
            port = int(r.get("port") or 0)
            if not ip or not port or not proto:
                continue
            host = ip_name_map.get(ip) or ip
            targets.append({"ip": ip, "host": host, "proto": proto, "port": port, "https": _is_https(r)})

        if callable(log):
            log("INFO", self.name, "start", {"targets": len(targets), "script": str(cmseek_py), "logs_dir": str(logs_dir)})

        inv_items: List[Dict[str, Any]] = []
        wp_items: List[Dict[str, Any]] = []
        joom_items: List[Dict[str, Any]] = []

        def _run_clear(timeout_s: int) -> None:
            cmd = ["python3", str(cmseek_py), "--clear-result"]
            try:
                t0 = time.time()
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=max(10, min(timeout_s, 60)))
                dt = round(time.time() - t0, 3)
                try:
                    with commands_path.open("a", encoding="utf-8") as cf:
                        cf.write(" ".join(cmd) + "\n")
                except Exception:
                    pass
                _event({"type": "clear_result", "rc": cp.returncode, "time_s": dt})
                if callable(log):
                    log("DEBUG", self.name, "clear_result_done", {"rc": cp.returncode, "time_s": dt})
            except subprocess.TimeoutExpired:
                _event({"type": "clear_result_timeout"})
                if callable(log):
                    log("WARNING", self.name, "clear_result_timeout", None)
            except Exception as e:
                _event({"type": "clear_result_error", "error": str(e)[:200]})
                if callable(log):
                    log("WARNING", self.name, "clear_result_error", {"error": str(e)[:200]})

        def _find_cms_json() -> Optional[Path]:
            base = cmseek_py.parent / "Result"
            if not base.exists():
                return None
            best = None
            best_m = -1.0
            for d in base.iterdir():
                try:
                    if d.is_dir():
                        p = d / "cms.json"
                        if p.exists():
                            m = p.stat().st_mtime
                            if m > best_m:
                                best_m, best = m, p
                except Exception:
                    pass
            return best

        for t in targets:
            ip = t["ip"]
            host = t["host"]
            proto = t["proto"]
            port = t["port"]
            https = t["https"]
            url = _build_url(host, port, https)
            safe_host = _slug(host)
            scheme = "https" if https else "http"
            run_id = f"{safe_host}_{scheme}-{port}_{int(time.time())}"
            out_path = stdout_dir / f"{run_id}.txt"
            err_path = stderr_dir / f"{run_id}.txt"

            if clear_between:
                _run_clear(timeout_s)

            flags = []
            if follow_redirect:
                flags.append("--follow-redirect")
            if random_agent:
                flags.append("--random-agent")
            cmd = ["python3", str(cmseek_py)] + flags + ["-u", url]

            if callable(log):
                log("DEBUG", self.name, "exec", {"ip": ip, "host": host, "url": url, "cmd": " ".join(cmd), "timeout_s": timeout_s})
            try:
                with commands_path.open("a", encoding="utf-8") as cf:
                    cf.write(" ".join(cmd) + "\n")
            except Exception:
                pass

            _event({"type": "scan_begin", "ip": ip, "host": host, "url": url})
            try:
                t0 = time.time()
                cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
                dt = round(time.time() - t0, 3)
                try:
                    out_path.write_text(cp.stdout or "", encoding="utf-8")
                except Exception:
                    pass
                try:
                    err_path.write_text(cp.stderr or "", encoding="utf-8")
                except Exception:
                    pass
                _event({"type": "scan_finished", "ip": ip, "host": host, "url": url, "rc": cp.returncode, "time_s": dt})
                if cp.returncode != 0:
                    if callable(log):
                        log("WARNING", self.name, "scan_failed", {"ip": ip, "host": host, "url": url, "rc": cp.returncode})
                    continue
            except subprocess.TimeoutExpired:
                _event({"type": "scan_timeout", "ip": ip, "host": host, "url": url})
                if callable(log):
                    log("WARNING", self.name, "scan_timeout", {"ip": ip, "host": host, "url": url})
                continue
            except Exception as e:
                _event({"type": "scan_exception", "ip": ip, "host": host, "url": url, "error": str(e)[:200]})
                if callable(log):
                    log("WARNING", self.name, "scan_exception", {"ip": ip, "host": host, "url": url, "error": str(e)[:200]})
                continue

            cms_path = _find_cms_json()
            if cms_path is None:
                _event({"type": "cms_json_missing", "ip": ip, "host": host, "url": url})
                if callable(log):
                    log("DEBUG", self.name, "cms_json_missing", {"ip": ip, "host": host, "url": url})
                continue

            try:
                raw = cms_path.read_text(encoding="utf-8", errors="ignore")
                data = json.loads(raw)
                _event({"type": "cms_json_parsed", "ip": ip, "host": host})
            except Exception as e:
                _event({"type": "cms_json_parse_error", "ip": ip, "host": host, "error": str(e)[:200]})
                if callable(log):
                    log("WARNING", self.name, "cms_json_parse_error", {"ip": ip, "host": host, "error": str(e)[:200]})
                continue

            try:
                copy_dir = results_dir / safe_host / f"{scheme}-{port}"
                copy_dir.mkdir(parents=True, exist_ok=True)
                (copy_dir / "cms.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
            except Exception:
                pass

            cms_name = _norm(data.get("cms_name") or data.get("cms_id") or "")
            version = _extract_version_generic(data)
            target_url = _norm(data.get("target_url"))
            final_url = _norm(data.get("url"))

            if store:
                store.put_cms_inventory(ip, proto, port, cms_name if cms_name else None, version if version else None)
            inv_items.append({
                "ip": ip,
                "host": host if host != ip else None,
                "proto": proto,
                "port": port,
                "cms_name": cms_name or None,
                "version": version or None,
                "target_url": target_url or None,
                "final_url": final_url or None
            })

            low = (cms_name or "").lower()
            if "wordpress" in low or data.get("cms_id") == "wp":
                users = _parse_wp_users(data.get("wp_users"))
                plugins = _parse_wp_pairs(data.get("wp_plugins"))
                themes = _parse_wp_pairs(data.get("wp_themes"))
                if store:
                    store.put_wp_details(ip, proto, port, users, plugins, themes)
                wp_items.append({
                    "ip": ip,
                    "host": host if host != ip else None,
                    "proto": proto,
                    "port": port,
                    "users": users,
                    "plugins": plugins,
                    "themes": themes
                })
                _event({"type": "wp_details", "ip": ip, "host": host, "users": len(users), "plugins": len(plugins), "themes": len(themes)})

            elif "joomla" in low or data.get("cms_id") in ("joom", "joomla"):
                dbg_raw = _norm(data.get("joomla_debug_mode"))
                dbg = dbg_raw if dbg_raw else None
                if store:
                    store.put_joomla_details(ip, proto, port, dbg)
                joom_items.append({
                    "ip": ip,
                    "host": host if host != ip else None,
                    "proto": proto,
                    "port": port,
                    "debug_mode": dbg
                })
                _event({"type": "joomla_details", "ip": ip, "host": host, "debug_mode": dbg})

        inv_out = data_dir / "cms_inventory.json"
        wp_out = data_dir / "wp_details.json"
        joom_out = data_dir / "joomla_details.json"

        try:
            inv_out.write_text(json.dumps({"items": inv_items}, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
        except Exception:
            pass
        try:
            wp_out.write_text(json.dumps({"items": wp_items}, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
        except Exception:
            pass
        try:
            joom_out.write_text(json.dumps({"items": joom_items}, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
        except Exception:
            pass

        if callable(log):
            log("INFO", self.name, "done", {
                "targets": len(targets),
                "inventory": len(inv_items),
                "wp_details": len(wp_items),
                "joomla_details": len(joom_items),
                "output_dir": str(data_dir),
                "logs_dir": str(logs_dir)
            })

        return True, False, "ok", {"targets": len(targets), "inventory": len(inv_items), "output_dir": str(data_dir)} 
