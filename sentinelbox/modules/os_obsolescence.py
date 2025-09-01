import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from ..module import Module

def now_iso() -> str:
    return datetime.utcnow().isoformat()

def parse_os_xml_strict(xml_text: str) -> dict[str, dict[str, Any]]:
    out = {}
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out
    for host in root.findall("host"):
        ip = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr")
                break
        if not ip:
            continue
        label = None
        acc = None
        node = host.find("os")
        if node is None:
            out[ip] = {"label": None, "accuracy": None}
            continue
        found = None
        for m in node.findall("osmatch"):
            classes = m.findall("osclass")
            if len(classes) == 1:
                found = m
                break
        if found is not None:
            label = found.get("name")
            try:
                acc = int(found.get("accuracy")) if found.get("accuracy") else None
            except Exception:
                acc = None
        out[ip] = {"label": label, "accuracy": acc}
    return out

class Rule:
    def __init__(self, raw: dict, idx: int):
        self.type = str(raw.get("match_type", "")).lower()
        self.pattern = str(raw.get("match", ""))
        self.comment = raw.get("comment")
        self.severity = raw.get("severity")
        self.last_review = raw.get("last_review")
        self.idx = idx
        self._rx = re.compile(self.pattern, re.IGNORECASE) if self.type == "regex" else None

    def match(self, s: str) -> bool:
        if not s:
            return False
        if self.type == "exact":
            return s == self.pattern
        if self.type == "regex":
            return bool(self._rx.search(s))
        return False

def load_rules(path: Path) -> list[Rule]:
    rules = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue
            rules.append(Rule(obj, i))
    return rules

def apply_rules(rules: list[Rule], label: Optional[str], rules_path: Path) -> Optional[dict[str, Any]]:
    if not label:
        return None
    for r in rules:
        if r.match(label):
            return {
                "severity": r.severity,
                "comment": r.comment,
                "matched": r.type,
                "target": label,
                "pattern": r.pattern,
                "source": str(rules_path),
                "rule_index": r.idx,
                "last_review": r.last_review
            }
    return None

def _normalize_label(s: str) -> str:
    t = s.strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"(?i)\bversion\b", "", t).strip()
    t = re.sub(r"(?i)\bbuild\b\s*\d+(\.\d+)*", "", t).strip()
    t = t.replace("–", "-").replace("—", "-")
    return t

def _slug(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in s)

class OSObsolescence(Module):
    name = "OSObsolescence"

    def run(self, context: dict[str, Any]) -> tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        cfg = context.get("os_obsolescence") or {}
        timing = str(cfg.get("nmap_timing", "T3"))
        host_timeout = int(cfg.get("host_timeout_seconds", 45))
        batch_size = max(1, int(cfg.get("batch_size", 16)))
        max_retries = int(cfg.get("max_retries", 1))
        overall_timeout = int(cfg.get("overall_timeout_seconds", 240))
        oscan_guess = bool(cfg.get("oscan_guess", True))
        oscan_limit = bool(cfg.get("oscan_limit", False))
        use_pn = bool(cfg.get("use_pn", True))
        rules_path = Path(str(cfg.get("rules_path", "data/nmap_os_comments.jsonl")))
        enable_fallback = bool(cfg.get("enable_rules_fallback", True))
        strict_unambiguous_only = bool(cfg.get("strict_unambiguous_only", True))

        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        logs_dir = audit_dir / "logs" / self.name
        xml_dir = logs_dir / "xml"
        batches_dir = logs_dir / "batches"
        errors_dir = logs_dir / "errors"
        hosts_dir = logs_dir / "hosts"
        for d in (data_dir, logs_dir, xml_dir, batches_dir, errors_dir, hosts_dir):
            d.mkdir(parents=True, exist_ok=True)

        if callable(log):
            log("INFO", self.name, "start", {"rules": rules_path.exists(), "rules_path": str(rules_path), "logs_dir": str(logs_dir)})

        rules = load_rules(rules_path) if rules_path.exists() else []
        ip_name_map: dict[str, Optional[str]] = {}
        try:
            for h in (store.list_hosts() if store else []):
                ip_name_map[h["ip"]] = h.get("hostname")
        except Exception:
            pass

        hosts = store.list_hosts() if store else []
        ips = [h["ip"] for h in hosts]
        if not ips:
            if callable(log):
                log("WARNING", self.name, "no_hosts", None)
            return True, False, "ok", {"count": 0, "logs_dir": str(logs_dir)}

        def build_args(extra: list[str]) -> list[str]:
            args = ["-O", f"-{timing}", "--max-os-tries", "1", "--host-timeout", f"{host_timeout}s", "--max-retries", str(max_retries)]
            if oscan_guess:
                args.append("--osscan-guess")
            if oscan_limit:
                args.append("--osscan-limit")
            if use_pn:
                args.append("-Pn")
            return args + extra

        def run_nmap(batch: list[str], batch_index: int, timeout_s: float) -> Optional[str]:
            out_xml = batches_dir / f"batch_{batch_index:04d}.xml"
            cmd = ["nmap"] + build_args([]) + ["-oX", str(out_xml)] + batch
            if callable(log):
                log("DEBUG", self.name, "exec", {"cmd": " ".join(cmd), "timeout": timeout_s, "ips": len(batch), "batch": batch_index})
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout_s))
            except subprocess.TimeoutExpired:
                if callable(log):
                    log("WARNING", self.name, "nmap_timeout", {"ips": len(batch), "batch": batch_index})
                return None
            if p.returncode != 0 and not out_xml.exists():
                if callable(log):
                    log("WARNING", self.name, "nmap_nonzero", {"code": p.returncode, "batch": batch_index, "stderr": (p.stderr or "")[:300]})
                try:
                    (errors_dir / f"batch_{batch_index:04d}.stderr.txt").write_text(p.stderr or "", encoding="utf-8")
                except Exception:
                    pass
                return None
            try:
                return out_xml.read_text(encoding="utf-8")
            except Exception:
                return None

        start = time.time()
        deadline = start + overall_timeout
        def remaining() -> float:
            return max(0.0, deadline - time.time())

        results: dict[str, dict[str, Any]] = {}
        i = 0
        batch_idx = 0
        while i < len(ips) and remaining() > 0:
            batch = ips[i:i+batch_size]
            xml = run_nmap(batch, batch_idx, min(remaining(), host_timeout * len(batch) + 5))
            if xml:
                parsed = parse_os_xml_strict(xml)
                for k, v in parsed.items():
                    results[k] = v
                if callable(log):
                    log("DEBUG", self.name, "batch_done", {"batch": batch_idx, "ips": len(batch), "parsed": len(parsed)})
            else:
                if callable(log):
                    log("DEBUG", self.name, "batch_empty", {"batch": batch_idx, "ips": len(batch)})
            i += len(batch)
            batch_idx += 1

        out_items = []
        for ip in ips:
            r = results.get(ip, {})
            label = r.get("label")
            acc = r.get("accuracy")
            obs = None
            obso = None
            if label:
                obso = apply_rules(rules, label, rules_path)
                if obso is None and enable_fallback and strict_unambiguous_only:
                    obso = None
                if obso is None and enable_fallback and not strict_unambiguous_only:
                    obso = apply_rules(rules, _normalize_label(label), rules_path)
                if obso is not None:
                    sev = str(obso.get("severity") or "").lower().strip()
                    obs = True if sev == "obsolete" else False
            if store:
                store.put_os_info(ip, label, acc, obs, obso)
            item = {
                "ip": ip,
                "name": ip_name_map.get(ip) or None,
                "label": label,
                "confidence": acc,
                "obsolete": obs,
                "obsolescence": obso
            }
            out_items.append(item)
            try:
                (hosts_dir / f"{_slug(ip)}.json").write_text(json.dumps(item, ensure_ascii=False, separators=(",", ":"), indent=2), encoding="utf-8")
            except Exception:
                pass

        out_path = data_dir / "os_inventory.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"items": out_items, "duration_s": round(time.time() - start, 3), "timed_out": remaining() <= 0}, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("INFO", self.name, "done", {"count": len(out_items), "output": str(out_path), "logs_dir": str(logs_dir)})
        return True, False, "ok", {"count": len(out_items), "output": str(out_path), "logs_dir": str(logs_dir)}
