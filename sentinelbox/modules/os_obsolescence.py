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

        if callable(log):
            log("INFO", self.name, "start", {"rules": rules_path.exists(), "rules_path": str(rules_path)})

        rules = load_rules(rules_path) if rules_path.exists() else []
        hosts = store.list_hosts() if store else []
        ips = [h["ip"] for h in hosts]
        if not ips:
            if callable(log):
                log("WARNING", self.name, "no_hosts", None)
            return True, False, "ok", {"count": 0}

        def build_args(extra: list[str]) -> list[str]:
            args = ["-O", f"-{timing}", "--max-os-tries", "1", "--host-timeout", f"{host_timeout}s", "--max-retries", str(max_retries)]
            if oscan_guess:
                args.append("--osscan-guess")
            if oscan_limit:
                args.append("--osscan-limit")
            if use_pn:
                args.append("-Pn")
            return args + extra + ["-oX", "-"]

        def run_nmap(batch: list[str], timeout_s: float) -> Optional[str]:
            cmd = ["nmap"] + build_args([]) + batch
            if callable(log):
                log("DEBUG", self.name, "exec", {"cmd": " ".join(cmd), "timeout": timeout_s, "ips": len(batch)})
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout_s))
            except subprocess.TimeoutExpired:
                if callable(log):
                    log("WARNING", self.name, "nmap_timeout", {"ips": len(batch)})
                return None
            if p.returncode != 0 and not p.stdout:
                if callable(log):
                    log("WARNING", self.name, "nmap_nonzero", {"code": p.returncode})
                return None
            return p.stdout

        start = time.time()
        deadline = start + overall_timeout
        def remaining() -> float:
            return max(0.0, deadline - time.time())

        results: dict[str, dict[str, Any]] = {}
        i = 0
        while i < len(ips) and remaining() > 0:
            batch = ips[i:i+batch_size]
            xml = run_nmap(batch, min(remaining(), host_timeout * len(batch) + 5))
            if xml:
                parsed = parse_os_xml_strict(xml)
                for k, v in parsed.items():
                    results[k] = v
            i += len(batch)

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
            out_items.append({
                "ip": ip,
                "label": label,
                "confidence": acc,
                "obsolete": obs,
                "obsolescence": obso
            })

        audit_dir = Path(context.get("audit_dir"))
        out_path = audit_dir / "data" / "os_inventory.json"
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"items": out_items, "duration_s": round(time.time() - start, 3), "timed_out": remaining() <= 0}, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("INFO", self.name, "done", {"count": len(out_items), "output": str(out_path)})
        return True, False, "ok", {"count": len(out_items), "output": str(out_path)}

def _normalize_label(s: str) -> str:
    t = s.strip()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"(?i)\bversion\b", "", t).strip()
    t = re.sub(r"(?i)\bbuild\b\s*\d+(\.\d+)*", "", t).strip()
    t = t.replace("–", "-").replace("—", "-")
    return t
