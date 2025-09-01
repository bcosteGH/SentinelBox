from __future__ import annotations
import json
import time
import base64
import re
import subprocess
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module

def _norm(s: Optional[str]) -> str:
    return (s or "").strip()

def _lower(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _idna(s: str) -> str:
    try:
        return s.encode("idna").decode("ascii")
    except Exception:
        return s

def _now() -> float:
    return time.time()

def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)

DEFAULT_PROBLEMS = {
  "mx_none": {"category":"MX","label":"Aucun enregistrement MX pour le domaine","penalty":20},
  "mx_single": {"category":"MX","label":"Un seul serveur MX (pas de redondance)","penalty":5},
  "mx_cname": {"category":"MX","label":"MX pointe vers un CNAME (non conforme)","penalty":3},
  "mx_private_ip": {"category":"MX","label":"Cible MX résout vers une adresse privée","penalty":10},
  "spf_missing": {"category":"SPF","label":"Aucun enregistrement SPF","penalty":25},
  "spf_multiple": {"category":"SPF","label":"Plusieurs enregistrements SPF","penalty":10},
  "spf_syntax": {"category":"SPF","label":"Erreur de syntaxe SPF","penalty":10},
  "spf_lookup_over": {"category":"SPF","label":"Trop de recherches DNS SPF (>10)","penalty":10},
  "spf_ptr": {"category":"SPF","label":"Mécanisme SPF ptr utilisé","penalty":5},
  "spf_no_all": {"category":"SPF","label":"Aucun mécanisme all final dans SPF","penalty":8},
  "spf_all_softfail": {"category":"SPF","label":"SPF termine par ~all (politique permissive)","penalty":5},
  "spf_all_neutral": {"category":"SPF","label":"SPF termine par ?all (politique neutre)","penalty":8},
  "spf_all_pass": {"category":"SPF","label":"SPF termine par +all (tout autorisé)","penalty":15},
  "dkim_not_found": {"category":"DKIM","label":"Aucun enregistrement DKIM détecté","penalty":5},
  "dkim_weak_key": {"category":"DKIM","label":"Clé DKIM faible (< 2048 bits)","penalty":2},
  "dkim_invalid": {"category":"DKIM","label":"Enregistrement DKIM invalide ou sans clé publique","penalty":3},
  "dmarc_missing": {"category":"DMARC","label":"Aucun enregistrement DMARC","penalty":30},
  "dmarc_syntax": {"category":"DMARC","label":"Erreur de syntaxe DMARC","penalty":20},
  "dmarc_policy_none": {"category":"DMARC","label":"Politique DMARC p=none (monitoring uniquement)","penalty":10},
  "dmarc_pct_lt100": {"category":"DMARC","label":"DMARC pct<100% (application partielle)","penalty":3},
  "dmarc_no_rua": {"category":"DMARC","label":"DMARC sans destinataire de rapports agrégés (rua)","penalty":3},
  "dmarc_no_ruf": {"category":"DMARC","label":"DMARC sans destinataire de rapports forensics (ruf)","penalty":2},
  "dmarc_relaxed_align": {"category":"DMARC","label":"Alignement DMARC en mode relaxé (adkim/aspf=r)","penalty":2},
  "dnssec_unsigned": {"category":"DNSSEC","label":"Domaine non signé par DNSSEC","penalty":20},
  "dnssec_nods": {"category":"DNSSEC","label":"DNSKEY présent mais aucun DS au parent","penalty":10},
  "dnssec_indeterminate": {"category":"DNSSEC","label":"État DNSSEC indéterminé","penalty":5}
}

CATEGORY_CAPS = {"MX":20,"SPF":25,"DKIM":5,"DMARC":30,"DNSSEC":20}

class MailDomainAudit(Module):
    name = "MailDomainAudit"

    def run(self, context: Dict[str, Any]) -> Tuple[bool, bool, Optional[str], Optional[Dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")
        cfg = context.get("mail_audit") or {}
        domains = [d for d in (cfg.get("domains") or []) if str(d).strip()]
        patterns_path = str(cfg.get("dkim_selector_patterns_path") or "").strip()
        max_spf_lookups = int(cfg.get("max_spf_lookups", 10))
        dns_timeout = float(cfg.get("dns_timeout_seconds", 3))
        problem_catalog_path = cfg.get("problem_catalog_path")
        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)
        out_path = data_dir / "mail_audit.json"
        self.logs_dir = audit_dir / "logs" / self.name
        self.dns_dir = self.logs_dir / "dns"
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.dns_dir.mkdir(parents=True, exist_ok=True)
        self.commands_path = self.logs_dir / "commands.txt"

        problems = dict(DEFAULT_PROBLEMS)
        if problem_catalog_path:
            try:
                p = Path(problem_catalog_path)
                if not p.is_absolute():
                    p = (audit_dir.parent.parent / p).resolve()
                if p.exists():
                    loaded = json.loads(p.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        problems.update(loaded)
                        if callable(log):
                            log("INFO", self.name, "problem_catalog_loaded", {"path": str(p), "count": len(loaded)})
            except Exception as e:
                if callable(log):
                    log("WARNING", self.name, "problem_catalog_error", {"error": str(e)[:200]})

        catalog_out = data_dir / "mail_audit_problems.json"
        try:
            catalog_out.write_text(json.dumps(problems, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

        pats, pats_path_used = self._load_selector_patterns(patterns_path, audit_dir)
        if callable(log):
            log("INFO", self.name, "start", {"domains": len(domains), "patterns": len(pats), "patterns_path": pats_path_used or None, "dns_timeout_s": dns_timeout, "max_spf_lookups": max_spf_lookups})

        if not domains:
            if callable(log):
                log("WARNING", self.name, "no_domains", None)
            out = {"items": [], "duration_s": 0.0}
            out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
            return True, False, "ok", {"count": 0, "output": str(out_path)}

        items = []
        t0 = _now()
        for raw_domain in domains:
            domain = _idna(_lower(raw_domain))
            selectors = self._expand_selector_patterns(pats, domain)
            if callable(log):
                log("DEBUG", self.name, "domain_begin", {"domain": domain, "selectors": len(selectors)})
            rec = self._audit_domain(domain, selectors, max_spf_lookups, dns_timeout, problems, log)
            items.append(rec)
            try:
                (self.logs_dir / f"{_slug(domain)}.json").write_text(json.dumps(rec, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            if store:
                self._store_one(store, domain, rec)
            if callable(log):
                log("INFO", self.name, "domain_done", {"domain": domain, "issues": len(rec.get("issues") or []), "scores": rec.get("scores"), "domain_json": str(self.logs_dir / f"{_slug(domain)}.json")})

        duration = round(_now() - t0, 3)
        out = {"items": items, "duration_s": duration}
        try:
            out_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception:
            pass

        if callable(log):
            log("INFO", self.name, "done", {"count": len(items), "output": str(out_path), "duration_s": duration})
        return True, False, "ok", {"count": len(items), "output": str(out_path)}

    def _store_one(self, store, domain: str, rec: Dict[str, Any]) -> None:
        scores = rec.get("scores") or {}
        details = json.dumps(rec, ensure_ascii=False)
        store.put_mail_audit_result(
            domain=domain,
            score_total=int(scores.get("total", 0)),
            score_mx=int(scores.get("MX", 0)),
            score_spf=int(scores.get("SPF", 0)),
            score_dkim=int(scores.get("DKIM", 0)),
            score_dmarc=int(scores.get("DMARC", 0)),
            score_dnssec=int(scores.get("DNSSEC", 0)),
            details_json=details
        )

    def _audit_domain(self, domain: str, selectors: List[str], max_spf_lookups: int, dns_timeout: float, problems: Dict[str, Any], log) -> Dict[str, Any]:
        mx = self._q_mx(domain, dns_timeout, log)
        spf_res = self._eval_spf(domain, dns_timeout, max_spf_lookups, log)
        dmarc_res = self._eval_dmarc(domain, dns_timeout, log)
        dkim_res = self._eval_dkim(domain, selectors, dns_timeout, log)
        dnssec_res = self._eval_dnssec(domain, dns_timeout, log)
        issues: List[Dict[str, Any]] = []
        if not mx["records"]:
            issues.append(self._mk_issue("mx_none", problems))
        if len(mx["records"]) == 1:
            issues.append(self._mk_issue("mx_single", problems))
        for r in mx["records"]:
            if r.get("cname"):
                issues.append(self._mk_issue("mx_cname", problems))
            if r.get("private_ip"):
                issues.append(self._mk_issue("mx_private_ip", problems))
        for pid in spf_res["issues"]:
            issues.append(self._mk_issue(pid, problems))
        for pid in dmarc_res["issues"]:
            issues.append(self._mk_issue(pid, problems))
        for pid in dkim_res["issues"]:
            issues.append(self._mk_issue(pid, problems))
        for pid in dnssec_res["issues"]:
            issues.append(self._mk_issue(pid, problems))
        per_cat = {"MX": [], "SPF": [], "DKIM": [], "DMARC": [], "DNSSEC": []}
        for it in issues:
            c = it["category"]
            if c in per_cat:
                per_cat[c].append(int(it.get("penalty", 0)))
        scores = {}
        total = 0
        for cat, cap in CATEGORY_CAPS.items():
            malus = sum(per_cat.get(cat) or [])
            malus = min(malus, cap)
            score = max(0, cap - malus)
            scores[cat] = score
            total += score
        scores["total"] = total
        return {
            "domain": domain,
            "mx": mx,
            "spf": spf_res,
            "dmarc": dmarc_res,
            "dkim": dkim_res,
            "dnssec": dnssec_res,
            "issues": issues,
            "scores": scores
        }

    def _mk_issue(self, pid: str, problems: Dict[str, Any]) -> Dict[str, Any]:
        p = problems.get(pid) or {}
        return {"id": pid, "category": p.get("category"), "label": p.get("label"), "penalty": p.get("penalty")}

    def _run_dig(self, name: str, rr: str, timeout_s: float, out_tag: Optional[str], log) -> List[str]:
        name = name.rstrip(".")
        cmd = ["dig", "+short", f"+time={max(1,int(timeout_s))}", "+tries=1", "+retry=0", name, rr]
        safe = _slug(out_tag if out_tag else f"{name}_{rr}")
        out_file = self.dns_dir / f"{safe}.txt"
        t0 = _now()
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=max(1.0, timeout_s+1.0))
            dt = round(_now() - t0, 3)
            try:
                out_file.write_text(p.stdout or "", encoding="utf-8")
            except Exception:
                pass
            try:
                with self.commands_path.open("a", encoding="utf-8") as cf:
                    cf.write(" ".join(cmd) + "\n")
            except Exception:
                pass
            if callable(log):
                log("DEBUG", self.name, "dns_query", {"domain": name, "rr": rr, "cmd": " ".join(cmd), "rc": p.returncode, "time_s": dt, "out": str(out_file)})
            if p.returncode != 0:
                return []
            out = [x.strip() for x in (p.stdout or "").splitlines() if x.strip()]
            return out
        except subprocess.TimeoutExpired:
            if callable(log):
                log("WARNING", self.name, "dns_timeout", {"domain": name, "rr": rr, "timeout_s": timeout_s})
            try:
                out_file.write_text("", encoding="utf-8")
            except Exception:
                pass
            return []
        except Exception as e:
            if callable(log):
                log("WARNING", self.name, "dns_error", {"domain": name, "rr": rr, "error": str(e)[:200]})
            try:
                out_file.write_text("", encoding="utf-8")
            except Exception:
                pass
            return []

    def _q_txt(self, name: str, timeout_s: float, out_tag: Optional[str], log) -> List[str]:
        raws = self._run_dig(name, "TXT", timeout_s, out_tag, log)
        txts = []
        for ln in raws:
            s = ln
            if s.startswith('"') and s.endswith('"'):
                s = s[1:-1]
            s = s.replace('" "', "")
            s = s.replace('"', "")
            if s:
                txts.append(s)
        return txts

    def _q_cname_target(self, name: str, timeout_s: float, log) -> Optional[str]:
        out = self._run_dig(name, "CNAME", timeout_s, f"{name}_CNAME", log)
        if not out:
            return None
        tgt = out[0].rstrip(".")
        return tgt or None

    def _q_a_aaaa(self, name: str, timeout_s: float, log) -> List[str]:
        a = self._run_dig(name, "A", timeout_s, f"{name}_A", log)
        aaaa = self._run_dig(name, "AAAA", timeout_s, f"{name}_AAAA", log)
        return [x for x in a + aaaa if x]

    def _q_mx(self, domain: str, timeout_s: float, log=None) -> Dict[str, Any]:
        lines = self._run_dig(domain, "MX", timeout_s, f"{domain}_MX", log)
        recs: List[Dict[str, Any]] = []
        for ln in lines:
            m = re.match(r"^\s*(\d+)\s+(.+)$", ln)
            if not m:
                continue
            pref = int(m.group(1))
            host = m.group(2).rstrip(".").lower()
            cname = self._q_cname_target(host, timeout_s, log)
            addrs = self._q_a_aaaa(cname or host, timeout_s, log)
            private = any(self._is_private_ip(ip) for ip in addrs)
            recs.append({"preference": pref, "host": host, "cname": cname, "addresses": addrs, "private_ip": private})
        recs.sort(key=lambda x: (x["preference"], x["host"]))
        return {"records": recs}

    def _is_private_ip(self, ip: str) -> bool:
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) == 4:
                if parts[0] == 10:
                    return True
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    return True
                if parts[0] == 192 and parts[1] == 168:
                    return True
            return False
        except Exception:
            return False

    def _get_spf_records(self, domain: str, timeout_s: float, log) -> List[str]:
        txts = self._q_txt(domain, timeout_s, f"{domain}_TXT", log)
        return [t for t in txts if _lower(t).startswith("v=spf1")]

    def _eval_spf(self, domain: str, timeout_s: float, max_spf_lookups: int, log=None) -> Dict[str, Any]:
        spfs = self._get_spf_records(domain, timeout_s, log)
        issues = []
        record = None
        if not spfs:
            issues.append("spf_missing")
        elif len(spfs) > 1:
            issues.append("spf_multiple")
            record = spfs[0]
        else:
            record = spfs[0]
        if not record:
            if callable(log):
                log("DEBUG", self.name, "spf_eval", {"domain": domain, "status": "missing"})
            return {"record": None, "lookups": 0, "issues": issues}
        toks = record.split()
        if _lower(toks[0]) != "v=spf1":
            issues.append("spf_syntax")
            if callable(log):
                log("DEBUG", self.name, "spf_eval", {"domain": domain, "status": "syntax_error"})
            return {"record": record, "lookups": 0, "issues": issues}
        lookups, ptr_used, syntax_err = self._spf_lookup_count(domain, record, timeout_s, max_depth=20, log=log)
        if syntax_err:
            issues.append("spf_syntax")
        if ptr_used:
            issues.append("spf_ptr")
        if lookups > max_spf_lookups:
            issues.append("spf_lookup_over")
        last_mech = None
        for t in reversed(toks):
            if t.startswith(("redirect=",)):
                last_mech = "redirect"
                break
            if t.startswith(("+all","-all","~all","?all")) or t.endswith("all"):
                last_mech = t
                break
        if last_mech is None:
            issues.append("spf_no_all")
        else:
            lm = _lower(last_mech)
            if lm.startswith("~all") or lm.endswith("~all"):
                issues.append("spf_all_softfail")
            elif lm.startswith("?all") or lm.endswith("?all"):
                issues.append("spf_all_neutral")
            elif lm.startswith("+all") or lm.endswith("+all") or lm == "all":
                issues.append("spf_all_pass")
        if callable(log):
            log("DEBUG", self.name, "spf_eval", {"domain": domain, "lookups": lookups, "issues": issues})
        return {"record": record, "lookups": lookups, "issues": issues}

    def _spf_lookup_count(self, domain: str, record: str, timeout_s: float, max_depth: int, log=None) -> Tuple[int, bool, bool]:
        seen: set[str] = set()
        ptr_used = False
        syntax_err = False
        def count_for(dom: str, lvl: int) -> Tuple[int, bool, bool]:
            nonlocal ptr_used, syntax_err
            if lvl > max_depth:
                return 0, ptr_used, True
            spfs = self._get_spf_records(dom, timeout_s, log)
            if not spfs:
                return 0, ptr_used, True
            rec = spfs[0]
            toks = rec.split()
            if not toks or _lower(toks[0]) != "v=spf1":
                return 0, ptr_used, True
            total = 0
            for tk in toks[1:]:
                tk = tk.strip()
                if not tk:
                    continue
                if ":" in tk:
                    mech, val = tk.split(":",1)
                elif "=" in tk:
                    mech, val = tk.split("=",1)
                else:
                    mech, val = tk, None
                m = _lower(mech.lstrip("+-~?"))
                if m in ("include","exists","a","mx","ptr","redirect"):
                    total += 1
                if m == "include" and val:
                    sub = val
                    if sub not in seen:
                        seen.add(sub)
                        c, ptr_loc, se = count_for(sub, lvl+1)
                        total += c
                        if se:
                            syntax_err = True
                        if ptr_loc:
                            ptr_used = True
                if m == "redirect" and val:
                    sub = val
                    if sub not in seen:
                        seen.add(sub)
                        c, ptr_loc, se = count_for(sub, lvl+1)
                        total += c
                        if se:
                            syntax_err = True
                        if ptr_loc:
                            ptr_used = True
                if m == "ptr":
                    ptr_used = True
            return total, ptr_used, syntax_err
        base_count, ptr_used, se = count_for(domain, 0)
        return base_count, ptr_used, se

    def _eval_dmarc(self, domain: str, timeout_s: float, log=None) -> Dict[str, Any]:
        name = f"_dmarc.{domain}"
        txts = self._q_txt(name, timeout_s, f"{name}_TXT", log)
        used = "domain"
        if not txts:
            parts = domain.split(".")
            if len(parts) >= 2:
                parent = ".".join(parts[-2:])
                txts = self._q_txt(f"_dmarc.{parent}", timeout_s, f"_dmarc.{parent}_TXT", log)
                used = "parent" if txts else "none"
        issues = []
        record = txts[0] if txts else None
        if not record:
            issues.append("dmarc_missing")
            if callable(log):
                log("DEBUG", self.name, "dmarc_eval", {"domain": domain, "status": "missing"})
            return {"record": None, "source": used, "issues": issues}
        fields = {}
        ok = True
        for seg in record.split(";"):
            seg = seg.strip()
            if not seg or "=" not in seg:
                continue
            k, v = seg.split("=",1)
            fields[_lower(k.strip())] = v.strip()
        if _lower(fields.get("v")) != "dmarc1":
            ok = False
        policy = _lower(fields.get("p"))
        if policy not in ("reject","quarantine","none"):
            ok = False
        if not ok:
            issues.append("dmarc_syntax")
        if policy == "none":
            issues.append("dmarc_policy_none")
        pct_raw = fields.get("pct")
        if pct_raw:
            try:
                pct = int(pct_raw)
                if pct < 100:
                    issues.append("dmarc_pct_lt100")
            except Exception:
                pass
        rua = fields.get("rua")
        if not rua:
            issues.append("dmarc_no_rua")
        ruf = fields.get("ruf")
        if not ruf:
            issues.append("dmarc_no_ruf")
        if _lower(fields.get("adkim","r")) == "r" or _lower(fields.get("aspf","r")) == "r":
            issues.append("dmarc_relaxed_align")
        if callable(log):
            log("DEBUG", self.name, "dmarc_eval", {"domain": domain, "source": used, "issues": issues})
        return {"record": record, "source": used, "issues": issues, "tags": fields}

    def _eval_dkim(self, domain: str, selectors: List[str], timeout_s: float, log=None) -> Dict[str, Any]:
        tested = []
        found_any = False
        weak = False
        invalid = False
        for sel in selectors:
            name = f"{sel}._domainkey.{domain}"
            txts = self._q_txt(name, timeout_s, f"{name}_TXT", log)
            if not txts:
                tested.append({"selector": sel, "found": False, "bits": None})
                continue
            rec = txts[0]
            tags = {}
            for seg in rec.split(";"):
                seg = seg.strip()
                if not seg or "=" not in seg:
                    continue
                k, v = seg.split("=",1)
                tags[_lower(k.strip())] = v.strip()
            p = tags.get("p")
            if not p:
                invalid = True
                tested.append({"selector": sel, "found": True, "bits": None})
                continue
            bits = self._dkim_bits(p)
            if bits and bits < 2048:
                weak = True
            tested.append({"selector": sel, "found": True, "bits": bits})
            found_any = True
        issues = []
        if not found_any:
            issues.append("dkim_not_found")
        if invalid:
            issues.append("dkim_invalid")
        if weak:
            issues.append("dkim_weak_key")
        if callable(log):
            log("DEBUG", self.name, "dkim_eval", {"domain": domain, "tested": len(tested), "issues": issues})
        return {"tested": tested, "issues": issues}

    def _dkim_bits(self, p: str) -> Optional[int]:
        try:
            raw = base64.b64decode(p + "===")
            return len(raw) * 8
        except Exception:
            return None

    def _eval_dnssec(self, domain: str, timeout_s: float, log=None) -> Dict[str, Any]:
        ds = self._run_dig(domain, "DS", timeout_s, f"{domain}_DS", log)
        dnskey = self._run_dig(domain, "DNSKEY", timeout_s, f"{domain}_DNSKEY", log)
        issues = []
        status = "unsigned"
        if dnskey and not ds:
            status = "signed-nods"
            issues.append("dnssec_nods")
        elif ds and dnskey:
            status = "signed"
        elif not ds and not dnskey:
            status = "unsigned"
            issues.append("dnssec_unsigned")
        else:
            status = "indeterminate"
            issues.append("dnssec_indeterminate")
        if callable(log):
            log("DEBUG", self.name, "dnssec_eval", {"domain": domain, "status": status, "issues": issues})
        return {"ds": bool(ds), "dnskey": bool(dnskey), "status": status, "issues": issues}

    def _load_selector_patterns(self, patterns_path: str, audit_dir: Path) -> Tuple[List[str], Optional[str]]:
        if not patterns_path:
            return self._default_patterns(), None
        p = Path(patterns_path)
        if not p.is_absolute():
            p = (audit_dir.parent.parent / p).resolve()
        if not p.exists():
            return self._default_patterns(), None
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return self._default_patterns(), None
        pats: List[str] = []
        for ln in lines:
            t = ln.strip()
            if not t:
                continue
            if t.startswith(";") or t.startswith("#"):
                continue
            pats.append(t)
        return pats or self._default_patterns(), str(p)

    def _default_patterns(self) -> List[str]:
        return ["default","selector","google","mail","dkim","key%N1,10%","selector%N1,10%","k%N1,20%","s%L256,384,512,768,1024,2048%","m%L256,384,512,768,1024,2048%"]

    def _expand_selector_patterns(self, patterns: List[str], domain: str) -> List[str]:
        out: List[str] = []
        seen: set[str] = set()
        for pat in patterns:
            expansions = self._expand_one_pattern(pat, domain)
            for sel in expansions:
                s = sel.strip()
                if not s:
                    continue
                if s in seen:
                    continue
                seen.add(s)
                out.append(s)
                if len(out) > 2000:
                    return out
        return out

    def _expand_one_pattern(self, pattern: str, domain: str) -> List[str]:
        todo = [pattern]
        done: List[str] = []
        limit = 20
        rx = re.compile(r"%([^%]+)%")
        while todo and limit > 0:
            limit -= 1
            cur = todo.pop(0)
            m = rx.search(cur)
            if not m:
                done.append(cur)
                continue
            token = m.group(1).strip()
            repls = self._expand_token(token, domain)
            if not repls:
                done.append(cur)
                continue
            for r in repls:
                todo.append(cur[:m.start()] + r + cur[m.end():])
        done2 = [x for x in done if rx.search(x) is None]
        return done2

    def _expand_token(self, token: str, domain: str) -> List[str]:
        if token.startswith(("N","n")):
            t = token[1:]
            m = re.match(r"^(\d+),(\d+)$", t)
            if not m:
                return []
            a_raw, b_raw = m.group(1), m.group(2)
            a = int(a_raw)
            b = int(b_raw)
            width = len(a_raw) if a_raw.startswith("0") else 0
            out = []
            step = 1 if b >= a else -1
            for i in range(a, b + step, step):
                s = str(i).zfill(width) if width > 0 else str(i)
                out.append(s)
                if len(out) > 500:
                    break
            return out
        if token.startswith(("L","l")):
            t = token[1:]
            parts = [x.strip() for x in t.split(",") if x.strip()]
            return parts
        if token.startswith(("D","d")):
            t = token[1:]
            labels = [x for x in domain.split(".") if x]
            if not t:
                return [".".join(labels)]
            rng = t.split(",")
            try:
                if len(rng) == 1:
                    idx = int(rng[0])
                    i = idx - 1 if idx > 0 else len(labels) + idx
                    if 0 <= i < len(labels):
                        return [labels[i]]
                    return []
                if len(rng) == 2:
                    a = int(rng[0])
                    b = int(rng[1])
                    ia = a - 1 if a > 0 else len(labels) + a
                    ib = b - 1 if b > 0 else len(labels) + b
                    if ia < 0: ia = 0
                    if ib >= len(labels): ib = len(labels) - 1
                    if ia > ib:
                        return []
                    return [".".join(labels[ia:ib+1])]
            except Exception:
                return []
            return []
        if token.startswith(("O","o")):
            return ["", token[1:]]
        return []
