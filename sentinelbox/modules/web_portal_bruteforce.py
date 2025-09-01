import json
import time
import re
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Optional, Dict, List, Tuple
from ..module import Module
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import StaleElementReferenceException

PAUSE_AFTER_LOAD_S = 5.0
AFTER_SUBMIT_WAIT_S = 6.0
WAIT_READY_S = 8.0
TRY_PAIRS = [("admin", "admin"), ("admin", "1234")]

def _read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    out: List[str] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#"):
                continue
            out.append(t)
    return out

def _read_pairs(path: Path) -> List[Tuple[str, str]]:
    if not path.exists():
        return []
    out: List[Tuple[str, str]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            t = line.strip()
            if not t or t.startswith("#") or ":" not in t:
                continue
            u, pw = t.split(":", 1)
            out.append((u.strip(), pw.strip()))
    return out

def _is_https(row: dict) -> bool:
    tun = str(row.get("tunnel") or "").lower()
    extra = str(row.get("extrainfo") or "").lower()
    svc = str(row.get("service_name") or "").lower()
    return ("ssl" in tun) or ("tls" in tun) or ("https" in svc) or ("https" in extra)

def _build_url(host: str, port: int, https: bool, endpoint: str) -> str:
    proto = "https" if https else "http"
    ep = (endpoint or "").lstrip("/")
    return f"{proto}://{host}:{port}/" if not ep else f"{proto}://{host}:{port}/{ep}"

def _norm(s: Optional[str]) -> str:
    return (s or "").strip().lower()

def _slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)

def _endpoint_slug(endpoint: Optional[str]) -> str:
    ep = (endpoint or "").strip()
    if ep == "" or ep == "/":
        return "root"
    return _slug(ep.lstrip("/"))

def _form_key(u_attr: str, u_val: str, p_attr: str, p_val: str) -> Tuple[str, str, str, str]:
    return (_norm(u_attr or "none"), _norm(u_val), _norm(p_attr or "none"), _norm(p_val))

def _pick_submit(form):
    cand = form.find_elements(By.XPATH, ".//input[(@type='submit' or @type='image') and not(@disabled)]")
    for x in cand:
        if x.is_displayed():
            return x
    cand = form.find_elements(By.XPATH, ".//button[(not(@type) or @type='submit') and not(@disabled)]")
    for x in cand:
        if x.is_displayed():
            return x
    return None

def _enumerate_inputs(form) -> List[Dict[str, Any]]:
    out = []
    els = form.find_elements(By.TAG_NAME, "input")
    for i, el in enumerate(els):
        try:
            out.append({
                "idx": i,
                "type": (el.get_attribute("type") or "").lower(),
                "name": el.get_attribute("name"),
                "id": el.get_attribute("id"),
                "value_len": len(el.get_attribute("value") or ""),
                "readonly": bool(el.get_attribute("readonly")),
                "disabled": bool(el.get_attribute("disabled")),
                "displayed": el.is_displayed()
            })
        except Exception:
            pass
    return out

def _detect_form(driver, login_names: List[str], password_names: List[str]) -> Tuple[bool, Optional[Dict[str, str]], int, List[Dict[str, Any]]]:
    forms = driver.find_elements(By.TAG_NAME, "form")
    total_forms = len(forms)
    inspected: List[Dict[str, Any]] = []
    for idx, form in enumerate(forms):
        form_info = {"form_index": idx, "inputs": _enumerate_inputs(form), "candidate": False}
        inputs = form.find_elements(By.TAG_NAME, "input")
        uname_attr = None
        uname_val = ""
        pass_attr = None
        pass_val = ""
        has_user = False
        has_pass = False
        for el in inputs:
            t = _norm(el.get_attribute("type"))
            nm = _norm(el.get_attribute("name"))
            idv = _norm(el.get_attribute("id"))
            if not has_user and (nm in login_names or idv in login_names):
                has_user = True
                if nm in login_names:
                    uname_attr, uname_val = "name", nm
                else:
                    uname_attr, uname_val = "id", idv
            if not has_pass and (t == "password" or nm in password_names or idv in password_names):
                has_pass = True
                if t == "password":
                    if nm:
                        pass_attr, pass_val = "name", nm
                    elif idv:
                        pass_attr, pass_val = "id", idv
                    else:
                        pass_attr, pass_val = "name", "password"
                elif nm in password_names:
                    pass_attr, pass_val = "name", nm
                elif idv in password_names:
                    pass_attr, pass_val = "id", idv
        if has_user or has_pass:
            form_info["candidate"] = True
            inspected.append(form_info)
            return True, {
                "u_attr": uname_attr or "none",
                "u_val": uname_val,
                "p_attr": pass_attr or "none",
                "p_val": pass_val
            }, total_forms, inspected
        inspected.append(form_info)
    return False, None, total_forms, inspected

def _dump_cookies_and_storage(driver) -> Dict[str, Any]:
    info: Dict[str, Any] = {"cookies": [], "localStorage": None, "sessionStorage": None}
    try:
        for c in driver.get_cookies():
            info["cookies"].append({"name": c.get("name"), "domain": c.get("domain"), "secure": c.get("secure")})
    except Exception:
        pass
    try:
        info["localStorage"] = driver.execute_script("return Object.keys(window.localStorage)")
    except Exception:
        pass
    try:
        info["sessionStorage"] = driver.execute_script("return Object.keys(window.sessionStorage)")
    except Exception:
        pass
    return info

def _wait_ready(driver, timeout_s: float) -> None:
    try:
        end = time.time() + timeout_s
        while time.time() < end:
            try:
                rs = driver.execute_script("return document.readyState")
            except Exception:
                rs = None
            if rs in ("interactive", "complete"):
                break
            time.sleep(0.15)
    except Exception:
        pass

def _reacquire_form_and_fields(driver, meta: Dict[str, str]) -> Tuple[Optional[Any], Optional[Any], Optional[Any], Optional[Any]]:
    forms = driver.find_elements(By.TAG_NAME, "form")
    for form in forms:
        uname_el = None
        pass_el = None
        if meta.get("u_attr") == "name":
            el = form.find_elements(By.NAME, meta.get("u_val"))
            uname_el = el[0] if el else None
        elif meta.get("u_attr") == "id":
            el = form.find_elements(By.ID, meta.get("u_val"))
            uname_el = el[0] if el else None
        if meta.get("p_attr") == "name":
            el = form.find_elements(By.NAME, meta.get("p_val"))
            pass_el = el[0] if el else None
        elif meta.get("p_attr") == "id":
            el = form.find_elements(By.ID, meta.get("p_val"))
            pass_el = el[0] if el else None
        if (meta.get("u_attr") == "none" or uname_el) and (meta.get("p_attr") == "none" or pass_el):
            submit = _pick_submit(form)
            return form, uname_el, pass_el, submit
    return None, None, None, None

class WebPortalBruteforce(Module):
    name = "WebPortalBruteforce"

    def run(self, context: dict[str, Any]) -> Tuple[bool, bool, Optional[str], Optional[dict[str, Any]]]:
        log = context.get("log")
        store = context.get("store")

        audit_dir = Path(context.get("audit_dir"))
        data_dir = audit_dir / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

        logs_dir = audit_dir / "logs" / self.name
        scr_dir = logs_dir / "screens"
        pages_dir = logs_dir / "pages"
        forms_dir = logs_dir / "forms"
        meta_dir = logs_dir / "meta"
        for d in (logs_dir, scr_dir, pages_dir, forms_dir, meta_dir):
            d.mkdir(parents=True, exist_ok=True)

        pages_root = data_dir / "web_pages"
        pages_root.mkdir(parents=True, exist_ok=True)
        pages_index = pages_root / "index.json"
        if not pages_index.exists():
            pages_index.write_text(json.dumps({"items": []}, ensure_ascii=False, indent=2), encoding="utf-8")

        wf_root = data_dir / "web_forms"
        wf_root.mkdir(parents=True, exist_ok=True)
        wf_index = wf_root / "index.json"
        if not wf_index.exists():
            wf_index.write_text(json.dumps({"items": []}, ensure_ascii=False, indent=2), encoding="utf-8")

        base_data = Path(context.get("audit_dir")).parent.parent / "data"
        wl_dir = base_data / "wordlists"
        endpoints = _read_lines(wl_dir / "web_endpoints.txt")
        login_names = [x.lower() for x in _read_lines(wl_dir / "web_login_names.txt")] or ["user", "username", "login", "email"]
        password_names = [x.lower() for x in _read_lines(wl_dir / "web_password_names.txt")] or ["pass", "password", "pwd"]
        pairs = _read_pairs(wl_dir / "web_pairs.txt") or TRY_PAIRS

        rows = store.list_services() if store else []
        ip_name_map: Dict[str, Optional[str]] = {}
        try:
            for h in (store.list_hosts() if store else []):
                ip_name_map[h["ip"]] = h.get("hostname")
        except Exception:
            pass

        web_targets: List[Dict[str, Any]] = []
        by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            if str(r.get("state", "")).lower() != "open":
                continue
            svc = _norm(r.get("service_name"))
            if "http" not in svc:
                continue
            ip = r.get("ip")
            proto = _norm(r.get("proto"))
            port = int(r.get("port") or 0)
            if not ip or not port or not proto:
                continue
            host = ip_name_map.get(ip) or ip
            web_targets.append({"ip": ip, "host": host, "proto": proto, "port": port, "https": _is_https(r)})

        for t in web_targets:
            by_ip.setdefault(t["ip"], []).append(t)
        for ip in by_ip:
            by_ip[ip].sort(key=lambda x: (0 if x["https"] else 1, 0 if x["port"] == 80 else 1, x["port"]))

        if callable(log):
            log("INFO", self.name, "start", {
                "ips": len(by_ip),
                "targets": sum(len(v) for v in by_ip.values()),
                "endpoints": len(endpoints),
                "login_names": login_names,
                "password_names": password_names
            })

        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--ignore-certificate-errors")
        options.set_capability("acceptInsecureCerts", True)
        try:
            options.set_capability("goog:loggingPrefs", {"browser": "ALL", "performance": "ALL"})
        except Exception:
            pass

        driver = webdriver.Chrome(options=options)
        try:
            caps = getattr(driver, "capabilities", {}) or {}
            ua = None
            try:
                ua = driver.execute_script("return navigator.userAgent")
            except Exception:
                ua = None
            sz = None
            try:
                sz = driver.get_window_size()
            except Exception:
                sz = None
            if callable(log):
                log("DEBUG", self.name, "webdriver_info", {
                    "browserName": caps.get("browserName"),
                    "browserVersion": caps.get("browserVersion"),
                    "platformName": caps.get("platformName"),
                    "userAgent": ua,
                    "window": sz,
                    "logs_dir": str(logs_dir)
                })
        except Exception:
            pass

        tested_forms_by_ip: Dict[str, set] = {}
        findings: List[Dict[str, Any]] = []
        attempts_total = 0

        def save_page_asset(ip: str, host: str, port: int, https: bool, endpoint: str, tag: str, requested_url: str, final_url: Optional[str]) -> Dict[str, str]:
            scheme = "https" if https else "http"
            ep_slug = _endpoint_slug(endpoint)
            safe_host = _slug(host)
            asset_id = "p" + secrets.token_hex(6)
            base = pages_root / safe_host / f"{scheme}-{port}" / ep_slug / asset_id
            base.mkdir(parents=True, exist_ok=True)
            page_png = base / "page.png"
            page_html = base / "page.html"
            meta_json = base / "meta.json"
            try:
                driver.save_screenshot(str(page_png))
            except Exception:
                pass
            try:
                with page_html.open("w", encoding="utf-8") as f:
                    f.write(driver.page_source or "")
            except Exception:
                pass
            meta = {
                "ip": ip,
                "host": host,
                "scheme": scheme,
                "port": port,
                "endpoint": f"/{(endpoint or '').lstrip('/')}" if endpoint and endpoint != "/" else "/",
                "endpoint_slug": ep_slug,
                "requested_url": requested_url,
                "final_url": final_url or requested_url,
                "tag": tag,
                "page_title": None,
                "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                "asset_id": asset_id
            }
            try:
                try:
                    meta["page_title"] = driver.title
                except Exception:
                    meta["page_title"] = None
                with meta_json.open("w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            try:
                idx = json.loads(pages_index.read_text(encoding="utf-8"))
            except Exception:
                idx = {"items": []}
            idx["items"].append({
                "ip": ip,
                "host": host,
                "scheme": scheme,
                "port": port,
                "endpoint_slug": ep_slug,
                "key": asset_id,
                "paths": {"page_png": str(page_png), "page_html": str(page_html), "meta": str(meta_json)}
            })
            try:
                pages_index.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            return {"screenshot": str(page_png), "html": str(page_html), "meta": str(meta_json)}

        def save_form_assets(ip: str, host: str, port: int, https: bool, endpoint: str, key: Tuple[str, str, str, str], form_obj: Optional[Any], url: str) -> Dict[str, str]:
            scheme = "https" if https else "http"
            ep_slug = _endpoint_slug(endpoint)
            safe_host = _slug(host)
            asset_id = "k" + secrets.token_hex(6)
            base = wf_root / safe_host / f"{scheme}-{port}" / ep_slug / asset_id
            base.mkdir(parents=True, exist_ok=True)
            page_png = base / "page.png"
            form_png = base / "form.png"
            form_html = base / "form.html"
            page_html = base / "page.html"
            meta_json = base / "meta.json"
            try:
                driver.save_screenshot(str(page_png))
            except Exception:
                pass
            try:
                if form_obj is not None:
                    try:
                        form_obj.screenshot(str(form_png))
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                outer = ""
                if form_obj is not None:
                    try:
                        outer = form_obj.get_attribute("outerHTML") or ""
                    except Exception:
                        outer = ""
                with form_html.open("w", encoding="utf-8") as f:
                    f.write(outer)
            except Exception:
                pass
            try:
                with page_html.open("w", encoding="utf-8") as f:
                    f.write(driver.page_source or "")
            except Exception:
                pass
            meta_fk = {"u_attr": key[0], "u_val": key[1], "p_attr": key[2], "p_val": key[3]}
            meta = {
                "ip": ip,
                "host": host,
                "scheme": scheme,
                "port": port,
                "url": url,
                "endpoint": f"/{(endpoint or '').lstrip('/')}" if endpoint and endpoint != "/" else "/",
                "endpoint_slug": ep_slug,
                "form_key": meta_fk,
                "detected_inputs": {"username_candidates": login_names, "password_candidates": password_names},
                "page_title": None,
                "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                "asset_id": asset_id
            }
            try:
                try:
                    meta["page_title"] = driver.title
                except Exception:
                    meta["page_title"] = None
                with meta_json.open("w", encoding="utf-8") as f:
                    json.dump(meta, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            try:
                idx = json.loads(wf_index.read_text(encoding="utf-8"))
            except Exception:
                idx = {"items": []}
            item = {
                "ip": ip,
                "host": host,
                "scheme": scheme,
                "port": port,
                "endpoint_slug": ep_slug,
                "key": asset_id,
                "form_key": meta_fk,
                "paths": {
                    "page_png": str(page_png),
                    "screenshot": str(page_png),
                    "meta": str(meta_json),
                    "form_html": str(form_html),
                    "page_html": str(page_html),
                    "form_png": str(form_png)
                }
            }
            idx["items"].append(item)
            try:
                wf_index.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass
            return item

        def event(meta: Dict[str, Any]) -> None:
            try:
                path = meta_dir / "events.jsonl"
                with path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(meta, ensure_ascii=False) + "\n")
            except Exception:
                pass

        try:
            for ip, ports in by_ip.items():
                tested_forms_by_ip.setdefault(ip, set())
                for t in ports:
                    port = t["port"]
                    https = t["https"]
                    host = t["host"]
                    form_tested_here = False
                    for ep in endpoints:
                        req_url = _build_url(host, port, https, ep)
                        if callable(log):
                            log("DEBUG", self.name, "page_load_begin", {"ip": ip, "host": host, "port": port, "url": req_url})
                        try:
                            driver.delete_all_cookies()
                        except Exception:
                            pass

                        load_err = None
                        t0 = time.time()
                        try:
                            driver.get(req_url)
                        except Exception as e:
                            load_err = str(e)
                        _wait_ready(driver, WAIT_READY_S)
                        time.sleep(PAUSE_AFTER_LOAD_S)
                        t_load = round(time.time() - t0, 3)

                        final_url = getattr(driver, "current_url", req_url)
                        save_page_asset(ip, host, port, https, ep or "/", "loaded", req_url, final_url)

                        cookies_and_storage = _dump_cookies_and_storage(driver)
                        try:
                            scr_path = scr_dir / f"{_slug(host)}_{port}_{_endpoint_slug(ep)}_loaded.png"
                            driver.save_screenshot(str(scr_path))
                        except Exception:
                            pass
                        try:
                            (pages_dir / f"{_slug(host)}_{port}_{_endpoint_slug(ep)}_loaded.html").write_text(driver.page_source or "", encoding="utf-8")
                        except Exception:
                            pass

                        ok, meta, total_forms, inspected = _detect_form(driver, login_names, password_names)
                        if callable(log):
                            log("DEBUG", self.name, "page_load_done", {
                                "ip": ip, "host": host, "port": port,
                                "requested_url": req_url,
                                "current_url": final_url,
                                "load_error": load_err,
                                "load_time_s": t_load,
                                "forms_found": total_forms,
                                "candidate_form": bool(ok),
                                "candidate_meta": meta,
                                "cookies_count": len(cookies_and_storage.get("cookies") or []),
                                "screen": str(scr_dir),
                                "pages": str(pages_dir)
                            })
                        event({"ts": datetime.utcnow().isoformat()+"Z", "type": "page_loaded", "ip": ip, "host": host, "port": port, "requested_url": req_url, "final_url": final_url, "forms_found": total_forms})

                        if not ok or not meta:
                            continue

                        key = _form_key(meta.get("u_attr"), meta.get("u_val"), meta.get("p_attr"), meta.get("p_val"))
                        if key in tested_forms_by_ip[ip]:
                            if callable(log):
                                log("DEBUG", self.name, "skip_form_already_tested", {"ip": ip, "host": host, "port": port, "url": req_url, "form_key": "|".join(key)})
                            form_tested_here = True
                            break

                        form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                        saved = save_form_assets(ip, host, port, https, ep, key, form2, final_url)
                        if callable(log):
                            log("INFO", self.name, "form_assets_saved", {"ip": ip, "host": host, "port": port, "url": final_url, "form_key": "|".join(key), "assets": saved})
                        event({"ts": datetime.utcnow().isoformat()+"Z", "type": "form_found", "ip": ip, "host": host, "port": port, "url": final_url, "form_key": key})

                        tested_forms_by_ip[ip].add(key)
                        form_tested_here = True

                        for idx, (u, pw) in enumerate(TRY_PAIRS, start=1):
                            attempts_total += 1
                            if callable(log):
                                log("DEBUG", self.name, "web_bruteforce_attempt_begin", {"ip": ip, "host": host, "port": port, "url": final_url, "user": u, "pass": pw, "try_index": idx, "form_key": "|".join(key)})
                            event({"ts": datetime.utcnow().isoformat()+"Z", "type": "attempt_begin", "ip": ip, "host": host, "port": port, "url": final_url, "user": u, "try_index": idx})

                            try:
                                form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                                if uname_el and not uname_el.get_attribute("readonly"):
                                    try:
                                        uname_el.clear()
                                    except StaleElementReferenceException:
                                        form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                                    if uname_el:
                                        uname_el.send_keys(u)
                                if pass_el and not pass_el.get_attribute("readonly"):
                                    try:
                                        pass_el.clear()
                                    except StaleElementReferenceException:
                                        form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                                    if pass_el:
                                        pass_el.send_keys(pw)

                                save_page_asset(ip, host, port, https, ep or "/", f"before_submit_try{idx}", final_url, getattr(driver, "current_url", final_url))

                                used = None
                                t1 = time.time()
                                try:
                                    form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                                    if submit and submit.is_displayed():
                                        driver.execute_script("arguments[0].scrollIntoView(true);", submit)
                                        time.sleep(0.2)
                                        try:
                                            driver.execute_script("arguments[0].click();", submit)
                                            used = "click_submit"
                                        except StaleElementReferenceException:
                                            form2, uname_el, pass_el, submit = _reacquire_form_and_fields(driver, meta)
                                            if submit:
                                                driver.execute_script("arguments[0].click();", submit)
                                                used = "click_submit_refetched"
                                    elif pass_el:
                                        pass_el.send_keys(Keys.ENTER)
                                        used = "enter_in_password"
                                    elif uname_el:
                                        uname_el.send_keys(Keys.ENTER)
                                        used = "enter_in_username"
                                    else:
                                        if form2:
                                            driver.execute_script("arguments[0].submit();", form2)
                                            used = "js_form_submit"
                                        else:
                                            used = "no_submit_control"
                                except StaleElementReferenceException:
                                    used = "submit_stale_reacquire_failed"
                                t_submit = round(time.time() - t1, 3)
                                if callable(log):
                                    log("DEBUG", self.name, "submit_method_used", {"ip": ip, "host": host, "port": port, "method": used, "submit_phase_s": t_submit})
                                event({"ts": datetime.utcnow().isoformat()+"Z", "type": "submit", "ip": ip, "host": host, "port": port, "method": used, "submit_s": t_submit})
                            except Exception as e:
                                if callable(log):
                                    log("DEBUG", self.name, "submit_prep_exception", {"error": str(e)[:200]})

                            _wait_ready(driver, WAIT_READY_S)
                            time.sleep(AFTER_SUBMIT_WAIT_S)

                            final_after = getattr(driver, "current_url", final_url)
                            save_page_asset(ip, host, port, https, ep or "/", f"after_submit_try{idx}", final_url, final_after)

                            ok_after, meta_after, total_after, _ = _detect_form(driver, login_names, password_names)
                            if callable(log):
                                log("DEBUG", self.name, "post_submit_scan", {"ip": ip, "host": host, "port": port, "url": final_after, "login_form_present": bool(ok_after), "forms_found": total_after})
                            event({"ts": datetime.utcnow().isoformat()+"Z", "type": "attempt_end", "ip": ip, "host": host, "port": port, "url": final_after, "login_form_present": bool(ok_after)})

                            if not ok_after:
                                if store:
                                    store.put_auth_finding(ip, t["proto"], port, "http" if not https else "https", u, pw, "WebForm", True, "Authentification triviale via formulaire web")
                                findings.append({
                                    "ip": ip,
                                    "host": host if host != ip else None,
                                    "proto": t["proto"],
                                    "port": port,
                                    "service": "https" if https else "http",
                                    "username": u,
                                    "password": pw,
                                    "method": "WebForm",
                                    "verified": True,
                                    "note": "Authentification triviale via formulaire web",
                                    "requested_url": req_url,
                                    "final_url": final_after
                                })
                                if callable(log):
                                    log("INFO", self.name, "web_bruteforce_result", {"ip": ip, "host": host, "port": port, "url": final_after, "success": True})
                                event({"ts": datetime.utcnow().isoformat()+"Z", "type": "success", "ip": ip, "host": host, "port": port, "url": final_after})
                                break
                            else:
                                if callable(log):
                                    log("DEBUG", self.name, "web_bruteforce_result", {"ip": ip, "host": host, "port": port, "url": final_after, "success": False})

                        break

                    if not form_tested_here and callable(log):
                        log("DEBUG", self.name, "no_form_for_target", {"ip": ip, "host": host, "port": port})
        finally:
            try:
                driver.quit()
            except Exception:
                pass

        out_path = data_dir / "weak_web_auth.json"
        with out_path.open("w", encoding="utf-8") as f:
            json.dump({"items": findings, "attempts": attempts_total}, f, ensure_ascii=False, separators=(",", ":"), indent=2)

        if callable(log):
            log("INFO", self.name, "done", {
                "ips": len(by_ip),
                "targets": sum(len(v) for v in by_ip.values()),
                "successes": len(findings),
                "output": str(out_path),
                "logs_dir": str(logs_dir),
                "web_pages_dir": str(pages_root),
                "web_forms_dir": str(wf_root)
            })

        return True, False, "ok", {"targets": sum(len(v) for v in by_ip.values()), "successes": len(findings), "output": str(out_path)}
