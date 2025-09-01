import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional, Any

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS audits(
  id TEXT PRIMARY KEY,
  started_at TEXT,
  finished_at TEXT,
  status TEXT
);
CREATE TABLE IF NOT EXISTS modules(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  name TEXT,
  state TEXT,
  started_at TEXT,
  finished_at TEXT,
  fatal INTEGER,
  message TEXT,
  data TEXT
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ts TEXT,
  level TEXT,
  module TEXT,
  message TEXT,
  data TEXT
);
CREATE TABLE IF NOT EXISTS hosts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  mac TEXT,
  vendor TEXT,
  hostname TEXT,
  first_seen TEXT,
  last_seen TEXT
);
CREATE TABLE IF NOT EXISTS kv(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  scope TEXT,
  k TEXT,
  v TEXT
);
CREATE TABLE IF NOT EXISTS os_inventory(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  label TEXT,
  confidence INTEGER,
  product TEXT,
  version TEXT,
  latest TEXT,
  obsolete INTEGER,
  eol TEXT,
  matched_by TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_osinv_audit_ip ON os_inventory(audit_id, ip);
CREATE TABLE IF NOT EXISTS ports_inventory(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  state TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ports_inv ON ports_inventory(audit_id, ip, proto, port);
CREATE TABLE IF NOT EXISTS service_inventory(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  state TEXT,
  service_name TEXT,
  name_confidence INTEGER,
  product TEXT,
  version TEXT,
  version_confidence INTEGER,
  extrainfo TEXT,
  tunnel TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_service_inv ON service_inventory(audit_id, ip, proto, port);
CREATE TABLE IF NOT EXISTS host_vuln_summary(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  items_json TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_host_vuln_summary ON host_vuln_summary(audit_id, ip);
CREATE TABLE IF NOT EXISTS auth_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  service_name TEXT,
  username TEXT,
  password_masked TEXT,
  method TEXT,
  verified INTEGER,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_auth_findings_audit_ip ON auth_findings(audit_id, ip);
CREATE TABLE IF NOT EXISTS web_auth_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  url TEXT,
  endpoint TEXT,
  username TEXT,
  password TEXT,
  method TEXT,
  verified INTEGER,
  note TEXT,
  screenshot_path TEXT
);

CREATE TABLE IF NOT EXISTS cms_inventory(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  cms_name TEXT,
  version TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cms_inventory ON cms_inventory(audit_id, ip, proto, port);

CREATE TABLE IF NOT EXISTS cms_wp_details(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  users_json TEXT,
  plugins_json TEXT,
  themes_json TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cms_wp_details ON cms_wp_details(audit_id, ip, proto, port);

-- Détails Joomla
CREATE TABLE IF NOT EXISTS cms_joomla_details(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  debug_mode TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_cms_joomla_details ON cms_joomla_details(audit_id, ip, proto, port);

CREATE TABLE IF NOT EXISTS tls_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  proto TEXT,
  port INTEGER,
  service_name TEXT,
  hostname TEXT,
  uri TEXT,
  html_path TEXT,
  score_protocol_support INTEGER,
  score_key_exchange INTEGER,
  score_cipher_strength INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_tls_results ON tls_results(audit_id, ip, proto, port);

CREATE TABLE IF NOT EXISTS mail_audit_results(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  domain TEXT,
  score_total INTEGER,
  score_mx INTEGER,
  score_spf INTEGER,
  score_dkim INTEGER,
  score_dmarc INTEGER,
  score_dnssec INTEGER,
  details_json TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_mail_audit_results ON mail_audit_results(audit_id, domain);


CREATE INDEX IF NOT EXISTS idx_web_auth_findings_audit_ip ON web_auth_findings(audit_id, ip);
CREATE INDEX IF NOT EXISTS idx_modules_audit ON modules(audit_id);
CREATE INDEX IF NOT EXISTS idx_events_audit ON events(audit_id);
CREATE UNIQUE INDEX IF NOT EXISTS ux_hosts_audit_ip ON hosts(audit_id, ip);
CREATE INDEX IF NOT EXISTS idx_kv_scope ON kv(audit_id, scope, k);
"""

def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)

def purge_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
    DROP TABLE IF EXISTS mail_audit_results;
    DROP TABLE IF EXISTS tls_results;
    DROP TABLE IF EXISTS web_auth_findings;
    DROP TABLE IF EXISTS auth_findings;
    DROP TABLE IF EXISTS host_vuln_summary;
    DROP TABLE IF EXISTS service_inventory;
    DROP TABLE IF EXISTS ports_inventory;
    DROP TABLE IF EXISTS os_inventory;
    DROP TABLE IF EXISTS cms_joomla_details;
    DROP TABLE IF EXISTS cms_wp_details;
    DROP TABLE IF EXISTS cms_inventory;
    DROP TABLE IF EXISTS kv;
    DROP TABLE IF EXISTS hosts;
    DROP TABLE IF EXISTS events;
    DROP TABLE IF EXISTS modules;
    DROP TABLE IF EXISTS audits;
    VACUUM;
    """)

def insert_audit(conn: sqlite3.Connection, audit_id: str, status: str) -> None:
    conn.execute("INSERT OR REPLACE INTO audits(id, started_at, finished_at, status) VALUES(?, ?, ?, ?)",
                 (audit_id, datetime.utcnow().isoformat(), None, status))

def update_audit_status(conn: sqlite3.Connection, audit_id: str, status: str) -> None:
    conn.execute("UPDATE audits SET status=? WHERE id=?", (status, audit_id))

def finish_audit(conn: sqlite3.Connection, audit_id: str, status: str) -> None:
    conn.execute("UPDATE audits SET finished_at=?, status=? WHERE id=?", (datetime.utcnow().isoformat(), status, audit_id))

def upsert_module(conn: sqlite3.Connection, audit_id: str, name: str, state: str, started_at: Optional[str], finished_at: Optional[str], fatal: bool, message: Optional[str], data_json: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM modules WHERE audit_id=? AND name=?", (audit_id, name))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO modules(audit_id, name, state, started_at, finished_at, fatal, message, data) VALUES(?,?,?,?,?,?,?,?)",
                     (audit_id, name, state, started_at, finished_at, int(fatal), message, data_json))
    else:
        conn.execute("UPDATE modules SET state=?, started_at=?, finished_at=?, fatal=?, message=?, data=? WHERE id=?",
                     (state, started_at, finished_at, int(fatal), message, data_json, row[0]))

def add_event(conn: sqlite3.Connection, audit_id: str, level: str, module: Optional[str], message: str, data_json: Optional[str]) -> None:
    conn.execute("INSERT INTO events(audit_id, ts, level, module, message, data) VALUES(?,?,?,?,?,?)",
                 (audit_id, datetime.utcnow().isoformat(), level, module, message, data_json))

def upsert_host(conn: sqlite3.Connection, audit_id: str, ip: str, mac: Optional[str], vendor: Optional[str], hostname: Optional[str]) -> None:
    cur = conn.execute("SELECT id, first_seen FROM hosts WHERE audit_id=? AND ip=?", (audit_id, ip))
    row = cur.fetchone()
    now = datetime.utcnow().isoformat()
    if row is None:
        conn.execute(
            "INSERT INTO hosts(audit_id, ip, mac, vendor, hostname, first_seen, last_seen) VALUES(?,?,?,?,?,?,?)",
            (audit_id, ip, mac, vendor, hostname, now, now)
        )
    else:
        conn.execute(
            "UPDATE hosts SET mac=?, vendor=?, hostname=?, last_seen=? WHERE id=?",
            (mac, vendor, hostname, now, row[0])
        )

def list_hosts(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, mac, vendor, hostname FROM hosts WHERE audit_id=? ORDER BY ip", (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "mac": r[1], "vendor": r[2], "hostname": r[3]} for r in rows]

def kv_put(conn: sqlite3.Connection, audit_id: str, scope: str, k: str, v: str) -> None:
    cur = conn.execute("SELECT id FROM kv WHERE audit_id=? AND scope=? AND k=?", (audit_id, scope, k))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO kv(audit_id, scope, k, v) VALUES(?,?,?,?)", (audit_id, scope, k, v))
    else:
        conn.execute("UPDATE kv SET v=? WHERE id=?", (v, row[0]))

def kv_get(conn: sqlite3.Connection, audit_id: str, scope: str, k: str) -> Optional[str]:
    cur = conn.execute("SELECT v FROM kv WHERE audit_id=? AND scope=? AND k=?", (audit_id, scope, k))
    row = cur.fetchone()
    return row[0] if row else None

def upsert_os_inventory(conn: sqlite3.Connection, audit_id: str, ip: str, label: Optional[str], confidence: Optional[int], product: Optional[str], version: Optional[str], latest: Optional[str], obsolete: Optional[bool], eol: Optional[str], matched_by: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM os_inventory WHERE audit_id=? AND ip=?", (audit_id, ip))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO os_inventory(audit_id, ip, label, confidence, product, version, latest, obsolete, eol, matched_by) VALUES(?,?,?,?,?,?,?,?,?,?)",
                     (audit_id, ip, label, confidence if confidence is not None else None, product, version, latest, int(obsolete) if obsolete is not None else None, eol, matched_by))
    else:
        conn.execute("UPDATE os_inventory SET label=?, confidence=?, product=?, version=?, latest=?, obsolete=?, eol=?, matched_by=? WHERE id=?",
                     (label, confidence if confidence is not None else None, product, version, latest, int(obsolete) if obsolete is not None else None, eol, matched_by, row[0]))

def upsert_port_inventory(conn: sqlite3.Connection, audit_id: str, ip: str, proto: str, port: int, state: str) -> None:
    cur = conn.execute("SELECT id FROM ports_inventory WHERE audit_id=? AND ip=? AND proto=? AND port=?", (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO ports_inventory(audit_id, ip, proto, port, state) VALUES(?,?,?,?,?)",
                     (audit_id, ip, proto, port, state))
    else:
        conn.execute("UPDATE ports_inventory SET state=? WHERE id=?", (state, row[0]))

def list_ports_inventory(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, state FROM ports_inventory WHERE audit_id=? ORDER BY ip, proto, port", (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "state": r[3]} for r in rows]

def upsert_service_inventory(conn: sqlite3.Connection, audit_id: str, ip: str, proto: str, port: int, state: str, service_name: Optional[str], name_confidence: Optional[int], product: Optional[str], version: Optional[str], version_confidence: Optional[int], extrainfo: Optional[str], tunnel: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM service_inventory WHERE audit_id=? AND ip=? AND proto=? AND port=?", (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO service_inventory(audit_id, ip, proto, port, state, service_name, name_confidence, product, version, version_confidence, extrainfo, tunnel) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (audit_id, ip, proto, port, state, service_name, name_confidence if name_confidence is not None else None, product, version, version_confidence if version_confidence is not None else None, extrainfo, tunnel)
        )
    else:
        conn.execute(
            "UPDATE service_inventory SET state=?, service_name=?, name_confidence=?, product=?, version=?, version_confidence=?, extrainfo=?, tunnel=? WHERE id=?",
            (state, service_name, name_confidence if name_confidence is not None else None, product, version, version_confidence if version_confidence is not None else None, extrainfo, tunnel, row[0])
        )

def replace_host_vuln_summary(conn: sqlite3.Connection, audit_id: str, ip: str, items_json: str) -> None:
    cur = conn.execute("SELECT id FROM host_vuln_summary WHERE audit_id=? AND ip=?", (audit_id, ip))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO host_vuln_summary(audit_id, ip, items_json) VALUES(?,?,?)", (audit_id, ip, items_json))
    else:
        conn.execute("UPDATE host_vuln_summary SET items_json=? WHERE id=?", (items_json, row[0]))

def list_os_inventory(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, label, confidence, product, version, latest, obsolete, eol, matched_by FROM os_inventory WHERE audit_id=? ORDER BY ip", (audit_id,))
    rows = cur.fetchall()
    res = []
    for r in rows:
        res.append({"ip": r[0], "label": r[1], "confidence": r[2], "product": r[3], "version": r[4], "latest": r[5], "obsolete": r[6], "eol": r[7], "matched_by": r[8]})
    return res

def list_service_inventory(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, state, service_name, name_confidence, product, version, version_confidence, extrainfo, tunnel FROM service_inventory WHERE audit_id=? ORDER BY ip, proto, port", (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "state": r[3], "service_name": r[4], "name_confidence": r[5], "product": r[6], "version": r[7], "version_confidence": r[8], "extrainfo": r[9], "tunnel": r[10]} for r in rows]

def insert_auth_finding(conn: sqlite3.Connection, audit_id: str, ip: str, proto: str, port: int, service_name: str, username: Optional[str], password_masked: Optional[str], method: str, verified: bool, note: Optional[str]) -> None:
    conn.execute(
        "INSERT INTO auth_findings(audit_id, ip, proto, port, service_name, username, password_masked, method, verified, note) VALUES(?,?,?,?,?,?,?,?,?,?)",
        (audit_id, ip, proto, port, service_name, username, password_masked, method, int(bool(verified)), note)
    )

def list_auth_findings(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, service_name, username, password_masked, method, verified, note FROM auth_findings WHERE audit_id=? ORDER BY ip, proto, port", (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "service_name": r[3], "username": r[4], "password_masked": r[5], "method": r[6], "verified": r[7], "note": r[8]} for r in rows]

def add_web_auth_finding(conn: sqlite3.Connection, audit_id: str, ip: str, proto: str, port: int, url: str, endpoint: str, username: Optional[str], password: Optional[str], method: str, verified: bool, note: Optional[str], screenshot_path: Optional[str]) -> None:
    conn.execute(
        "INSERT INTO web_auth_findings(audit_id, ip, proto, port, url, endpoint, username, password, method, verified, note, screenshot_path) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (audit_id, ip, proto, port, url, endpoint, username, password, method, int(bool(verified)), note, screenshot_path)
    )

def list_web_auth_findings(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, url, endpoint, username, password, method, verified, note, screenshot_path FROM web_auth_findings WHERE audit_id=? ORDER BY ip, proto, port", (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "url": r[3], "endpoint": r[4], "username": r[5], "password": r[6], "method": r[7], "verified": r[8], "note": r[9], "screenshot_path": r[10]} for r in rows]

def upsert_cms_inventory(conn, audit_id: str, ip: str, proto: str, port: int, cms_name: str, version: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM cms_inventory WHERE audit_id=? AND ip=? AND proto=? AND port=?",
                       (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO cms_inventory(audit_id, ip, proto, port, cms_name, version) VALUES(?,?,?,?,?,?)",
                     (audit_id, ip, proto, port, cms_name, version))
    else:
        conn.execute("UPDATE cms_inventory SET cms_name=?, version=? WHERE id=?",
                     (cms_name, version, row[0]))

def list_cms_inventory(conn, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, cms_name, version FROM cms_inventory WHERE audit_id=? ORDER BY ip, proto, port",
                       (audit_id,))
    return [{"ip": r[0], "proto": r[1], "port": r[2], "cms_name": r[3], "version": r[4]} for r in cur.fetchall()]

def upsert_wp_details(conn, audit_id: str, ip: str, proto: str, port: int,
                      users_json: str, plugins_json: str, themes_json: str) -> None:
    cur = conn.execute("SELECT id FROM cms_wp_details WHERE audit_id=? AND ip=? AND proto=? AND port=?",
                       (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO cms_wp_details(audit_id, ip, proto, port, users_json, plugins_json, themes_json) VALUES(?,?,?,?,?,?,?)",
                     (audit_id, ip, proto, port, users_json, plugins_json, themes_json))
    else:
        conn.execute("UPDATE cms_wp_details SET users_json=?, plugins_json=?, themes_json=? WHERE id=?",
                     (users_json, plugins_json, themes_json, row[0]))

def list_wp_details(conn, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, users_json, plugins_json, themes_json FROM cms_wp_details WHERE audit_id=? ORDER BY ip, proto, port",
                       (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "users_json": r[3], "plugins_json": r[4], "themes_json": r[5]} for r in rows]

def upsert_joomla_details(conn, audit_id: str, ip: str, proto: str, port: int, debug_mode: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM cms_joomla_details WHERE audit_id=? AND ip=? AND proto=? AND port=?",
                       (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute("INSERT INTO cms_joomla_details(audit_id, ip, proto, port, debug_mode) VALUES(?,?,?,?,?)",
                     (audit_id, ip, proto, port, debug_mode))
    else:
        conn.execute("UPDATE cms_joomla_details SET debug_mode=? WHERE id=?",
                     (debug_mode, row[0]))

def list_joomla_details(conn, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, proto, port, debug_mode FROM cms_joomla_details WHERE audit_id=? ORDER BY ip, proto, port",
                       (audit_id,))
    rows = cur.fetchall()
    return [{"ip": r[0], "proto": r[1], "port": r[2], "debug_mode": r[3]} for r in rows]


def upsert_tls_result(conn, audit_id: str, ip: str, proto: str, port: int,
                      service_name: Optional[str], hostname: Optional[str],
                      uri: Optional[str], html_path: Optional[str],
                      score_protocol_support: Optional[int],
                      score_key_exchange: Optional[int],
                      score_cipher_strength: Optional[int]) -> None:
    cur = conn.execute("SELECT id FROM tls_results WHERE audit_id=? AND ip=? AND proto=? AND port=?",
                       (audit_id, ip, proto, port))
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO tls_results(audit_id, ip, proto, port, service_name, hostname, uri, html_path, "
            "score_protocol_support, score_key_exchange, score_cipher_strength) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (audit_id, ip, proto, port, service_name, hostname, uri, html_path,
             score_protocol_support, score_key_exchange, score_cipher_strength)
        )
    else:
        conn.execute(
            "UPDATE tls_results SET service_name=?, hostname=?, uri=?, html_path=?, "
            "score_protocol_support=?, score_key_exchange=?, score_cipher_strength=? WHERE id=?",
            (service_name, hostname, uri, html_path,
             score_protocol_support, score_key_exchange, score_cipher_strength, row[0])
        )

def list_tls_results(conn, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute(
        "SELECT ip, proto, port, service_name, hostname, uri, html_path, "
        "score_protocol_support, score_key_exchange, score_cipher_strength "
        "FROM tls_results WHERE audit_id=? ORDER BY ip, proto, port",
        (audit_id,)
    )
    rows = cur.fetchall()
    return [{
        "ip": r[0], "proto": r[1], "port": r[2], "service_name": r[3], "hostname": r[4],
        "uri": r[5], "html_path": r[6],
        "score_protocol_support": r[7], "score_key_exchange": r[8], "score_cipher_strength": r[9]
    } for r in rows]


def upsert_mail_audit_result(conn, audit_id: str, domain: str,
                             score_total: int, score_mx: int, score_spf: int,
                             score_dkim: int, score_dmarc: int, score_dnssec: int,
                             details_json: str) -> None:
    cur = conn.execute("SELECT id FROM mail_audit_results WHERE audit_id=? AND domain=?", (audit_id, domain))
    row = cur.fetchone()
    if row is None:
        conn.execute(
            "INSERT INTO mail_audit_results(audit_id, domain, score_total, score_mx, score_spf, score_dkim, score_dmarc, score_dnssec, details_json) VALUES(?,?,?,?,?,?,?,?,?)",
            (audit_id, domain, score_total, score_mx, score_spf, score_dkim, score_dmarc, score_dnssec, details_json)
        )
    else:
        conn.execute(
            "UPDATE mail_audit_results SET score_total=?, score_mx=?, score_spf=?, score_dkim=?, score_dmarc=?, score_dnssec=?, details_json=? WHERE id=?",
            (score_total, score_mx, score_spf, score_dkim, score_dmarc, score_dnssec, details_json, row[0])
        )

def list_mail_audit_results(conn, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT domain, score_total, score_mx, score_spf, score_dkim, score_dmarc, score_dnssec, details_json FROM mail_audit_results WHERE audit_id=? ORDER BY domain", (audit_id,))
    rows = cur.fetchall()
    out = []
    for r in rows:
        out.append({
            "domain": r[0],
            "score_total": r[1],
            "score_mx": r[2],
            "score_spf": r[3],
            "score_dkim": r[4],
            "score_dmarc": r[5],
            "score_dnssec": r[6],
            "details_json": r[7],
        })
    return out
