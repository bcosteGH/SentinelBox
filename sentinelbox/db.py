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
    DROP TABLE IF EXISTS auth_findings;
    DROP TABLE IF EXISTS host_vuln_summary;
    DROP TABLE IF EXISTS service_inventory;
    DROP TABLE IF EXISTS ports_inventory;
    DROP TABLE IF EXISTS os_inventory;
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

