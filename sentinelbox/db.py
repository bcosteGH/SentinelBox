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
"""

OS_INVENTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS os_inventory(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  audit_id TEXT,
  ip TEXT,
  label TEXT,
  confidence INTEGER,
  obsolete INTEGER,
  obsolescence TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_osinv_audit_ip ON os_inventory(audit_id, ip);
"""

def open_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.executescript(OS_INVENTORY_SCHEMA)
    _ensure_os_inventory_shape(conn)

def _ensure_os_inventory_shape(conn: sqlite3.Connection) -> None:
    cur = conn.execute("PRAGMA table_info(os_inventory)")
    cols = {r[1] for r in cur.fetchall()}
    expected = {"id", "audit_id", "ip", "label", "confidence", "obsolete", "obsolescence"}
    if cols != expected:
        conn.execute("DROP TABLE IF EXISTS os_inventory")
        conn.executescript(OS_INVENTORY_SCHEMA)

def purge_db(conn: sqlite3.Connection) -> None:
    conn.executescript("DELETE FROM events; DELETE FROM modules; DELETE FROM audits; DELETE FROM hosts; DELETE FROM kv; DELETE FROM os_inventory; VACUUM;")

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

def upsert_os_inventory(conn: sqlite3.Connection, audit_id: str, ip: str, label: Optional[str], confidence: Optional[int], obsolete: Optional[bool], obsolescence_json: Optional[str]) -> None:
    cur = conn.execute("SELECT id FROM os_inventory WHERE audit_id=? AND ip=?", (audit_id, ip))
    row = cur.fetchone()
    obs_int = int(obsolete) if isinstance(obsolete, bool) else None
    if row is None:
        conn.execute(
            "INSERT INTO os_inventory(audit_id, ip, label, confidence, obsolete, obsolescence) VALUES(?,?,?,?,?,?)",
            (audit_id, ip, label, confidence if confidence is not None else None, obs_int, obsolescence_json)
        )
    else:
        conn.execute(
            "UPDATE os_inventory SET label=?, confidence=?, obsolete=?, obsolescence=? WHERE id=?",
            (label, confidence if confidence is not None else None, obs_int, obsolescence_json, row[0])
        )

def list_os_inventory(conn: sqlite3.Connection, audit_id: str) -> list[dict[str, Any]]:
    cur = conn.execute("SELECT ip, label, confidence, obsolete, obsolescence FROM os_inventory WHERE audit_id=? ORDER BY ip", (audit_id,))
    rows = cur.fetchall()
    res = []
    for r in rows:
        res.append({
            "ip": r[0],
            "label": r[1],
            "confidence": r[2],
            "obsolete": bool(r[3]) if r[3] is not None else None,
            "obsolescence": r[4]
        })
    return res
