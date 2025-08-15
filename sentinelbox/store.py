from pathlib import Path
from typing import Any, Optional
from .db import upsert_host, list_hosts, kv_put, kv_get, upsert_os_inventory, list_os_inventory

class Store:
    def __init__(self, conn, audit_id: str, audit_dir: Path):
        self.conn = conn
        self.audit_id = audit_id
        self.audit_dir = audit_dir

    def set_cidr(self, cidr: str) -> None:
        kv_put(self.conn, self.audit_id, "network", "cidr", cidr)

    def get_cidr(self) -> Optional[str]:
        return kv_get(self.conn, self.audit_id, "network", "cidr")

    def put_host(self, ip: str, mac: Optional[str], vendor: Optional[str], hostname: Optional[str]) -> None:
        upsert_host(self.conn, self.audit_id, ip, mac, vendor, hostname)

    def list_hosts(self) -> list[dict[str, Any]]:
        return list_hosts(self.conn, self.audit_id)

    def put_os_info(self, ip: str, label: Optional[str], confidence: Optional[int], obsolete: Optional[bool], obsolescence: Optional[dict[str, Any]]) -> None:
        payload = None
        if obsolescence is not None:
            import json
            payload = json.dumps(obsolescence, ensure_ascii=False, separators=(",", ":"))
        upsert_os_inventory(self.conn, self.audit_id, ip, label, confidence, obsolete, payload)

    def list_os_info(self) -> list[dict[str, Any]]:
        items = list_os_inventory(self.conn, self.audit_id)
        out = []
        import json
        for it in items:
            ob = json.loads(it["obsolescence"]) if it["obsolescence"] else None
            out.append({
                "ip": it["ip"],
                "label": it["label"],
                "confidence": it["confidence"],
                "obsolete": it["obsolete"],
                "obsolescence": ob
            })
        return out
