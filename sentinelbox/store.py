from pathlib import Path
from typing import Any, Optional
from .db import upsert_host, list_hosts, kv_put, kv_get, upsert_os_inventory, list_os_inventory, upsert_service_inventory, replace_host_vuln_summary, upsert_port_inventory, list_ports_inventory, list_service_inventory, insert_auth_finding, list_auth_findings

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
        upsert_os_inventory(self.conn, self.audit_id, ip, label, confidence, None, None, None, obsolete, obsolescence.get("last_review") if obsolescence else None, "rule" if obsolescence else None)

    def list_os_info(self) -> list[dict[str, Any]]:
        return list_os_inventory(self.conn, self.audit_id)

    def put_service_info(self, ip: str, proto: str, port: int, state: str, service_name: Optional[str], name_confidence: Optional[int], product: Optional[str], version: Optional[str], version_confidence: Optional[int], extrainfo: Optional[str], tunnel: Optional[str]) -> None:
        upsert_service_inventory(self.conn, self.audit_id, ip, proto, port, state, service_name, name_confidence, product, version, version_confidence, extrainfo, tunnel)

    def list_services(self) -> list[dict[str, Any]]:
        return list_service_inventory(self.conn, self.audit_id)

    def replace_host_vuln_summary(self, ip: str, items_json: str) -> None:
        replace_host_vuln_summary(self.conn, self.audit_id, ip, items_json)

    def put_port(self, ip: str, proto: str, port: int, state: str) -> None:
        upsert_port_inventory(self.conn, self.audit_id, ip, proto, port, state)

    def list_ports(self) -> list[dict[str, Any]]:
        return list_ports_inventory(self.conn, self.audit_id)

    def put_auth_finding(self, ip: str, proto: str, port: int, service_name: str, username: Optional[str], password_masked: Optional[str], method: str, verified: bool, note: Optional[str]) -> None:
        insert_auth_finding(self.conn, self.audit_id, ip, proto, port, service_name, username, password_masked, method, verified, note)

    def list_auth_findings(self) -> list[dict[str, Any]]:
        return list_auth_findings(self.conn, self.audit_id)
