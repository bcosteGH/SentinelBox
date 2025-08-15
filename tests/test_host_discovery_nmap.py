from pathlib import Path
import json
import subprocess
import pytest

from sentinelbox.modules.host_discovery_nmap import HostDiscoveryNmap

class DummyPS:
    def __init__(self, hosts):
        self._hosts = hosts
    def all_hosts(self):
        return list(self._hosts.keys())
    def __getitem__(self, k):
        return self._hosts[k]
    def scan(self, hosts=None, arguments=None):
        return

class DummyNmapModule:
    class PortScannerError(Exception):
        pass
    def __init__(self, ps):
        self._ps = ps
    def PortScanner(self):
        return self._ps

def run_module(tmp_path: Path, context_overrides=None):
    base = tmp_path / "runs"
    base.mkdir()
    audit_dir = base / "aid"
    audit_dir.mkdir()
    ctx = {
        "audit_dir": str(audit_dir),
        "interface": "enp0s3",
        "target_cidr": None,
        "report_dir": str(tmp_path / "reports"),
        "discovery": {
            "method": "nmap",
            "nmap_args": "-sn",
            "nmap_timing": "T3",
            "nmap_min_rate": 0,
            "nmap_max_rate": 0,
            "large_hosts_threshold": 4096,
            "arp_fallback_timeout_seconds": 300,
            "resolve_hostnames": True,
            "resolver_timeout_ms": 300,
            "resolver_threads": 8,
            "enable_avahi": False,
        },
    }
    if context_overrides:
        ctx.update(context_overrides)
    m = HostDiscoveryNmap()
    ok, fatal, msg, data = m.run(ctx)
    return ok, fatal, msg, data, audit_dir

def test_no_cidr(monkeypatch, tmp_path):
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.is_interface_up", lambda iface: True)
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.get_interface_cidr", lambda iface: None)
    ok, fatal, msg, data, _ = run_module(tmp_path)
    assert ok is False
    assert fatal is True
    assert msg == "no_cidr"

def test_interface_down(monkeypatch, tmp_path):
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.get_interface_cidr", lambda iface: "192.168.1.10/24")
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.is_interface_up", lambda iface: False)
    ok, fatal, msg, data, _ = run_module(tmp_path)
    assert ok is False
    assert fatal is True
    assert msg == "interface_down"

def test_large_network_timeout(monkeypatch, tmp_path):
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.get_interface_cidr", lambda iface: "10.0.0.1/8")
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.is_interface_up", lambda iface: True)
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.count_hosts", lambda cidr: 200000)
    def fake_run(cmd, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd="nmap", timeout=timeout)
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.subprocess.run", fake_run)
    ok, fatal, msg, data, audit_dir = run_module(tmp_path)
    assert ok is True
    assert fatal is False
    assert msg == "partial_timeout"
    assert data["truncated"] is True
    assert (audit_dir / "data" / "hosts.json").exists()

def test_python_nmap_normal_path(monkeypatch, tmp_path):
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.get_interface_cidr", lambda iface: "192.168.1.10/24")
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.is_interface_up", lambda iface: True)
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.count_hosts", lambda cidr: 128)
    hosts = {
        "192.168.1.1": {"status": {"state": "up"}, "addresses": {"mac": "aa:bb:cc:dd:ee:ff"}, "vendor": {"aa:bb:cc:dd:ee:ff": "TestVendor"}, "hostnames": [{"name": "gw.local"}]},
        "192.168.1.20": {"status": {"state": "up"}, "addresses": {}, "vendor": {}, "hostnames": []},
    }
    dummy_ps = DummyPS(hosts)
    dummy_nmap = DummyNmapModule(dummy_ps)
    monkeypatch.setattr("sentinelbox.modules.host_discovery_nmap.nmap", dummy_nmap)
    ok, fatal, msg, data, audit_dir = run_module(tmp_path)
    assert ok is True
    assert fatal is False
    assert msg == "ok"
    j = json.loads((audit_dir / "data" / "hosts.json").read_text())
    ips = [h["ip"] for h in j["hosts"]]
    assert "192.168.1.1" in ips and "192.168.1.20" in ips
