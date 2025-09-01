from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Any
import os
import tomllib

@dataclass
class Report:
    output_dir: Path

@dataclass
class Discovery:
    method: str
    nmap_args: str
    nmap_timing: str
    nmap_min_rate: int
    nmap_max_rate: int
    large_hosts_threshold: int
    arp_fallback_timeout_seconds: int
    resolve_hostnames: bool
    resolver_timeout_ms: int
    resolver_threads: int
    enable_avahi: bool

@dataclass
class LoggingCfg:
    level: str

@dataclass
class OSObsolescence:
    nmap_timing: str
    host_timeout_seconds: int
    batch_size: int
    max_retries: int
    overall_timeout_seconds: int
    oscan_guess: bool
    oscan_limit: bool
    use_pn: bool
    rules_path: Path
    enable_rules_fallback: bool
    strict_unambiguous_only: bool

@dataclass
class PortScan:
    nmap_timing: str
    tcp_top_ports: int
    tcp_min_rate: int
    tcp_max_rate: int
    host_timeout_seconds: int
    batch_size: int
    max_retries: int
    overall_timeout_seconds: int
    use_pn: bool
    udp_ports: list[int]

@dataclass
class ServiceFingerprint:
    nmap_timing: str
    host_timeout_seconds: int
    max_retries: int
    min_rate: int
    max_rate: int
    version_intensity: int
    enable_vulners: bool
    vulners_mincvss: float
    scripts: str

@dataclass
class AuthBruteforce:
    host_timeout_seconds: int
    per_target_max_attempts: int
    delay_ms: int
    enable_ssh: bool
    enable_ftp: bool
    enable_telnet: bool
    enable_snmp: bool

@dataclass
class CMSeekCfg:
    script_path: str
    timeout_seconds: int
    clear_between_scans: bool
    follow_redirect: bool
    random_agent: bool

@dataclass
class TLSScanCfg:
    script_path: str
    timeout_seconds: int
    prefer_hostname: bool
    enabled_services: list[str]
    connect_timeout: int
    openssl_timeout: int


@dataclass
class MailAuditCfg:
    domains: list[str]
    dkim_selector_patterns_path: Path
    dns_timeout_seconds: float
    max_spf_lookups: int
    problem_catalog_path: Optional[Path]

@dataclass
class Config:
    interface: str
    workdir: Path
    db_path: Path
    target_cidr: Optional[str]
    reset_previous_runs: bool
    reset_database: bool
    report: Report
    discovery: Discovery
    logging: LoggingCfg
    os_obsolescence: OSObsolescence
    port_scan: PortScan
    service_fingerprint: ServiceFingerprint
    auth_bruteforce: AuthBruteforce
    cmseek: CMSeekCfg
    tls_scan: TLSScanCfg
    mail_audit: MailAuditCfg

def _get(d: dict[str, Any], key: str, default: Any) -> Any:
    return d[key] if key in d else default

def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)

def _as_str_list(val: Any, default: list[str]) -> list[str]:
    if isinstance(val, list):
        out = []
        for x in val:
            if x is None:
                continue
            if isinstance(x, (int, float)):
                out.append(str(x))
            else:
                out.append(str(x).strip())
        return [x for x in out if x]
    if isinstance(val, str):
        parts = [x.strip() for x in val.split(",")]
        return [x for x in parts if x]
    return list(default)

def _as_int_map(val: Any, default: dict[str, int]) -> dict[str, int]:
    if isinstance(val, dict):
        out: dict[str, int] = {}
        for k, v in val.items():
            try:
                out[str(k)] = int(v)
            except Exception:
                continue
        return out if out else dict(default)
    if isinstance(val, list):
        out: dict[str, int] = {}
        for item in val:
            if isinstance(item, dict):
                for k, v in item.items():
                    try:
                        out[str(k)] = int(v)
                    except Exception:
                        continue
            elif isinstance(item, str):
                s = item.strip()
                if "=" in s:
                    k, v = s.split("=", 1)
                    try:
                        out[k.strip()] = int(v.strip())
                    except Exception:
                        continue
        return out if out else dict(default)
    if isinstance(val, str):
        out: dict[str, int] = {}
        for chunk in val.split(","):
            s = chunk.strip()
            if not s or "=" not in s:
                continue
            k, v = s.split("=", 1)
            try:
                out[k.strip()] = int(v.strip())
            except Exception:
                continue
        return out if out else dict(default)
    return dict(default)

def load_config(path: Optional[Path] = None) -> "Config":
    cfg_path = Path(os.getenv("SB_CONFIG", "sentinelbox.toml")) if path is None else path
    data = _load_toml(cfg_path)

    core = data.get("core", {})
    report = data.get("report", {})
    disc = data.get("discovery", {})
    logsec = data.get("logging", {})
    osobs = data.get("os_obsolescence", {})
    pscan = data.get("port_scan", {})
    svc = data.get("service_fingerprint", {})
    abf = data.get("auth_bruteforce", {})
    cm = data.get("cmseek", {})
    tls = data.get("tls_scan", {})
    mailsec = data.get("mail_audit", {})

    interface = str(_get(core, "interface", "eth0"))
    workdir = Path(_get(core, "workdir", "./runs"))
    db_path = Path(_get(core, "db_path", "./state.sqlite"))
    target_cidr_raw = _get(core, "target_cidr", "")
    target_cidr = target_cidr_raw if target_cidr_raw else None
    reset_previous_runs = bool(_get(core, "reset_previous_runs", True))
    reset_database = bool(_get(core, "reset_database", True))

    rep = Report(output_dir=Path(_get(report, "output_dir", "./reports")))
    dis = Discovery(
        method=str(_get(disc, "method", "nmap")),
        nmap_args=str(_get(disc, "nmap_args", "-sn")),
        nmap_timing=str(_get(disc, "nmap_timing", "T3")),
        nmap_min_rate=int(_get(disc, "nmap_min_rate", 0)),
        nmap_max_rate=int(_get(disc, "nmap_max_rate", 0)),
        large_hosts_threshold=int(_get(disc, "large_hosts_threshold", 4096)),
        arp_fallback_timeout_seconds=int(_get(disc, "arp_fallback_timeout_seconds", 300)),
        resolve_hostnames=bool(_get(disc, "resolve_hostnames", True)),
        resolver_timeout_ms=int(_get(disc, "resolver_timeout_ms", 300)),
        resolver_threads=int(_get(disc, "resolver_threads", 32)),
        enable_avahi=bool(_get(disc, "enable_avahi", True)),
    )
    logcfg = LoggingCfg(level=str(_get(logsec, "level", "DEBUG")).upper())

    osdet = OSObsolescence(
        nmap_timing=str(_get(osobs, "nmap_timing", "T3")),
        host_timeout_seconds=int(_get(osobs, "host_timeout_seconds", 45)),
        batch_size=int(_get(osobs, "batch_size", 16)),
        max_retries=int(_get(osobs, "max_retries", 1)),
        overall_timeout_seconds=int(_get(osobs, "overall_timeout_seconds", 240)),
        oscan_guess=bool(_get(osobs, "oscan_guess", True)),
        oscan_limit=bool(_get(osobs, "oscan_limit", False)),
        use_pn=bool(_get(osobs, "use_pn", True)),
        rules_path=Path(str(_get(osobs, "rules_path", "data/nmap_os_comments.jsonl"))),
        enable_rules_fallback=bool(_get(osobs, "enable_rules_fallback", True)),
        strict_unambiguous_only=bool(_get(osobs, "strict_unambiguous_only", True)),
    )

    psc = PortScan(
        nmap_timing=str(_get(pscan, "nmap_timing", "T4")),
        tcp_top_ports=int(_get(pscan, "tcp_top_ports", 1000)),
        tcp_min_rate=int(_get(pscan, "tcp_min_rate", 50)),
        tcp_max_rate=int(_get(pscan, "tcp_max_rate", 150)),
        host_timeout_seconds=int(_get(pscan, "host_timeout_seconds", 180)),
        batch_size=int(_get(pscan, "batch_size", 16)),
        max_retries=int(_get(pscan, "max_retries", 1)),
        overall_timeout_seconds=int(_get(pscan, "overall_timeout_seconds", 900)),
        use_pn=bool(_get(pscan, "use_pn", True)),
        udp_ports=list(_get(pscan, "udp_ports", [53,67,69,123,137,138,161,162,500,514,520,631,1434,1701,1900,4500,5353])),
    )

    service_fp = ServiceFingerprint(
        nmap_timing=str(_get(svc, "nmap_timing", "T4")),
        host_timeout_seconds=int(_get(svc, "host_timeout_seconds", 180)),
        max_retries=int(_get(svc, "max_retries", 1)),
        min_rate=int(_get(svc, "min_rate", 50)),
        max_rate=int(_get(svc, "max_rate", 150)),
        version_intensity=int(_get(svc, "version_intensity", 2)),
        enable_vulners=bool(_get(svc, "enable_vulners", True)),
        vulners_mincvss=float(_get(svc, "vulners_mincvss", 7)),
        scripts=str(_get(svc, "scripts", "")),
    )

    auth_bf = AuthBruteforce(
        host_timeout_seconds=int(_get(abf, "host_timeout_seconds", 20)),
        per_target_max_attempts=int(_get(abf, "per_target_max_attempts", 6)),
        delay_ms=int(_get(abf, "delay_ms", 200)),
        enable_ssh=bool(_get(abf, "enable_ssh", True)),
        enable_ftp=bool(_get(abf, "enable_ftp", True)),
        enable_telnet=bool(_get(abf, "enable_telnet", True)),
        enable_snmp=bool(_get(abf, "enable_snmp", True)),
    )

    cmseek_cfg = CMSeekCfg(
        script_path=str(_get(cm, "script_path", "outils/cmseek/cmseek.py")),
        timeout_seconds=int(_get(cm, "timeout_seconds", 180)),
        clear_between_scans=bool(_get(cm, "clear_between_scans", True)),
        follow_redirect=bool(_get(cm, "follow_redirect", True)),
        random_agent=bool(_get(cm, "random_agent", True)),
    )

    tls_cfg = TLSScanCfg(
        script_path=str(_get(tls, "script_path", "outils/testssl.sh/testssl.sh")),
        timeout_seconds=int(_get(tls, "timeout_seconds", 60)),
        prefer_hostname=bool(_get(tls, "prefer_hostname", True)),
        enabled_services=list(_get(tls, "enabled_services", ["https","ftps","imaps","pop3s","smtps","ldaps","ircs","nntps","xmpps"])),
        connect_timeout=int(_get(tls, "connect_timeout", 2)),
        openssl_timeout=int(_get(tls, "openssl_timeout", 2)),
    )

    mail_cfg = MailAuditCfg(
        domains=list(_get(mailsec, "domains", [])),
        dkim_selector_patterns_path=Path(str(_get(mailsec, "dkim_selector_patterns_path", "data/dkim_selector_patterns.txt"))),
        dns_timeout_seconds=float(_get(mailsec, "dns_timeout_seconds", 3)),
        max_spf_lookups=int(_get(mailsec, "max_spf_lookups", 10)),
        problem_catalog_path=Path(str(_get(mailsec, "problem_catalog_path", ""))) if _get(mailsec, "problem_catalog_path", "") else None,
    )

    return Config(
        interface=interface,
        workdir=workdir,
        db_path=db_path,
        target_cidr=target_cidr,
        reset_previous_runs=reset_previous_runs,
        reset_database=reset_database,
        report=rep,
        discovery=dis,
        logging=logcfg,
        os_obsolescence=osdet,
        port_scan=psc,
        service_fingerprint=service_fp,
        auth_bruteforce=auth_bf,
        cmseek=cmseek_cfg,
        tls_scan=tls_cfg,
        mail_audit=mail_cfg
    )
