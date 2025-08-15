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
class OSDetect:
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
    os_detect: OSDetect

def _get(d: dict[str, Any], key: str, default: Any) -> Any:
    return d[key] if key in d else default

def _load_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    with path.open("rb") as f:
        return tomllib.load(f)

def load_config(path: Optional[Path] = None) -> 'Config':
    cfg_path = Path(os.getenv("SB_CONFIG", "sentinelbox.toml")) if path is None else path
    data = _load_toml(cfg_path)
    core = data.get("core", {})
    report = data.get("report", {})
    disc = data.get("discovery", {})
    logsec = data.get("logging", {})
    osobs = data.get("os_obsolescence", {})

    interface = str(_get(core, "interface", "eth0"))
    workdir = Path(str(_get(core, "workdir", "./runs")))
    db_path = Path(str(_get(core, "db_path", "./state.sqlite")))
    target_cidr_raw = str(_get(core, "target_cidr", ""))
    target_cidr = target_cidr_raw if target_cidr_raw else None
    reset_previous_runs = bool(_get(core, "reset_previous_runs", True))
    reset_database = bool(_get(core, "reset_database", True))

    rep = Report(output_dir=Path(str(_get(report, "output_dir", "./reports"))))
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

    osdet = OSDetect(
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
        os_detect=osdet,
    )
