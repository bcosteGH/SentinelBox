from sentinelbox.runner import AuditRunner
from sentinelbox.config import load_config
from sentinelbox.modules.host_discovery_nmap import HostDiscoveryNmap
from sentinelbox.modules.os_obsolescence import OSObsolescence

def main():
    cfg = load_config()
    runner = AuditRunner(cfg.workdir, cfg.db_path)
    modules = [HostDiscoveryNmap(), OSObsolescence()]
    ctx = {
        "interface": cfg.interface,
        "target_cidr": cfg.target_cidr,
        "report_dir": str(cfg.report.output_dir),
        "reset_previous_runs": cfg.reset_previous_runs,
        "reset_database": cfg.reset_database,
        "log_level": cfg.logging.level,
        "discovery": {
            "method": cfg.discovery.method,
            "nmap_args": cfg.discovery.nmap_args,
            "nmap_timing": cfg.discovery.nmap_timing,
            "nmap_min_rate": cfg.discovery.nmap_min_rate,
            "nmap_max_rate": cfg.discovery.nmap_max_rate,
            "large_hosts_threshold": cfg.discovery.large_hosts_threshold,
            "arp_fallback_timeout_seconds": cfg.discovery.arp_fallback_timeout_seconds,
            "resolve_hostnames": cfg.discovery.resolve_hostnames,
            "resolver_timeout_ms": cfg.discovery.resolver_timeout_ms,
            "resolver_threads": cfg.discovery.resolver_threads,
            "enable_avahi": cfg.discovery.enable_avahi,
        },
        "os_obsolescence": {
            "nmap_timing": cfg.os_detect.nmap_timing,
            "host_timeout_seconds": cfg.os_detect.host_timeout_seconds,
            "batch_size": cfg.os_detect.batch_size,
            "max_retries": cfg.os_detect.max_retries,
            "overall_timeout_seconds": cfg.os_detect.overall_timeout_seconds,
            "oscan_guess": cfg.os_detect.oscan_guess,
            "oscan_limit": cfg.os_detect.oscan_limit,
            "use_pn": cfg.os_detect.use_pn,
            "rules_path": str(cfg.os_detect.rules_path),
            "enable_rules_fallback": cfg.os_detect.enable_rules_fallback,
            "strict_unambiguous_only": cfg.os_detect.strict_unambiguous_only,
        },
    }
    audit_id = runner.run_audit(modules, ctx)
    print(audit_id)

if __name__ == "__main__":
    main()
