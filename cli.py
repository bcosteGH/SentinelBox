from sentinelbox.runner import AuditRunner
from sentinelbox.config import load_config
from sentinelbox.modules.host_discovery_nmap import HostDiscoveryNmap
from sentinelbox.modules.port_scan import PortScanNmap
from sentinelbox.modules.os_obsolescence import OSObsolescence
from sentinelbox.modules.service_fingerprint_nmap import ServiceFingerprintNmap
from sentinelbox.modules.auth_bruteforce import AuthBruteforce  # NEW

def main():
    cfg = load_config()
    runner = AuditRunner(cfg.workdir, cfg.db_path)

    modules = [
        HostDiscoveryNmap(),
        PortScanNmap(),
        ServiceFingerprintNmap(),
        AuthBruteforce(),          # NEW
        OSObsolescence(),
    ]

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

        "port_scan": {
            "nmap_timing": cfg.port_scan.nmap_timing,
            "tcp_top_ports": cfg.port_scan.tcp_top_ports,
            "tcp_min_rate": cfg.port_scan.tcp_min_rate,
            "tcp_max_rate": cfg.port_scan.tcp_max_rate,
            "host_timeout_seconds": cfg.port_scan.host_timeout_seconds,
            "batch_size": cfg.port_scan.batch_size,
            "max_retries": cfg.port_scan.max_retries,
            "overall_timeout_seconds": cfg.port_scan.overall_timeout_seconds,
            "use_pn": cfg.port_scan.use_pn,
            "udp_ports": cfg.port_scan.udp_ports,
        },

        "service_fingerprint": {
            "nmap_timing": cfg.service_fingerprint.nmap_timing,
            "host_timeout_seconds": cfg.service_fingerprint.host_timeout_seconds,
            "max_retries": cfg.service_fingerprint.max_retries,
            "min_rate": cfg.service_fingerprint.min_rate,
            "max_rate": cfg.service_fingerprint.max_rate,
            "version_intensity": cfg.service_fingerprint.version_intensity,
            "enable_vulners": cfg.service_fingerprint.enable_vulners,
            "vulners_mincvss": cfg.service_fingerprint.vulners_mincvss,
            "scripts": cfg.service_fingerprint.scripts,
        },
        
        "auth_bruteforce": {
            "host_timeout_seconds": cfg.auth_bruteforce.host_timeout_seconds,
            "per_target_max_attempts": cfg.auth_bruteforce.per_target_max_attempts,
            "delay_ms": cfg.auth_bruteforce.delay_ms,
            "enable_ssh": cfg.auth_bruteforce.enable_ssh,
            "enable_ftp": cfg.auth_bruteforce.enable_ftp,
            "enable_telnet": cfg.auth_bruteforce.enable_telnet,
            "enable_snmp": cfg.auth_bruteforce.enable_snmp,
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
