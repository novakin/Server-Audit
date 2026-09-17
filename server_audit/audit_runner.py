"""Explicit audit orchestration. Collectors return evidence and findings."""

import datetime
import os
import platform

from server_audit.collectors import network_audit
from server_audit.collectors import ssh_audit
from server_audit.collectors import system_audit
from server_audit.collectors.accounts import collect as collect_accounts
from server_audit.command_runner import run
from server_audit.collectors.docker_audit import collect as collect_docker
from server_audit.collectors.env_files import collect as collect_env_files
from server_audit.collectors.git_secrets import SCAN_SECONDS, collect as collect_git_secrets
from server_audit.collectors.scheduled_tasks import collect as collect_scheduled_tasks


def summarize(checks):
    """Derive findings without treating absent optional backends as failures."""
    findings = []
    optional = {"ufw", "nftables", "iptables_ipv4", "iptables_ipv6", "docker"}
    for name, check in checks.items():
        if check["status"] == "error" or (check["status"] == "unavailable" and name not in optional):
            detail = check.get("detail") or check.get("output") or "check unavailable"
            findings.append({"level": "UNKNOWN", "message": f"{name}: {detail}"})
    findings.extend(network_audit.firewall_findings(checks))
    findings.extend(system_audit.maintenance_findings(checks))
    return findings


def audit(connection=None, ssh_config=None, env_roots=None, git_roots=None, git_scan_seconds=SCAN_SECONDS):
    report = {
        "schema_version": 1,
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "host": platform.node(), "findings": [], "checks": {},
        "limitations": [
            "No external scan: bindings and firewall rules do not prove internet reachability. Check provider firewalls, NAT, IPv4 and IPv6 from an independent host.",
            "SSH settings describe the selected on-disk configuration (sshd default unless --ssh-config is supplied), not necessarily the running daemon or its command-line overrides. Match rules require --ssh-context.",
            "Port inventory covers the current network namespace. Docker published ports are listed separately; other container runtimes and namespaces are not covered.",
            "Package results use existing APT metadata; this script does not refresh it or classify every update as a security update.",
            "This is a configuration inventory and focused audit, not vulnerability scanning or proof that the server is secure.",
        ],
    }
    checks = report["checks"]
    findings = report["findings"]
    if os.geteuid() != 0:
        findings.append({"level": "UNKNOWN", "message": "Not running as root: SSH configuration, firewall and process ownership checks may be incomplete."})
    checks["os"] = system_audit.collect_os()
    checks["ssh"], ssh_reviews = ssh_audit.collect(run, connection, ssh_config)
    findings.extend(ssh_reviews)
    checks["ports"], port_findings = network_audit.collect_ports(run)
    findings.extend(port_findings)
    checks.update(network_audit.collect_firewalls(run))
    checks.update(system_audit.collect_services_and_updates(run))
    checks["docker"], docker_findings = collect_docker(run)
    findings.extend(docker_findings)
    checks["apt_metadata"] = system_audit.collect_apt_metadata()
    checks["reboot_required"], reboot_findings = system_audit.collect_reboot_state()
    findings.extend(reboot_findings)
    try:
        checks["accounts"], account_findings = collect_accounts(run, checks["ssh"].get("output", "") if checks["ssh"]["status"] == "ok" else "")
        findings.extend(account_findings)
    except (OSError, KeyError) as error:
        checks["accounts"] = {"status": "error", "detail": str(error)}
    checks["environment_files"], env_findings = collect_env_files(env_roots, run, checks)
    findings.extend(env_findings)
    checks["git_secrets"], git_findings = collect_git_secrets(git_roots, scan_seconds=git_scan_seconds)
    findings.extend(git_findings)
    checks["scheduled_tasks"], scheduled_findings = collect_scheduled_tasks(run)
    findings.extend(scheduled_findings)
    findings.extend(summarize(checks))
    report["summary"] = {level: sum(finding["level"] == level for finding in findings) for level in ("REVIEW", "UNKNOWN")}
    return report
