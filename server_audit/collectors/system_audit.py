"""Operating system, service state and package maintenance evidence."""

import datetime
import platform
from pathlib import Path


def collect_os():
    os_release = Path("/etc/os-release")
    try:
        output = os_release.read_text()
    except FileNotFoundError:
        output = platform.platform()
    except (OSError, UnicodeError) as error:
        return {"status": "error", "detail": str(error)}
    return {"status": "ok", "output": output}


def collect_services_and_updates(run):
    return {name: run(command) for name, command in {
        "running_services": ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--plain"],
        "failed_services": ["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--no-pager", "--plain"],
        "available_updates": ["apt", "list", "--upgradable"],
    }.items()}


def collect_apt_metadata():
    cache = Path("/var/lib/apt/lists")
    try:
        times = [entry.stat().st_mtime for entry in cache.iterdir() if entry.is_file() and "Packages" in entry.name]
        check = {
            "status": "ok" if times else "unavailable",
            "output": "Oldest package index timestamp: " + datetime.datetime.fromtimestamp(min(times), datetime.timezone.utc).isoformat() if times else "No package indexes found.",
        }
    except OSError as error:
        check = {"status": "error", "detail": str(error)}
    return check


def collect_reboot_state():
    marker = Path("/var/run/reboot-required")
    try:
        # Unlike exists(), stat() does not suppress inspection errors.
        marker.stat()
    except FileNotFoundError:
        required = False
    except OSError as error:
        return {"status": "error", "detail": f"Could not inspect {marker}: {error}"}, []
    else:
        required = True
    check = {"status": "ok", "output": str(required)}
    findings = []
    if required:
        findings.append({"level": "REVIEW", "message": "System reports a reboot is required."})
    return check, findings


def maintenance_findings(checks):
    findings = []
    updates = checks.get("available_updates", {})
    if updates.get("status") == "ok":
        packages = [line.split("/", 1)[0] for line in updates.get("output", "").splitlines() if "[upgradable from:" in line]
        updates["packages"] = packages
        if packages:
            findings.append({"level": "REVIEW", "message": f"{len(packages)} package updates available in cached APT metadata. Review and apply relevant updates; security classification is not established."})
    failed = checks.get("failed_services", {})
    if failed.get("status") == "ok":
        units = [line.split()[0] for line in failed.get("output", "").splitlines() if line.strip()]
        failed["units"] = units
        if units:
            findings.append({"level": "REVIEW", "message": "Failed services: " + ", ".join(units)})
    return findings
