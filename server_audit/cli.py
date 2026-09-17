#!/usr/bin/env python3
"""Read-only Ubuntu/Debian host audit. No external scans or configuration writes."""

import argparse
import json
import os
import platform
import sys

from server_audit.audit_runner import audit
from server_audit.reporting import export_report, render_text
from server_audit.collectors.git_secrets import SCAN_SECONDS, scan_seconds_value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit full structured report as JSON")
    parser.add_argument("--export", nargs="?", const="audits", metavar="DIRECTORY", help="Write a unique HTML/JSON audit folder (default parent: ./audits)")
    parser.add_argument("--ssh-context", help="Evaluate SSH Match rules, e.g. user=alice,addr=198.51.100.10,host=client.example")
    parser.add_argument("--ssh-config", help="Audit a specific sshd configuration file instead of the default")
    parser.add_argument("--env-root", action="append", metavar="DIRECTORY", help="Scan this directory for .env metadata; repeat for multiple roots. Replaces default roots: /etc /opt /srv /var/www /home /root")
    parser.add_argument("--git-root", action="append", metavar="REPOSITORY", help="Inspect local Git configuration and stored objects with built-in secret rules; repeat for multiple repositories")
    parser.add_argument("--git-scan-seconds", type=scan_seconds_value, default=SCAN_SECONDS, metavar="SECONDS",
                        help="Scan budget per Git repository (default: 60 seconds; maximum: 3600)")
    args = parser.parse_args()
    if platform.system() != "Linux":
        parser.error("Run this script on the Ubuntu/Debian server, not on your local Windows machine.")
    # The audit commonly runs as root: resolve only system-installed commands.
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    report = audit(args.ssh_context, args.ssh_config, args.env_root, args.git_root, args.git_scan_seconds)
    if args.export is not None:
        try:
            folder = export_report(report, args.export)
        except OSError as error:
            print(f"Export failed: {error}", file=sys.stderr)
            return 1
        print(f"Audit exported: {folder / 'report.html'}", file=sys.stderr)
    if args.json:
        print(json.dumps(report, indent=2))
    elif args.export is None:
        sys.stdout.write(render_text(report))
    return 0


if __name__ == "__main__":
    sys.exit(main())
