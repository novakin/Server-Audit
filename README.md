# Server security audit

Internal, read-only Ubuntu/Debian host audit. Collects configuration, access and exposure evidence with Python 3 and available native tools. Produces text, JSON and an offline HTML report. Findings require review; this is not a security certification or malware scanner.

The audit does not install tools, refresh APT, change host configuration or scan remote hosts. Export writes private local files; requested Git scanning also uses temporary scratch files. Inspection can create normal system log records.

An explicit [external-verification companion](docs/external-verification.md) can probe selected TCP endpoints from an independent machine, then import observations into a new report. It runs separately from host collection and never discovers targets automatically.

## Start here

Copy the complete [runtime file set](docs/architecture.md#architecture-and-extending-audits) and template into one trusted directory on the target server, then run:

```bash
python3 audit.py --help
sudo python3 audit.py --export /var/lib/server-security-audit
```

Open the generated `report.html`; retain its sibling `data/report.json` and completion manifest. Root improves visibility. A zero exit code means report generation completed, not that all checks passed. Reports contain sensitive internal operational details.

## Documentation

Coding agents must follow the active [project instructions](AGENTS.md).

| Guide | Use it for |
| --- | --- |
| [Roadmap](docs/roadmap.md) | Approved fix scope, proposed next work and architecture decision triggers |
| [Operator runbook](docs/operations.md) | Prerequisites, CLI, running audits, exports, retention and troubleshooting |
| [Audit coverage and limits](docs/audit-reference.md) | SSH, accounts/keys, network/firewalls, Docker, environment files, Git secrets and scheduled tasks |
| [Architecture and extension guide](docs/architecture.md) | Module ownership, data flow, collector contract and adding audits |
| [Report format](docs/report-format.md) | JSON fields, status semantics, completion manifest and compatibility |
| [Development and verification](docs/development.md) | Test workflow, change checklist and recorded validation |
| [Debian live validation](docs/live-validation.md) | Native SSH/Docker/firewall results, regression fixes and remaining gaps |
| [External verification](docs/external-verification.md) | Independent TCP probe, dry run, offline import, exposure labels and limits |

## Detection and interpretation

Missing optional Docker/firewall tools are **Skipped** with a reason; no missing executable is launched. Access errors and incomplete required evidence remain **Unknown** findings. Git content scanning runs only for explicit `--git-root` selections. An empty successful inventory is different from unavailable coverage.

See [status definitions](docs/report-format.md#check-statuses) and [audit scope](docs/audit-reference.md) before acting on results. The script never applies remediation.

## Project state

Source repository: [novakin/Server-Audit](https://github.com/novakin/Server-Audit). Generated audit reports remain restricted internal evidence and must not be committed, regardless of source repository visibility. No CI pipeline or release process is configured. Current reliability/SSH fix tests and disclosed skips are recorded in the [verification summary](docs/development.md#reliability-and-ssh-fixes--2026-09-17). Ubuntu WSL validation is recorded in the [development guide](docs/development.md#recorded-verification--2026-09-17). Debian 13 and real SSH/Docker/firewall integrations passed in an [isolated lab](docs/live-validation.md). Standalone systemd-host behavior and external exposure remain unverified. No maintainer contact, retention duration or support SLA is assigned here; use the existing internal ownership and incident process.

Documentation reviewed against the current source on 2026-09-17. Keep source, tests and these guides aligned when behavior changes.
