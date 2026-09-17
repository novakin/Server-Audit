# Operator runbook

[Documentation index](../README.md) · Internal engineering documentation · Reviewed 2026-09-17

Run an audit on an authorized Ubuntu/Debian host, retain its evidence privately, and review incomplete coverage before drawing conclusions.

## Prerequisites and installation

The runtime uses Python 3 and its standard library. There is no pip requirements file or automatic dependency installer. Ubuntu WSL and Debian 13 userland in an isolated WSL2 lab have been exercised; standalone Debian systemd-host validation remains outstanding. See [live validation](live-validation.md) for tested versions and limits. A minimum Python version has not been established by a compatibility test matrix. Record `python3 --version` for the environment being assessed.

Copy every runtime file in the [architecture table](architecture.md#architecture-and-extending-audits), including `report_template.html`, into one trusted directory on the server. Do not copy `.artifacts`, collected reports, cached bytecode or local scanner test binaries. Keep source and template from the same reviewed revision or source snapshot. The script directory and native tool directories must not be writable by untrusted users when running as root.

Run from that directory. Root improves coverage; unprivileged runs are allowed but record incomplete visibility. The CLI checks for Linux, not for a specific distribution. Do not interpret a successful launch on another Linux distribution as supported behavior.

| Area | Native tools used |
| --- | --- |
| SSH and key fingerprints | `sshd`, `ssh-keygen` |
| Listening sockets | `ss` |
| Firewall evidence | `ufw`, `nft`, `iptables-save`, `ip6tables-save` |
| Services, timer metadata and SSH journal | `systemctl`, `journalctl` |
| Updates | `apt` using existing package metadata |
| Account access/history | `passwd`, `chage`, `sudo`, `lastlog` |
| Extended ACL metadata | Python `os.getxattr`; `getfacl` is suggested only for manual follow-up |
| Optional Docker inventory | `docker`, local default Unix socket |
| Requested repository secret scans | `gitleaks` and `git`; see [scanner scope](audit-reference.md#git-secrets) |

Install missing tools only through your normal host administration process when coverage requires them. The audit neither installs tools nor starts services. Executables resolve from `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`; a tool available only in your interactive shell may be unavailable to the audit.

## First run

```bash
python3 --version
python3 audit.py --help
sudo python3 audit.py --export /var/lib/server-security-audit
```

Choose a trusted export parent and run on the target host. Normal inspection may create system log records. Export writes a local report folder; requested Git scans also create temporary scanner files. The audit does not modify service configuration, permissions, package metadata or schedules.

Review the export path written to stderr. Confirm `manifest.json` has `status: complete`, then open `report.html` locally or transfer the complete folder through your approved secure channel. A completed bundle can contain incomplete checks.

## CLI reference

| Option | Behavior |
| --- | --- |
| No output option | Human-readable text on stdout |
| `--json` | Full structured report on stdout |
| `--export [DIRECTORY]` | New private bundle; default parent `./audits`; suppresses normal text output |
| `--export DIRECTORY --json` | Bundle plus JSON on stdout; export path on stderr |
| `--ssh-context CONTEXT` | Connection attributes for SSH Match evaluation |
| `--ssh-config PATH` | On-disk SSH configuration to evaluate |
| `--env-root DIRECTORY` | Repeatable; replaces default directory discovery roots, not application-reference inspection |
| `--git-root REPOSITORY` | Repeatable; explicitly enables content scanning of selected repositories |
| `-h`, `--help` | Show arguments without collecting host evidence |

```bash
sudo python3 audit.py --env-root /srv/apps --env-root /opt/services --export /var/lib/server-security-audit
sudo python3 audit.py --ssh-context 'user=alice,addr=198.51.100.10,host=client.example' --export
sudo python3 audit.py --git-root /srv/app --export
```

Prefer export bundles for stored audits. If redirecting stdout, set a restrictive umask in the shell that creates the file; sudo does not make shell redirection private:

```bash
(umask 077; sudo python3 audit.py --json > audit-report.json)
```

## Review workflow

For actual off-host TCP observations, follow the [external-verification runbook](external-verification.md). Run its companion from an independent machine after exporting the snapshot; it is not an `audit.py` option and is never run automatically. Offline import creates a new bundle while retaining the original audit.

1. Confirm host identity, audit time and intended SSH/repository/environment scope.
2. Read coverage and Unknown findings first. Distinguish skipped optional tools from failed or partial collection.
3. Review findings with their collected evidence. A Review finding is a prompt for investigation, not proof of exploitation.
4. Validate relevant service configuration, account authorization and external exposure separately. Record the evidence and decision in your internal change or incident record.
5. Apply any remediation through a separate reviewed change. The audit performs no remediation. Re-run after changes and retain both reports according to your internal policy.

## Export an audit

```bash
# Create a new audit folder under ./audits
sudo python3 audit.py --export

# Choose an export parent directory
sudo python3 audit.py --export /var/lib/server-security-audit

# Also emit JSON to stdout for automation; export location goes to stderr
sudo python3 audit.py --export ./audits --json
```

Each run creates a unique folder using the export time in UTC, sanitized hostname and a collision-resistant temporary-directory suffix. Existing exports are never reused or overwritten.

```text
audits/
  20260917T120000Z-edge-01-<unique>/
    report.html
    data/
      report.json
    manifest.json
```

`data/report.json` contains the full collected report, including failed checks, findings and limitations. Top-level `schema_version: 1` identifies the report format. The HTML is rendered from that same data without changing it. The manifest records export time, audit time, hostname, export schema version and artifact paths. It is published only after the artifacts have been written successfully; it is not a cryptographic integrity signature. A folder without a valid `manifest.json` with `status: complete` is incomplete. Export failures return exit code 1 and retain partial files for inspection. No automatic retention or cleanup runs.

Open `report.html` directly in a browser. Styles and scripts are embedded; there are no CDN dependencies, analytics or network fetches. The report includes review/unknown finding filters, search, collection coverage, socket/account/container inventories and expandable evidence. Native details remain usable without JavaScript. Light/dark themes follow browser preferences. Print/save-PDF expands all evidence and includes findings hidden by filters, then restores the screen state. The JSON download link requires keeping the sibling `data` directory; the HTML itself can be viewed alone.

On Linux, audit folders and data directories are created with mode `0700`; files use `0600`, owned by the invoking user (normally root under sudo). Existing parent-directory permissions are not changed. On Windows or Windows-mounted filesystems, host ACL/mount behavior governs access; POSIX modes are not a substitute for checking those permissions. Export only to trusted directories. Transfer a complete folder through your normal secure file-transfer process, and grant access only to intended internal reviewers. Both JSON and HTML contain sensitive operational evidence; HTML escaping prevents captured host strings from becoming executable markup, but does not redact that evidence.

## Data handling and retention

Treat every report as restricted internal operational data. Hostnames, usernames, addresses, filesystem paths, service details, sudo policy and public-key fingerprints can be sensitive even when secret values are omitted. Full stdout and native evidence may also be sensitive. See [per-audit exclusions](audit-reference.md) before sharing a subset.

Keep reports outside source control and public web roots. Restrict access and use approved encrypted transfer/storage. The source repository is public. `.gitignore` excludes standard report directories, `.artifacts`, bytecode and common secret files; custom report destinations still require explicit review before staging. No automated publication pipeline is configured.

There is no retention policy built into the script, and no automatic deletion. The internal system owner must choose retention, access and disposal rules for the environment. No owner, retention duration or support SLA has been assigned in these docs. A suspected credential leak belongs in the existing internal incident process; do not paste raw secrets or full audit bundles into broadly visible tickets.

## Troubleshooting

| Symptom | Meaning and next check |
| --- | --- |
| Docker Skipped | CLI absent from audit PATH. Check installation/path only if Docker coverage is expected; daemon absence is not established. |
| Docker Error / Unknown | CLI exists but collection failed. Review daemon/socket permissions and service state; the audit will not start the daemon. |
| No kernel firewall evidence | No backend was readable. Check privilege and installed tools, then assess provider filtering separately. |
| SSH unavailable | Check `sshd` installation, privileges and selected configuration. Validate Match context against intended connections. |
| Key usage Unknown | No usable match in retained evidence. Check journal access/retention; this does not mean the key was never used. |
| Environment or scheduled-task coverage partial | Read `issues`, skipped paths and limits. Symlinks, bounds and unsupported syntax require local follow-up. |
| Requested Git scan unavailable | Check Gitleaks visibility in audit PATH and selected repository scope. Never interpret scanner failure as no secrets. |
| No completion manifest | Export was interrupted or failed. Keep the partial folder for diagnosis; rerun into a new bundle after fixing storage/access. |
| Long execution time | Collection is sequential; command deadlines apply individually. Large account/container inventories may take longer. There is no total-runtime guarantee. |

Exit code `0` means generation completed, even with Review/Unknown findings. Export I/O failures return `1`; argument/platform errors return `2`. Other unhandled runtime failures may also return nonzero. Automation must check both completion and report contents; there is no severity-based exit option.
