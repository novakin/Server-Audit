<a name="top"></a>

<div align="center">

# 🛡️ Server Audit

**Review server access, services and exposure in one report.**

Read-only checks for Ubuntu and Debian. Offline reports. No automatic fixes.

![Target: Ubuntu / Debian](https://img.shields.io/badge/Target-Ubuntu%20%2F%20Debian-5E81AC?style=flat-square)
![Runtime: Python 3](https://img.shields.io/badge/Runtime-Python%203-3776AB?style=flat-square&logo=python&logoColor=white)
![Reports: HTML / JSON / Text](https://img.shields.io/badge/Reports-HTML%20%2F%20JSON%20%2F%20Text-4C956C?style=flat-square)

[**Get started**](#get-started) · [Checks](#what-it-checks) · [Examples](#usage-examples) · [Reports](#understanding-your-report) · [Help](#faq-and-troubleshooting) · [Documentation](#documentation)

</div>

<!-- Optional visual: add one real HTML-report screenshot generated from synthetic
     data here, using a relative repository path after the image exists. Show the
     summary, coverage and an evidence section. Do not use production reports. -->

---

Server Audit gathers local configuration, account access and service evidence into an offline report. Use it for a server handover, a routine review, or a record before and after an approved change.

**Run on the server → Export the report → Review in your browser.**

<a name="what-it-checks"></a>

## 🔎 What it checks

| Area | What you can review |
| --- | --- |
| **SSH and accounts** | Authentication settings, sudo policy, authorized-key fingerprints, file permissions and retained login evidence. |
| **Ports and firewalls** | Listening TCP/UDP sockets, addresses, owning processes and available firewall rules. |
| **Docker** | Container health, published ports, mounts, configured privileges and resource limits on the local default Docker socket. |
| **System health** | Running and failed services, updates from cached APT metadata, and reboot-required state. |
| **Environment files** | Ownership and permissions of discovered files and supported application references—not environment-variable values. |
| **Scheduled tasks** | Cron jobs, systemd timers, permissions and command patterns that need review. |
| **Git secrets · opt-in** | Candidate credentials in selected local Git configuration and stored objects. **Not current working files.** |

Checks depend on available tools, permissions and scope. Review coverage notes alongside findings; no detections does not prove absence. See [full coverage and limits](docs/audit-reference.md).

<a name="get-started"></a>

## 🚀 Get started

You need an authorized Ubuntu/Debian host, Python 3 and a reviewed copy of the project. Root access improves coverage; it is not mandatory. There is no `pip install` step, and missing native tools are not installed automatically.

Check [prerequisites and tested environments](docs/operations.md#prerequisites-and-installation) before your first run. Ubuntu/Debian are the target platforms, not a claim that every version has been validated.

### 1. Copy the runtime

Copy these items from one reviewed revision into a clean, trusted directory, such as `/opt/server-audit/`:

```text
audit.py
external_probe.py
server_audit/          # Include all subdirectories and the HTML template
```

Keep the directory structure; exclude caches. Tests are not required. When running with `sudo`, untrusted users must not be able to modify the runtime files or directory.

### 2. Generate your first report

From that directory:

```bash
python3 --version
python3 audit.py --help
sudo python3 audit.py --export /var/lib/server-security-audit
```

The command creates a new bundle and prints the path to `report.html`.

### 3. Open and review

Check that `manifest.json` contains `"status": "complete"`, then open `report.html`. For a headless server, securely transfer the complete bundle to your workstation.

Review **Unknown** findings and coverage gaps first, then the evidence behind **Review** findings.

> [!IMPORTANT]
> **Keep reports private.** They contain sensitive accounts, addresses, paths and configuration evidence. Do not commit them to Git or publish them in a web directory.

<a name="usage-examples"></a>

## 🧰 Usage examples

### Terminal output or an offline bundle

```bash
# Read the results in your terminal
sudo python3 audit.py

# Save an HTML/JSON bundle under ./audits
sudo python3 audit.py --export ./audits
```

Relative paths use your current directory. Use absolute paths for scheduled runs.

### Add Git secret inspection

```bash
sudo python3 audit.py \
  --git-root /srv/app \
  --git-root /opt/another-repo \
  --git-scan-seconds 60 \
  --export ./audits
```

This requires local Git and inspects only the repositories you select. It does not clone, fetch or validate credentials remotely. The default scan budget is 60 seconds per repository; limits can leave partial coverage.

> [!NOTE]
> **Git inspection is opt-in and does not scan current working files.** Findings identify candidate locations without exporting matching secret values. See [Git scope and limits](docs/audit-reference.md#git-secrets).

<details>
<summary><strong>Choose environment-file discovery directories</strong></summary>

```bash
sudo python3 audit.py \
  --env-root /srv/apps \
  --env-root /opt/services \
  --export ./audits
```

These options replace default directory-discovery roots, not the separate inspection of supported application references. This check reads file metadata, not file contents.

</details>

<details>
<summary><strong>Evaluate SSH settings for a specific connection</strong></summary>

```bash
sudo python3 audit.py \
  --ssh-context 'user=alice,addr=198.51.100.10,host=client.example' \
  --export ./audits
```

Replace the example connection details. This evaluates on-disk configuration, not necessarily the running daemon's settings. Add `--ssh-config /path/to/sshd_config` for a custom configuration file.

</details>

<details>
<summary><strong>Use JSON for automation</strong></summary>

```bash
# Print structured results
sudo python3 audit.py --json

# Save stdout with restrictive permissions
(umask 077; sudo python3 audit.py --json > audit-report.json)
```

The shell creates redirected files, so `sudo` alone does not make them private. Prefer export bundles for retained audits; see the [report format](docs/report-format.md) for integration.

</details>

<a name="understanding-your-report"></a>

## 📊 Understanding your report

```text
<unique-audit-folder>/
├── report.html        # Offline browser report
├── data/
│   └── report.json    # Full structured evidence
└── manifest.json      # Export-completion record
```

The HTML report includes search, finding filters, coverage and expandable evidence, with light/dark browser preferences and print support. It needs no hosted dashboard or CDN. Keep the bundle together to preserve its JSON download link and completion record.

| Finding | What it means | Your next step |
| --- | --- | --- |
| **Review** | An observed setting or condition needs a decision—not proof of compromise. | Inspect the evidence and decide whether a change is needed. |
| **Unknown** | Evidence is missing or insufficient. | Check the reason, address the coverage gap where possible, and reassess. |

**Successful collection is not a security pass.** Exit code `0` means generation finished, and a complete manifest means export finished. Neither certifies the host or guarantees full coverage. There is no security score.

<details>
<summary><strong>What do the collection statuses mean?</strong></summary>

| Status | Meaning |
| --- | --- |
| `ok` | Collection succeeded in its stated scope; findings or nested failures can still exist. |
| `skipped` | An optional prerequisite was missing; the reason is recorded. |
| `not_requested` | An opt-in check was not selected. |
| `partial` | Some evidence was collected, but coverage is incomplete. |
| `unavailable` / `error` | Required evidence was unavailable, or collection failed. |

Read findings and nested statuses too. See the [full status definitions](docs/report-format.md#check-statuses).

</details>

<a name="external-verification--optional"></a>

## 🌐 External verification · optional

A local listening port does not prove internet reachability. The separate `external_probe.py` companion can test explicitly selected TCP endpoints from an independent machine and import observations into a new report.

It never runs automatically with the host audit and requires Python 3.9 or newer. Use only authorized targets; a negative observation applies to that probe and time, not all possible network paths.

**[Follow the external-verification guide →](docs/external-verification.md)**

<a name="safety-and-limitations"></a>

## 🔒 Safety and privacy

**You control remediation.** The audit does not install tools, refresh APT, change configuration or permissions, restart services or scan remote hosts. External probing is a separate workflow.

**Read-only is not zero activity.** Exports write reports, requested Git scans create private reader metadata, and inspection can produce system log records. Retain and transfer evidence through your normal restricted-access process.

**Treat results as evidence, not certification.** This is not malware scanning, image-vulnerability scanning or exhaustive secret detection. Cached metadata, access restrictions and scan limits can leave gaps. Review the [scope limitations](docs/audit-reference.md), apply changes separately, then rerun.

<a name="faq-and-troubleshooting"></a>

## ❓ FAQ and troubleshooting

<details>
<summary><strong>Can I run this from Windows?</strong></summary>

Run `audit.py` on the target Ubuntu/Debian server. Open the exported HTML on your workstation. The optional companion is separate; it does not run the host audit remotely.

</details>

<details>
<summary><strong>Why is Docker or a firewall check skipped?</strong></summary>

The optional tool may be absent from the audit's system PATH. That does not prove Docker or firewall protection is absent. Permission failures and unreadable kernel-firewall evidence require review; see [troubleshooting](docs/operations.md#troubleshooting).

</details>

<details>
<summary><strong>There is no completion manifest. Can I use the report?</strong></summary>

Treat the bundle as incomplete. Check the export error and storage permissions, retain partial files for diagnosis, and rerun into a new bundle after resolving the issue.

</details>

<details>
<summary><strong>How do I upgrade?</strong></summary>

Copy a complete reviewed revision into a new, clean directory. Do not mix revisions or overlay the package onto obsolete flat modules. Keep the previous revision for rollback. See the [runtime copy instructions](docs/operations.md#prerequisites-and-installation).

</details>

For help, provide your OS and Python versions, project revision, command and sanitized error—not raw credentials or a full audit bundle. More cases are covered in the [operator runbook](docs/operations.md#troubleshooting).

<a name="documentation"></a>

## 📚 Documentation

| I need to… | Read this |
| --- | --- |
| Run, export, transfer or troubleshoot an audit | [Operator runbook](docs/operations.md) |
| Understand coverage and limitations | [Audit reference](docs/audit-reference.md) |
| Test endpoints from another network | [External verification](docs/external-verification.md) |
| Integrate JSON results | [Report format and statuses](docs/report-format.md) |
| Check tested environments and known gaps | [Verification](docs/development.md) · [Debian lab](docs/live-validation.md) |

<details>
<summary><strong>For contributors</strong></summary>

See the [architecture guide](docs/architecture.md), [development workflow](docs/development.md), [roadmap](docs/roadmap.md) and [project instructions](AGENTS.md).

</details>

<p align="right"><a href="#top">Back to top ↑</a></p>
