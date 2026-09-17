# Development and verification

[Documentation index](../README.md) · Internal engineering documentation · Reviewed 2026-09-17

Maintain the internal tool with focused changes, reproducible fixtures and explicit validation limits.

## Local setup

Use a trusted local copy and Python 3. No third-party Python dependencies are required. Run unit tests from the project root. Use Linux or Ubuntu WSL for POSIX coverage; Windows can run portable tests but intentionally skips Linux-specific cases. Avoid running a full host audit when a mocked collector test answers the question.

```bash
python3 -m unittest test_docker_audit -q
python3 -m unittest discover -s . -p 'test_*.py' -q
```

For optional real scanner integration, provide an existing trusted executable. The test creates a disposable repository with fake credentials; do not use production keys.

```bash
AUDIT_TEST_GITLEAKS_PATH=/absolute/path/to/gitleaks python3 -m unittest test_git_secrets -q
```

The integration test is skipped when `AUDIT_TEST_GITLEAKS_PATH` is unset or the platform is not Linux. On Linux, a supplied nonexistent or unusable executable fails the test rather than skipping it. A green suite with skips is not equivalent to complete native validation. Do not download tools or change the host merely to make a skip disappear without an operational need.

## Test ownership

| Tests | Coverage |
| --- | --- |
| `test_audit.py` | Command failures, network/SSH policy, optional-tool detection and orchestration behavior |
| `test_runner.py` and `fixtures/audit-contract.json` | Existing report shape and ordered command contract, with explicit intentional deltas |
| `test_accounts.py` | Accounts, permissions, keys and observed usage |
| `test_docker_audit.py` | Container projection, findings, absent CLI and daemon failures |
| `test_env_files.py` | Metadata-only file handling, scope limits and application references |
| `test_git_secrets.py` | Redaction, failures and opt-in real scanner integration |
| `test_scheduled_tasks.py` | Cron/timers, bounded reads, script references, ownership and redaction |
| `test_reporting.py` | Rendering, escaping, permissions, completion manifests and CLI output |
| `test_live_integrations.py` | Opt-in disposable-lab SSH, Docker, firewall and socket checks; see [fixture contract](live-validation.md#repeatable-live-test-fixture-contract) |
| `test_external_verification.py` | Loopback TCP, mocked public IPv4/IPv6 observations, import/schema limits, scope classification and no-network import/dry run |

## Change checklist

1. Inspect the responsible module and its tests. Preserve unrelated local changes and collected evidence.
2. Add focused regression proof for changed behavior. Use injected command responses and temporary files; include failure/partial paths and redaction checks where relevant.
3. Follow the [collector contract](architecture.md#architecture-and-extending-audits). Preserve explicit prerequisites and keep rendering separate from collection.
4. Run focused tests, then the full suite for changes affecting the runner, report contract or shared helpers. Record platform, failures and skips.
5. For HTML changes, inspect the actual report at desktop/mobile sizes and in light/dark themes. Check overflow, readable statuses, escaping, navigation and print behavior when affected.
6. Update the relevant guide in the same change. If report fields/statuses change, update contract tests and [format documentation](report-format.md).
7. Before distributing a snapshot, include the full runtime file list and template, exclude reports/test artifacts, and retain the previous known-good snapshot for rollback. No deployment is implied by a local change.

Do not add a new framework, documentation generator, CI pipeline or release process merely to document this small project. These can be introduced when an actual maintenance requirement exists. Source is maintained in [novakin/Server-Audit](https://github.com/novakin/Server-Audit); automated CI and release tagging are not configured. Before committing, review the staged file list and diff. Keep actual host reports, local lab files and scanner binaries out of this public repository; ignore rules cannot cover every custom output path.

## Documentation maintenance

README is the entry point. Operations owns setup and handling; audit reference owns detection scope; architecture owns extension rules; report format owns status semantics; this guide owns test workflow. Link to the owning page instead of repeating detailed facts. Update the reviewed date when behavior is checked against source. Keep historical verification labeled by date and avoid presenting test totals as permanent guarantees.

## Recorded verification — 2026-09-17

External-verification follow-up: discovery now includes 87 tests. Ubuntu WSL passed 83 with four separately gated live-lab checks skipped; Windows passed 62 with 25 skips. Fifteen new external-workflow tests use loopback sockets or mocked public endpoints. Native IPv6 loopback passed on Ubuntu; Windows denied the control connection with WSAEACCES, so that integration test was explicitly skipped. No external addresses were scanned for implementation validation. Live-lab results remain the separate dated run below.

The initial results below predate the Debian live lab. Follow-up [Debian validation](live-validation.md) passed all 68 existing tests plus four new opt-in live integration tests and fixed two Docker template failures. Systemd/journal and external reachability limits remain explicit.

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

Tests cover socket classification (including IPv4-mapped IPv6 loopback), SSH policy findings, command failures, optional-tool handling, update/service summaries and complete report assembly with a custom SSH configuration. Linux tests also generate a temporary Ed25519 key to verify native fingerprinting, quoted key options, comments, duplicate detection and account-specific usage correlation. Ownership/mode checks, symlink/FIFO refusal and unknown history are covered.

Docker fixture tests cover privilege findings, loopback versus other port bindings, stopped containers, disappearing containers, malformed output, missing/denied Docker access and excluded secret-bearing fields.

Export tests cover unchanged JSON data, unique folders, Linux permissions, HTML escaping, empty versus unavailable inventories, incomplete writes and CLI output/exit behavior.

The offline HTML was reviewed in Chrome at desktop and mobile widths in light/dark mode. Browser checks cover finding filters, evidence navigation, print expansion/restoration, no external resource requests and no console errors. A complete Ubuntu audit also exercised `--export --json` successfully. Browser print preparation is checked; PDF pagination still depends on browser print settings.

Environment tests cover no content reads, modes, writable parents, ACL presence/failures, symlink/FIFO refusal, scan bounds and application references. Git tests cover redacted output, missing/failed scans and real Gitleaks detection of a deleted committed fake key and an ignored working-tree `.env` file. Enable the disposable-repository integration test with `AUDIT_TEST_GITLEAKS_PATH=/absolute/path/to/gitleaks`; otherwise it is skipped.

Scheduled-task tests cover system/user cron parsing, suspicious patterns, command redaction, script references, links/FIFOs, binary metadata, file limits, shared-script ownership contexts, timer target inspection, unsupported syntax and timer failures. Before adding scheduled-task behavior, the refactor reproduced the saved HTML/text output exactly and preserved existing report data and command order.

Validated locally on Windows and Ubuntu WSL: all 68 tests pass on Ubuntu with the optional Gitleaks integration enabled; Windows runs 48 and skips 20 Linux/POSIX/integration tests. Gitleaks v8.30.1 was downloaded into an isolated local test directory and checked against its published release checksum; it was not installed system-wide. A complete Ubuntu WSL audit generated valid JSON and exercised socket, systemd, APT and account tools. That environment lacked sshd, Docker and firewall tools, so those integrations, including the Docker CLI inspection template, still need validation on a representative server. Journal key-use correlation is tested with fixtures, not real remote logins. The Debian WSL instance had no Python 3; Debian runtime validation remains outstanding. Actual host configuration and network exposure require running the audit on the target server.
