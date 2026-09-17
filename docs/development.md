# Development and verification

[Documentation index](../README.md) · Internal engineering documentation · Reviewed 2026-09-17

Maintain the internal tool with focused changes, reproducible fixtures and explicit validation limits.

## Packed-storage coverage follow-up — 2026-09-17

Verified against PR #3 head `79a7a6faa8fe548d47db042cace00d65def8abb0` in Debian 13 with Python 3.13.5 and the already installed Git 2.47.3. Runtime modules, tests, template and historical runner fixture matched the reviewed Git blob identities before editing. Only `git_reader.py` and `git_secrets.py` change runtime behavior: check pack/index pairing and observe diagnostic presence without retaining raw stderr. No extra Git command, external tool or dependency is introduced.

| Run | Result |
| --- | --- |
| Unmodified feature suite | 153 discovered; 148 passed, 5 skipped; no failures. |
| Four review regressions against unmodified code | Healthy/corrupt-pack cases passed; missing/corrupt-index cases failed as expected. |
| Original four review regressions after the fix | 4 passed; no skips. |
| Focused Git detector, reader, packed-storage and pipeline suite | 76 passed; no skips. |
| Complete changed suite | 168 discovered; 163 passed, 5 skipped; no failures. |

```bash
python3 -m unittest test_git_secrets test_git_reader test_git_pack test_git_audit -v
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Nine new native packed-storage tests cover healthy, missing, corrupt, truncated and mismatched indexes, missing/corrupt packs, source immutability, preserved config/loose-object findings, later repositories and redacted exports. Six additional process tests cover late/large stderr, stderr during request writes or finish, a stalled stderr pipe and accepted quiet exit statuses. The existing stderr test now requires an exit-zero diagnostic to fail collection while preserving its redaction assertions. Cancellation and shutdown regressions remain active.

Raw diagnostics are discarded chunk by chunk, with only a boolean retained. Diagnostics conservatively make coverage incomplete; this is not message classification or full pack/index integrity verification. No source repair, new scanner, renderer/layout change, production audit or external probe was performed. CLI help and Python compilation passed. The five skips remain one OpenSSH key-generation test (tool absent) and four separately prepared native-lab checks; native Git tests ran. Historical results below describe earlier revisions.

## Built-in local Git inspection — 2026-09-17

Verification used Debian 13, Python 3.13.5 and the already installed Git 2.47.3, based on main commit `ab9af66215f3b66f2306f5a942c1641a6b546138`. Unchanged runtime modules, existing retained test files and the historical runner fixture were matched to GitHub blob identities. This was an isolated container, not a production audit or a fully booted systemd host.

| Run | Result |
| --- | --- |
| Focused built-in detector, reader and pipeline suite | 61 passed; no skips. |
| Complete changed suite | 153 discovered; 148 passed, 5 skipped; no failures. |
| CLI help | Passed; includes `--git-scan-seconds` and built-in local-object scope. |

```bash
python3 -m unittest test_git_secrets test_git_reader test_git_audit -v
python3 -m unittest discover -s . -p 'test_*.py' -v
python3 audit.py --help
```

The five skips are the existing OpenSSH key-generation test (`ssh-keygen` absent) and four explicitly prepared native-lab tests. The old Gitleaks opt-in test is removed because that integration is removed, not because its skip gate was relaxed. Twenty-seven Gitleaks-specific tests (five scan tests, eleven scratch/process tests and eleven shutdown follow-up tests) are replaced by 61 focused tests for the new implementation. The four OS reliability tests and unrelated collector/export tests remain. No unchanged skip gate was broadened.

Native Git fixtures exercise deleted historical secrets, packed/delta objects, unreachable loose objects, bare and SHA-256 repositories, commit/tag/config candidates, config includes and injected execution settings, partial clones with disabled fetching, corrupt/oversized objects, scope/byte/object/detection/time limits, source immutability, and exclusion of current working files. Reader tests exercise bounded pipes, nonzero/truncated output, shutdown/reap failures, second interruption, private workspace retention/cleanup and real SIGINT. The real denied-signal variant injects a `PermissionError`; its harness subsequently stops/reaps the child. It proves cancellation remains fatal, not that the auditor can override an actual kernel denial. Pipeline tests prevent final summary/export after fatal shutdown and check redaction, legacy rendering and CLI validation.

No external probes, production host audits, installation, CI, packaging or deployment changes were performed. No Windows compatibility run, fully booted systemd validation or new browser visual review is claimed. HTML layout/rendering code are unchanged; the template's Git scope sentence is corrected and synthetic exports verify escaping, metadata, redaction and manifest completion. Previous native/browser validation below is historical, not fresh validation of this change. See [scope limits](audit-reference.md#git-secrets).

## Scanner shutdown failure follow-up — 2026-09-17

Historical Gitleaks implementation record, superseded by the built-in implementation above. Commands and test names below describe that prior revision.

Verified against branch baseline `796a1547f6fe723f7e7ecd6d2937523d4588b05f` in a Debian 13 Linux container with Python 3.13.5. All original runtime modules, the HTML template, test modules and the historical runner fixture were matched to their GitHub blob hashes before testing. Only `git_secrets.py` changes runtime behavior; the existing reliability mocks were adapted to explicit process/scratch ownership without removing assertions or broadening skip gates.

| Run | Result |
| --- | --- |
| Unmodified branch suite | 108 discovered; 102 passed, 6 skipped; no failures. |
| Two new cancellation regressions against unfixed code | Both failed as expected: `KeyboardInterrupt` was not raised after an injected shutdown or reap error. |
| New shutdown regressions | 11 passed; no skips. |
| Focused reliability, shutdown, Git, SSH and reporting suite | 49 discovered; 48 passed, 1 skipped (opt-in real Gitleaks). |
| Complete changed suite | 119 discovered; 113 passed, 6 skipped; no failures. |

```bash
python3 -m unittest test_scanner_shutdown -v
python3 -m unittest test_reliability test_scanner_shutdown test_git_secrets test_ssh_evidence test_reporting -v
python3 -m unittest discover -s . -p 'test_*.py' -v
```

The new tests cover cancellation after shutdown/reaping errors, fatal timeout shutdown failure, a second interruption during shutdown, ordinary launch/wait errors, retained scratch and stopped repository iteration, stop/reap/cleanup ordering, and suppression of final summary/export after failed shutdown. One test sends real SIGINT to a synthetic scanner wrapper while deliberately injecting a denied group signal. Its test harness subsequently stops and reaps the child; this proves cancellation propagation, not that production can override a denied signal. The existing normal real-SIGINT regression also passed.

The six full-suite skips remain one native OpenSSH key-generation test (`ssh-keygen` absent), one opt-in real Gitleaks test, and four prepared-lab integration tests. Native IPv4/IPv6 loopback checks passed; public targets were mocked. No tools were installed, production host audits run, external targets probed, or CI/deployment changes made. Real Gitleaks/OpenSSH integration, visual browser review and fully booted systemd-host validation were not performed for this follow-up. Report schema, SSH fields, renderer/template and historical fixture remain unchanged. See [operator handling](operations.md#scanner-failures-and-interruption) for retained scratch.

## Reliability and SSH fixes — 2026-09-17

Historical pre-replacement verification; see the current built-in Git record above.

Local verification for the four review fixes used a Debian 13 Linux container with Python 3.13.5. This was not a fully booted systemd test host or a production audit. The original runtime files, template, test files and runner fixture were verified against GitHub blob identities at baseline `2f1a9d64d23dbb3c759d76c23a2e476cc8936c64` before applying changes.

| Run | Result |
| --- | --- |
| Unmodified baseline | 87 discovered; 81 passed, 6 skipped; no failures. |
| New focused regressions | 21 passed: 15 reliability/process tests and 6 SSH evidence tests. |
| Complete changed suite | 108 discovered; 102 passed, 6 skipped; no failures. |

The six skips were one native OpenSSH key-generation test (`ssh-keygen` absent), one opt-in real Gitleaks test (not enabled), and four prepared-lab integration tests (not enabled). Existing skip gates were not broadened. The passing new process test sends real SIGINT to a wrapper and verifies its synthetic scanner has stopped and been reaped; it does not invoke Gitleaks or scan repositories for credentials. Native IPv4/IPv6 loopback tests also passed. No tools were installed, host audits run, production targets probed, or CI workflows enabled for this change.

```bash
python3 -m unittest test_reliability test_ssh_evidence -v
python3 -m unittest discover -s . -p 'test_*.py' -v
```

Tests cover OS permission/read/decode errors, unchanged missing-file fallback, scanner scratch creation/control-file/cleanup failures, evidence preservation across repositories and runner checks, propagated programming errors/interruptions, timeout cleanup, private output/redaction, SSH scope on success and failure, repeated values, legacy rendering and the unchanged schema. The historical `fixtures/audit-contract.json` stays byte-for-byte unchanged; `test_runner.py` explicitly asserts the intended additions and corrected limitation.

The HTML template/layout is unchanged. Synthetic export tests verify escaping, additive evidence, unchanged source JSON and completion manifests. No new visual browser review, real scanner/OpenSSH integration or systemd-host validation is claimed. Earlier native and browser runs below are separate historical evidence; the [documented live gaps](live-validation.md#remaining-limits) remain open.

## Local setup

Use a trusted local copy and Python 3. No third-party Python dependencies are required. Run unit tests from the project root. Use Linux or Ubuntu WSL for POSIX coverage; Windows can run portable tests but intentionally skips Linux-specific cases. Avoid running a full host audit when a mocked collector test answers the question.

```bash
python3 -m unittest test_docker_audit -q
python3 -m unittest discover -s . -p 'test_*.py' -q
```

Native Git tests create disposable local repositories with synthetic candidates using an already installed `git` executable. They run automatically on POSIX when Git is available; no Gitleaks binary or `AUDIT_TEST_GITLEAKS_PATH` is used. Pure detector/CLI tests do not need Git. Do not download or add external tools merely to remove a skip: new integrations require prior explicit user approval under [AGENTS.md](../AGENTS.md#external-tool-approval).

A green suite with skips is not complete native validation. Tests do not grant permission to run a production audit or probe external targets. Record the versions actually used and distinguish synthetic error injection from real permission failures.

## Test ownership

| Tests | Coverage |
| --- | --- |
| `test_audit.py` | Command failures, network/SSH policy, optional-tool detection and orchestration behavior |
| `test_runner.py` and `fixtures/audit-contract.json` | Existing report shape and ordered command contract, with explicit intentional deltas |
| `test_reliability.py` | Existing OS failure isolation and evidence preservation |
| `test_git_pack.py` | Native packed-storage failures, evidence preservation and redaction |
| `test_git_reader.py` | Bounded pipes, safe metadata, shutdown/cancellation and native SIGINT |
| `test_git_audit.py` | CLI budgets, failure propagation, no export on abort, redaction and legacy reports |
| `test_ssh_evidence.py` | Attempted SSH scope, repeated values, additive compatibility and export/rendering |
| `test_accounts.py` | Accounts, permissions, keys and observed usage |
| `test_docker_audit.py` | Container projection, findings, absent CLI and daemon failures |
| `test_env_files.py` | Metadata-only file handling, scope limits and application references |
| `test_git_secrets.py` | Built-in rules, synthetic native Git storage, local-only scope, redaction and limits |
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

Do not add a new framework, documentation generator, CI pipeline or release process merely to document this small project. These can be introduced when an actual maintenance requirement exists. Source is maintained in [novakin/Server-Audit](https://github.com/novakin/Server-Audit); automated CI and release tagging are not configured. Before committing, review the staged file list and diff. Keep actual host reports, local lab files and scanner binaries out of the source repository; ignore rules cannot cover every custom output path.

## Documentation maintenance

README is the entry point. Operations owns setup and handling; audit reference owns detection scope; architecture owns extension rules; report format owns status semantics; this guide owns test workflow. Link to the owning page instead of repeating detailed facts. Update the reviewed date when behavior is checked against source. Keep historical verification labeled by date and avoid presenting test totals as permanent guarantees.

## Recorded verification — 2026-09-17

Historical runs preceding the reliability/SSH fix validation above follow. Their environments, counts and remaining gaps describe those runs, not new validation of the current change.

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
