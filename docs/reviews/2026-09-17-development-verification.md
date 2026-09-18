# Historical development verification — 2026-09-17

[Current development procedure](../development.md) · [Review records](README.md)

Historical evidence, not current instructions or a new verification run. This block was retained from [docs/development.md at a6599fe](https://github.com/novakin/Server-Audit/blob/a6599fe930bc565b3d13e39eb87faeb964f4b068/docs/development.md) during documentation adoption on 2026-09-18 (Europe/Berlin). Original record dates are preserved; their original timezone was not recorded. Results, commands, environments and limitations describe their stated revisions. Recorded machine-local evidence paths are not published artifacts. Only navigation targets were adjusted for this location.

## Final revised-corrections verification — 2026-09-17

The full-checkout verification below supersedes the temporary full-suite gap recorded in the multiline follow-up. It applies to the exact revised correction package, based on `698f85eca384ce2bad41e3b3876b85b37d3e67f5`, without further runtime or test changes. Publication updates only this verification record beyond that package.

Environment: Debian 13, Python 3.13.5 and already installed Git 2.47.3. All ten delivered files matched their manifest and the final tested checkout. Thirty-five unchanged runtime/test/fixture files were matched to baseline Git blob hashes; reversing the patch recovered eight further exact baseline files. The complete runtime and test tree was present, not replacement stubs.

| Run | Result |
| --- | --- |
| Exact unmodified baseline full suite | 173 discovered; 168 passed, 5 skipped; no failures |
| Exact revised delivery full suite | 205 discovered; 200 passed, 5 skipped; no failures |
| Focused Git suites including both new regression modules | 108 passed; no skips |
| Independent delivery recheck plus boundary tests | 24 passed; no skips |
| Compilation and patch reverse/forward application | Passed; resulting file hashes verified |

The 24-test run combines eight independent delivery rechecks and the 16 boundary tests; the boundary tests are also included in the focused/full suites, so these totals are not additive. All 173 original test methods, assertion-call counts and decorators remain; 32 new methods give 205 discovered cases. The five existing skips remain one unavailable OpenSSH key-generation test and four separately gated prepared-lab checks. No skip condition was broadened. The historical JSON fixture and HTML template are byte-identical to baseline.

The commands shown in the multiline follow-up were rerun successfully in the complete verified checkout. No production-host audit, external-target probe, tool installation, new native-lab/Windows/browser validation or deployment was performed. This record establishes regression results for the agreed corrective scope, not exhaustive secret detection or a production security certification.

## Multiline reference-boundary follow-up — 2026-09-17

This local follow-up corrects an incomplete reference exclusion in the preceding, unpublished correction package. Both quoted and unquoted matches now require a bounded delimiter or actual end of data; newlines and comments alone are not completion. Runtime change is confined to `server_audit/collectors/git_secrets.py`. The earlier Git-configuration fixes, ruleset version 2, candidate regexes, scan limits, host schema, README and renderer/template are unchanged.

Fresh checks used Debian 13, Python 3.13.5 and existing Git 2.47.3:

| Check | Result |
| --- | --- |
| Eight independent delivery-recheck tests against the preceding package | Five passed; three failed, reproducing the multiline omission |
| Same eight tests after the boundary correction | Eight passed, no skips |
| New `tests/test_git_reference_boundaries.py` | Sixteen passed, no skips |
| Combined fresh run | Twenty-four passed, no skips |

The new tests cover fallbacks/concatenations across LF, CRLF, CR and UTF-8 JavaScript line separators, quoted references/placeholders, comments, truncated suffixes, explicit delimiters, genuine EOF and intentionally conservative ambiguous boundaries. Real disposable SHA-1/SHA-256 repositories are exercised both loose and packed; source bytes and redaction are checked. The earlier three Git defects are also rechecked through the independent delivery tests.

At the time of this targeted follow-up, the complete repository suite had not yet been rerun. That gap was subsequently closed by the final revised-corrections verification above. The earlier totals below still describe their original runs. Current commands for the revised implementation are:

```bash
python3 -m unittest tests.test_git_secrets tests.test_git_reader tests.test_git_pack tests.test_git_audit tests.test_git_regressions tests.test_git_reference_boundaries -v
python3 -m unittest discover -s tests -t . -p 'test_*.py' -v
```

No production host audit, remote-target probe, expression evaluation, tool installation, GitHub publication or deployment was performed in this follow-up.

## Git scanner corrections — 2026-09-17

Baseline: merged main `698f85eca384ce2bad41e3b3876b85b37d3e67f5`, after the README-only PR. Verified in Debian 13 with Python 3.13.5 and the existing Git 2.47.3. Baseline runtime/test files and edited guides were matched to Git blob identities. Runtime changes are confined to `server_audit/collectors/git_secrets.py` and `server_audit/collectors/git_reader.py`: missing primary configuration prevents an unverified object scan, assignment exclusions match bounded complete references, and NUL-delimited metadata plus Git's typed boolean conversion accepts valid boolean syntax. Ruleset version becomes 2; host schema, candidate regexes, limits and scope stay unchanged.

| Run | Result |
| --- | --- |
| Unmodified baseline suite | 173 discovered; 168 passed, 5 skipped; no failures. |
| Three original review regressions before corrections | All three failed as expected. |
| Same three review regressions after corrections | 3 passed; no skips. |
| Added regression module | 16 passed; no skips. |
| Focused Git detector, reader, packed-storage, pipeline and new regressions | 92 passed; no skips. |
| Complete corrected suite | 189 discovered; 184 passed, 5 skipped; no failures. |

Reproduce the focused and complete runs from the repository root:

```bash
python3 -m unittest tests.test_git_secrets tests.test_git_reader tests.test_git_pack tests.test_git_audit tests.test_git_regressions -v
python3 -m unittest discover -s tests -t . -p 'test_*.py' -v
```

Full-discovery runs used the same unittest loader/runner through a local validation driver with normal Python SIGINT handling. Foreground tool time limits interrupted earlier attempts. An initial detached-shell run inherited ignored SIGINT and failed the two cancellation subcases; restoring normal signal handling in the driver resolved that harness problem without changing tests or runtime shutdown behavior. The passing baseline and corrected runs both include the real SIGINT tests. No validation-driver files are part of the runtime or this repository change.

All original 173 test identities, assertion-call counts and skip gates are retained. The runner contract explicitly expects ruleset 2 without rewriting the historical JSON fixture. One existing fatal-shutdown test fixture now supplies primary config and a mocked format result so it reaches its original shutdown failure path; its assertions remain intact. Existing ruleset-1 and legacy Git reports still render. New tests cover normal/bare SHA-1/SHA-256 storage, preservation of earlier findings and later repositories, synthetic permission denial, literal defaults/concatenation, malformed/truncated reference syntax, native boolean spellings, embedded-newline framing, source immutability and JSON/HTML/text redaction with partial coverage.

The five unchanged skips are one OpenSSH key-generation test (`ssh-keygen` absent) and four explicitly prepared native-lab tests. Native Git and IPv4/IPv6 loopback tests ran; public endpoints stayed mocked. No tool installation, production host audit, external target probe, new native-lab/systemd/Windows or browser validation was performed. The README, HTML template, historical report fixture, CLI options and report/export schemas are unchanged. No new dependency, CI, deployment or release mechanism is introduced. These results are evidence for this revision, not a security certification or exhaustive secret-coverage claim.

## Package layout verification — 2026-09-17

Baseline: merged main `66e930ef4f281be90e38615a5bf484763137328b`. Local environment: Debian 13, Python 3.13.5 and existing Git 2.47.3. All 45 baseline source/document files were matched to their Git blob hashes before editing. This change relocates code, updates imports/mock targets/subprocess imports and the template lookup, and moves shared host fixtures out of the runner test. Collector functions, detection rules, limits, report schemas and command order are not changed.

| Run | Result |
| --- | --- |
| Unmodified baseline | 168 discovered; 163 passed, 5 skipped; no failures. |
| Moved existing suite | Same 168 test cases; 163 passed, same 5 skipped; no failures. |
| New runtime-copy/layout tests | 5 passed; no skips. |
| Complete reorganised suite | 173 discovered; 168 passed, 5 skipped; no failures. |

Deterministic runner, reporting and enriched external fixtures have identical JSON, text and HTML outputs before/after the move. Both root CLI help outputs also match: 11 comparisons in total. `tests/fixtures/audit-contract.json` and `server_audit/templates/report_template.html` retain their original blob identities. Package markers do not eagerly import collectors.

`tests/test_layout.py` copies only the two launchers and runtime package, excludes caches and runs from a different directory without `PYTHONPATH`. It exercises launcher exit codes, all help commands, synthetic host export, caller-relative configuration/repository/export paths, no-network companion dry run and offline import. The host audit function is replaced with a synthetic report; no real host collection occurs. Actual export writes JSON/HTML and a completion manifest using the copied template.

The five unchanged skips are one OpenSSH key-generation test (tool absent) and four explicitly prepared native-lab tests. Native Git storage/process tests ran, including packed-index regressions and cancellation. Loopback tests remain local and public endpoints mocked. Compilation, active command examples and relative documentation links/anchors are checked. No tools installed, production hosts audited, native-lab/systemd/Windows validation or browser visual review performed; HTML bytes and layout are unchanged. No CI, release or deployment workflow is introduced.

## Historical verification records

The following records retain their original versions, totals, scope and command/module names. Some named modules were subsequently replaced or moved. They are historical evidence, not current runnable instructions or repeat validation of the package layout; use [Local setup](../development.md#local-setup) for current commands. File links and references to retained source point to the current locations. The former Gitleaks records do not reintroduce that dependency.

## Packed-storage coverage follow-up — 2026-09-17

Verified against PR #3 head `79a7a6faa8fe548d47db042cace00d65def8abb0` in Debian 13 with Python 3.13.5 and the already installed Git 2.47.3. Runtime modules, tests, template and historical runner fixture matched the reviewed Git blob identities before editing. Only `server_audit/collectors/git_reader.py` and `server_audit/collectors/git_secrets.py` change runtime behavior: check pack/index pairing and observe diagnostic presence without retaining raw stderr. No extra Git command, external tool or dependency is introduced.

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

No external probes, production host audits, installation, CI, packaging or deployment changes were performed. No Windows compatibility run, fully booted systemd validation or new browser visual review is claimed. HTML layout/rendering code are unchanged; the template's Git scope sentence is corrected and synthetic exports verify escaping, metadata, redaction and manifest completion. Previous native/browser validation below is historical, not fresh validation of this change. See [scope limits](../audit-reference.md#git-secrets).

## Scanner shutdown failure follow-up — 2026-09-17

Historical Gitleaks implementation record, superseded by the built-in implementation above. Commands and test names below describe that prior revision.

Verified against branch baseline `796a1547f6fe723f7e7ecd6d2937523d4588b05f` in a Debian 13 Linux container with Python 3.13.5. All original runtime modules, the HTML template, test modules and the historical runner fixture were matched to their GitHub blob hashes before testing. Only `server_audit/collectors/git_secrets.py` changes runtime behavior; the existing reliability mocks were adapted to explicit process/scratch ownership without removing assertions or broadening skip gates.

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

The six full-suite skips remain one native OpenSSH key-generation test (`ssh-keygen` absent), one opt-in real Gitleaks test, and four prepared-lab integration tests. Native IPv4/IPv6 loopback checks passed; public targets were mocked. No tools were installed, production host audits run, external targets probed, or CI/deployment changes made. Real Gitleaks/OpenSSH integration, visual browser review and fully booted systemd-host validation were not performed for this follow-up. Report schema, SSH fields, renderer/template and historical fixture remain unchanged. See [operator handling](../operations.md#scanner-failures-and-interruption) for retained scratch.

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

Tests cover OS permission/read/decode errors, unchanged missing-file fallback, scanner scratch creation/control-file/cleanup failures, evidence preservation across repositories and runner checks, propagated programming errors/interruptions, timeout cleanup, private output/redaction, SSH scope on success and failure, repeated values, legacy rendering and the unchanged schema. The historical `tests/fixtures/audit-contract.json` stays byte-for-byte unchanged; `tests/test_runner.py` explicitly asserts the intended additions and corrected limitation.

The HTML template/layout is unchanged. Synthetic export tests verify escaping, additive evidence, unchanged source JSON and completion manifests. No new visual browser review, real scanner/OpenSSH integration or systemd-host validation is claimed. Earlier native and browser runs below are separate historical evidence; the [documented live gaps](../live-validation.md#remaining-limits) remain open.

## Recorded verification — 2026-09-17

Historical runs preceding the reliability/SSH fix validation above follow. Their environments, counts and remaining gaps describe those runs, not new validation of the current change.

External-verification follow-up: discovery now includes 87 tests. Ubuntu WSL passed 83 with four separately gated live-lab checks skipped; Windows passed 62 with 25 skips. Fifteen new external-workflow tests use loopback sockets or mocked public endpoints. Native IPv6 loopback passed on Ubuntu; Windows denied the control connection with WSAEACCES, so that integration test was explicitly skipped. No external addresses were scanned for implementation validation. Live-lab results remain the separate dated run below.

The initial results below predate the Debian live lab. Follow-up [Debian validation](../live-validation.md) passed all 68 existing tests plus four new opt-in live integration tests and fixed two Docker template failures. Systemd/journal and external reachability limits remain explicit.

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
