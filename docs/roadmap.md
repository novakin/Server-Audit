# Server-Audit roadmap

[Documentation index](../README.md)

Last substantive update: 2026-10-05 (Europe/Berlin), reconciling the September improvement sequence, merged deliveries through PR #40 and remaining native-validation scope.

## Objective and approval boundary

Make the existing read-only auditor reliable to run, accurate to interpret and straightforward to validate. Preserve the explicit runner, focused collectors and offline reports until a concrete requirement justifies a change.

The recorded deliveries below cover R1–R4, G1, L1, the separately approved CI work and subsequent correctness/reporting improvements. The roadmap describes direction and conditional opportunities; [GitHub Issues](https://github.com/novakin/Server-Audit/issues) own current actionable work, scope approval and dependencies. This document does not authorize implementation of other entries. Packaging, additional checks and broader hardening remain separate proposals. New external-tool integrations require explicit approval before implementation; see [AGENTS.md](../AGENTS.md#external-tool-approval). No target dates, budgets or release commitments have been assigned; assigned owners are recorded in GitHub metadata.

## Merged delivery: four fixes

Baseline reviewed: `2f1a9d64d23dbb3c759d76c23a2e476cc8936c64`. R1–R4 and the shutdown follow-up were merged in [PR #1](https://github.com/novakin/Server-Audit/pull/1), merge commit `ab9af662`. Deployment remains separate. The historical scanner-specific implementation is now superseded by G1; its error/cancellation invariants remain required. See the [verification record](development.md#reliability-and-ssh-fixes--2026-09-17) for commands, results and skips.

| ID | Outcome | Acceptance criteria and evidence |
| --- | --- | --- |
| R1 | Expected OS read and Git scratch failures preserve other evidence. | OS read/decode errors become an error check, not a clean fallback. Scratch setup/write/cleanup failures remain explicit; later repositories and unrelated checks survive. Programming errors are not swallowed. [Tests](../tests/test_reliability.py), [handling](operations.md#scanner-failures-and-interruption). |
| R2 | Interrupted scanners stop before scratch cleanup. | Timeout and KeyboardInterrupt use the same cleanup; the POSIX process group is stopped and the scanner reaped. Interruption propagates without a completed scan/report. Real synthetic SIGINT regression passes. [Current reader](../server_audit/collectors/git_reader.py), [reader tests](../tests/test_git_reader.py), [pipeline tests](../tests/test_git_audit.py). |
| R3 | Reports identify the attempted SSH configuration and context. | Scope remains visible on success, missing tools and tool failures. Text/JSON/HTML retain it; limitation wording matches on-disk scope rather than claiming running-daemon identity. [Contract](report-format.md#ssh-scope-and-repeated-settings), [tests](../tests/test_ssh_evidence.py). |
| R4 | Structured SSH evidence preserves repeated settings. | Ordered lists retain every selected occurrence. Legacy scalar fields, raw output and existing policy findings remain compatible; report schema stays at 1. The historical fixture is unchanged, with intentional deltas asserted in [runner tests](../tests/test_runner.py). |

Do not implement additional proposals without approval. Documentation and tests travel with the fixes, not as deferred cleanup. A passing suite with disclosed skips is acceptable evidence for this patch, not certification of a production server or completion of native integrations.

## G1 — Approved built-in local Git replacement

Status: merged in [PR #3](https://github.com/novakin/Server-Audit/pull/3), merge commit `66e930ef`, including the packed-storage follow-up. Deployment remains separate. Replaces Gitleaks with Python candidate rules. The local Git executable is explicitly approved only to read config storage-format metadata and stored objects. The default per-repository budget is 60 seconds and can be selected through the CLI. No additional external tool or service is authorized.

Acceptance: inspect config and locally stored blob/commit/tag bytes, including packed/delta and unreachable objects still present; no working-file scan or remote fetch; redacted locations only; bounded input/time/counts; retain earlier findings on incomplete reads; preserve fatal cancellation/unconfirmed-shutdown behavior. Tests cover native storage and injected failures. See [scope](audit-reference.md#git-secrets), [decision](architecture.md#decision-built-in-local-git-secret-inspection) and [verification](development.md#built-in-local-git-inspection--2026-09-17). `AGENTS.md` now explicitly requires user approval before any new external-tool integration.

## L1 — Approved repository layout

Status: merged in [PR #4](https://github.com/novakin/Server-Audit/pull/4), commit `c5b8a655667187847fe083578361de3ac71291c7`. Deployment remains separate. Keep the two launchers at root; move runtime into `server_audit/`, checks into `server_audit/collectors/`, the template into `server_audit/templates/`, and tests/fixtures into `tests/`. Retain the explicit runner, approval policy and copy-and-run operation. The layout change itself approved no new dependency, installer, CI, generic utility layer or behavioural feature; later CI approval is recorded separately below.

Original layout acceptance: all previous test cases and skip gates retained; unchanged fixture/template bytes and deterministic JSON/text/HTML; both launchers and offline companion operations work from a runtime-only copy in another directory; user-relative paths preserved; module/mock/subprocess imports, agent guidance, runtime file lists and local documentation links updated. See [layout decision](architecture.md#decision-runtime-package-and-test-layout), [tests](../tests/test_layout.py) and [verification](development.md#package-layout-verification--2026-09-17). D1 distribution automation remains a separate proposal; a packaging smoke test does not authorise a release pipeline.

## V1 — Delivered CI and current follow-up entry points

The original one-job CI proposal was implemented in [PR #7](https://github.com/novakin/Server-Audit/pull/7). [PR #10](https://github.com/novakin/Server-Audit/pull/10) added the separately approved Ubuntu lab job after successful routine tests. Both are merged; a workflow is not proof of mandatory merge enforcement or deployment. The [development guide](development.md#continuous-integration) owns current operation and the [dated Ubuntu review](reviews/2026-09-18-ubuntu-ci-hardening.md) preserves revision-specific acceptance and hardening evidence.

[PR #33](https://github.com/novakin/Server-Audit/pull/33) extended the existing lab with a fifth native EnvironmentFile case; PRs [#32](https://github.com/novakin/Server-Audit/pull/32) and [#34](https://github.com/novakin/Server-Audit/pull/34) also extended SSH attribution/override validation. All five live cases passed with zero skips on merged `main` revision `802b8e1bd48238b2182cbb994834ed327ec8119d` in [run 37350754830](https://github.com/novakin/Server-Audit/actions/runs/37350754830). This recorded Ubuntu evidence does not complete V2's timer/journal scope; [live validation](live-validation.md) owns the current fixture contract and limits.

[PR #6](https://github.com/novakin/Server-Audit/pull/6) also merged the subsequent Git coverage/configuration/reference-boundary corrections, identifying detection behavior as ruleset 2. The original G1 rationale above remains historical delivery context; the [audit reference](audit-reference.md#git-secrets) owns current behavior.

Concrete follow-ups have one authoritative record each: [reboot-marker error isolation, #11](https://github.com/novakin/Server-Audit/issues/11), [ordinary-command output bounding, #12](https://github.com/novakin/Server-Audit/issues/12), and [required-check administration, #13](https://github.com/novakin/Server-Audit/issues/13). Read those Issues for current status, approval and dependencies; do not infer permission from this list. Recording or linking them does not implement their changes.

## September improvement sequence: delivery reconciliation

The [original seven-step assessment](reviews/2026-09-18-code-functional-assessment.md#6-recommended-implementation-sequence) remains historical. The table below records implementation deliveries verified on 2026-10-05 (Europe/Berlin), through merged main revision `802b8e1bd48238b2182cbb994834ed327ec8119d`; Issues and PR acceptance records own subsequent decisions and verification.

| Original step | Delivered scope and evidence | Remaining boundary |
| --- | --- | --- |
| 1 — SSH account/key attribution | [PR #32](https://github.com/novakin/Server-Audit/pull/32), [#23](https://github.com/novakin/Server-Audit/issues/23): selected user scope, qualified fallback/shared observations and native different-user key-path evaluation. | Observed candidate files do not prove effective authorization or running-daemon identity. |
| 2 — EnvironmentFile wildcards | [PR #33](https://github.com/novakin/Server-Audit/pull/33), [#24](https://github.com/novakin/Server-Audit/issues/24): optional/mandatory unevaluated references remain Unknown, independent discovery survives, and native properties are validated. | Actual process environment loading and full wildcard expansion are outside this metadata-only correction. |
| 3 — Reboot-marker error isolation | [PR #20](https://github.com/novakin/Server-Audit/pull/20), [#11](https://github.com/novakin/Server-Audit/issues/11): read failures preserve error/Unknown and later collection. | No additional work inferred from its presence in the historical sequence. |
| 4 — SSH forwarding overrides | [PR #34](https://github.com/novakin/Server-Audit/pull/34), [#25](https://github.com/novakin/Server-Audit/issues/25): yes/no/absent override advice and native evaluations. | No broader authentication-policy engine or live forwarding probe. |
| 5 — Parsing/application coverage | [PR #40](https://github.com/novakin/Server-Audit/pull/40), [#27](https://github.com/novakin/Server-Audit/issues/27) and [#28](https://github.com/novakin/Server-Audit/issues/28): retained valid listeners, parser counts and explicit Docker reference coverage. | Existing aggregate status meanings are preserved; collection success is not complete coverage. |
| 6 — Docker inventory resilience | [PR #37](https://github.com/novakin/Server-Audit/pull/37), [#26](https://github.com/novakin/Server-Audit/issues/26): stop at malformed listing entries while retaining earlier inventory and incomplete evidence. | Malformed synthetic output does not establish a production incident. |
| 7 — Report context/native coverage | [PR #40](https://github.com/novakin/Server-Audit/pull/40), [#31](https://github.com/novakin/Server-Audit/issues/31): explicit resource metadata/grouping with full findings, filtering and print inclusion preserved; native EnvironmentFile/SSH coverage above. | V2 timer and journal correlation remain separate work in [#41](https://github.com/novakin/Server-Audit/issues/41). Full PDF pagination and assistive-technology behavior remain unverified. |

Related improvements were also delivered: symbolic-link mode handling ([PR #22](https://github.com/novakin/Server-Audit/pull/22), [#18](https://github.com/novakin/Server-Audit/issues/18)); canonical-root noise and qualified file-read advice ([PR #35](https://github.com/novakin/Server-Audit/pull/35), [PR #36](https://github.com/novakin/Server-Audit/pull/36), [#30](https://github.com/novakin/Server-Audit/issues/30)); and native output limits plus cron privacy/link coverage ([PR #40](https://github.com/novakin/Server-Audit/pull/40), [#12](https://github.com/novakin/Server-Audit/issues/12), [#38](https://github.com/novakin/Server-Audit/issues/38), [#39](https://github.com/novakin/Server-Audit/issues/39)). The [whole-code reassessment](reviews/2026-10-05-codebase-quality-review.md) explains the selected scope and rating; it does not replace the earlier plan or authorize conditional opportunities.

## Recommended next: separate approval required

Priority here is sequencing, not security severity. V2 is broader than the five Ubuntu native cases already delivered. EnvironmentFile properties are exercised; native timer/service metadata and journal-based key-use correlation are not. [Issue #41](https://github.com/novakin/Server-Audit/issues/41) owns the remaining V2 scope/environment decision and acceptance. [Issue #13](https://github.com/novakin/Server-Audit/issues/13) independently owns mandatory pre-merge checks: readback on 2026-10-05 (Europe/Berlin) found main unprotected with no applicable branch rules. Successful jobs do not establish enforcement.

| ID / status | Smallest useful scope | Start condition | Done when |
| --- | --- | --- | --- |
| V2 — Remaining native validation | Reuse the existing lab for native timer/service metadata and journal-based key-use correlation; retain delivered EnvironmentFile coverage. | The bounded fixture/provisioning scope and disposable, fully booted Ubuntu or Debian systemd environment are explicitly approved in [#41](https://github.com/novakin/Server-Audit/issues/41). | Record exact versions, synthetic fixtures, revision-specific native results, redaction and cleanup proof. Complete the accepted timer/journal scope with zero live skips; retain other [lab limits](live-validation.md#remaining-limits). One supported environment can satisfy V2; it is not a distribution matrix or proof of actual application environment loading. |
| H1 — Superseded by G1 | Gitleaks report ingestion is removed; the new local reader bounds data before capture. | Covered by the approved G1 scope, not a separate scanner integration. | Byte/object/detection/time limits and partial-result tests pass. Native Git internal memory is not claimed to be capped. |

Ordinary native-command bounding was delivered separately in [PR #40](https://github.com/novakin/Server-Audit/pull/40) for [#12](https://github.com/novakin/Server-Audit/issues/12), rather than being part of H1/G1. The [operations guide](operations.md) owns the fixed per-stream limits and incomplete-output policy; slicing after capture is not used as a collection-memory limit.

## Conditional opportunities, not promised milestones

| ID | Trigger | First implementation to assess | Acceptance boundary |
| --- | --- | --- | --- |
| D1 — Repeatable distribution | Repeated server copies, another operator, or a need for identifiable rollback snapshots. | A reviewed version/tag, short notes and a runtime/template archive built from an explicit file allowlist. | Test the actual extracted archive using CLI help and synthetic export; identify its revision and exclude reports, credentials, scanner binaries and caches. No installer/auto-updater, additional distribution dependency, public publication or deployment implied; the separately approved Git reader remains opt-in. |
| C1 — Offline comparison | Repeated audits create a concrete need to review changes. | Compare two JSON snapshots; add stable finding identifiers only where necessary. | Check host/scope/schema comparability. Missing evidence is not a resolved issue. Do not match solely by human finding text. No database or web service required. |
| P1 — Targeted performance | Measured duration on authorized representative runs is operationally unacceptable. | Measure collector costs and improve the slowest operation or bounded independent subset. | Preserve prerequisite order, deterministic assembly, privacy and interruption behavior; demonstrate an improvement against the baseline. No general concurrency rewrite by default. |

New audit coverage needs a named unanswered operational question, defined scope/privacy/failure behavior, synthetic regressions and a native-validation plan before approval.

## Architecture options: reassess only on evidence

| Option | Reconsider when | Simpler first step |
| --- | --- | --- |
| Plugin registry | Collectors genuinely need independent development/distribution without editing the runner; privileged code-loading trust is addressed. | Explicit imports and ordered calls. More collectors alone are not sufficient. |
| Collector base classes | Repeated lifecycle behavior is inconsistent and functions no longer keep it maintainable. | One focused shared helper. |
| Dependency-injection framework | Multiple implementations/lifecycles make explicit arguments demonstrably difficult. | Existing injected command functions. |
| Database | Necessary cross-host/history queries exceed a practical file workflow. | Offline comparison or a local index. |
| Web service | Reviewers require authenticated central access with assigned ownership, access control, retention and support. | Offline report improvements and controlled transfer; treat hosting as a separate product/security decision. |
| Automatic remediation | A separately approved workflow defines authorization, validation and rollback. | Human-reviewed recommendations; consider a separate opt-in companion, not changes to the read-only auditor. |

A trigger initiates a decision; it does not approve an architecture. CI and distribution are separate choices, not reasons to introduce these layers.

## Review and maintenance

The linked records distinguish approved deliveries, proposals and verification limits. A documentation update is not an independent security assessment or a fresh runtime validation. Review scope and source revision belong in the change PR; avoid an undated blanket acceptance claim here.

Keep this roadmap focused on direction, conditional triggers and linked delivery rationale. Actionable work belongs in Issues; approvals, owners when assigned, blockers and verified resolution belong there, not in a second status table. A completed code fix requires its accepted merge/evidence; deployment and repository administration require their own verification. Reassess priorities instead of automatically starting every candidate. `AGENTS.md` remains authoritative for agent behavior; detailed runtime facts belong in the linked owning guides.
