# Server-Audit roadmap

[Documentation index](../README.md) · Reviewed 2026-09-17

## Objective and approval boundary

Make the existing read-only auditor reliable to run, accurate to interpret and straightforward to validate. Preserve the explicit runner, focused collectors and offline reports until a concrete requirement justifies a change.

The approved implementation scope is **R1–R4, with their tests and owning documentation**. The roadmap itself is a reviewed plan, not authorization to implement its other entries. CI, packaging, new checks and broader hardening are not included in this change. No target dates, budgets, operational owners or release commitments have been assigned.

## Current delivery: four fixes

Baseline reviewed: `2f1a9d64d23dbb3c759d76c23a2e476cc8936c64`. Status on this review branch: implemented and locally tested; merge and deployment are separate decisions. See the [verification record](development.md#reliability-and-ssh-fixes--2026-09-17) for commands, results and skips.

| ID | Outcome | Acceptance criteria and evidence |
| --- | --- | --- |
| R1 | Expected OS read and Git scratch failures preserve other evidence. | OS read/decode errors become an error check, not a clean fallback. Scratch setup/write/cleanup failures remain explicit; later repositories and unrelated checks survive. Programming errors are not swallowed. [Tests](../test_reliability.py), [handling](operations.md#scanner-failures-and-interruption). |
| R2 | Interrupted scanners stop before scratch cleanup. | Timeout and KeyboardInterrupt use the same cleanup; the POSIX process group is stopped and the scanner reaped. Interruption propagates without a completed scan/report. Real synthetic SIGINT regression passes. [Implementation](../git_secrets.py), [tests](../test_reliability.py). |
| R3 | Reports identify the attempted SSH configuration and context. | Scope remains visible on success, missing tools and tool failures. Text/JSON/HTML retain it; limitation wording matches on-disk scope rather than claiming running-daemon identity. [Contract](report-format.md#ssh-scope-and-repeated-settings), [tests](../test_ssh_evidence.py). |
| R4 | Structured SSH evidence preserves repeated settings. | Ordered lists retain every selected occurrence. Legacy scalar fields, raw output and existing policy findings remain compatible; report schema stays at 1. The historical fixture is unchanged, with intentional deltas asserted in [runner tests](../test_runner.py). |

Stop implementation here. Documentation and tests travel with the fixes, not as deferred cleanup. A passing suite with disclosed skips is acceptable evidence for this patch, not certification of a production server or completion of native integrations.

## Recommended next: separate approval required

Priority here is sequencing, not security severity. V1 and V2 are independent; neither needs a plugin system, release pipeline or new testing framework.

| ID / status | Smallest useful scope | Start condition | Done when |
| --- | --- | --- | --- |
| V1 — Proposed next | One Linux CI job using one explicit Python version and the existing unittest command. | Approval to add a test workflow; select its tested Python baseline and required native tools. | PRs/main pushes produce commit-linked results; an intentional failing assertion fails the job. Use read-only repository permissions, reviewed pinned action revisions, nonpersistent checkout credentials and a timeout. Disclose optional skips. No production credentials, host audits, external probes, deployment or report uploads. |
| V2 — Proposed next validation | A repeatable run on a disposable, fully booted Ubuntu/Debian systemd host for services, timers, EnvironmentFiles and journal-based key use. | An explicitly authorized disposable environment is available. | Record exact versions, sanitized fixtures, results and gaps for native serialization and key-use correlation. Do not represent one host as a distribution support matrix. Existing [lab limits](live-validation.md#remaining-limits) remain open until this is done. |
| H1 — Proposed later | Bound scanner-report ingestion before JSON parsing; define byte/detection limits and the incomplete-result policy. | R1–R2 accepted; agree limits against representative synthetic results. | Oversize and excessive-detection tests produce Unknown/incomplete evidence without exporting secrets or reading unlimited JSON first. Limits are documented; do not claim this also bounds the scanner's own memory/disk consumption. |

A general native-command output-capture rewrite is not part of H1. Measure representative output volumes and assess privacy before selecting a buffering design. Slicing a fully captured string is not a collection-memory limit.

## Conditional opportunities, not promised milestones

| ID | Trigger | First implementation to assess | Acceptance boundary |
| --- | --- | --- | --- |
| D1 — Repeatable distribution | Repeated server copies, another operator, or a need for identifiable rollback snapshots. | A reviewed version/tag, short notes and a runtime/template archive built from an explicit file allowlist. | Test the actual extracted archive using CLI help and synthetic export; identify its revision and exclude reports, credentials, scanner binaries and caches. No installer/auto-updater, runtime Git dependency, public publication or deployment implied. |
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

Self-review completed against the code, report contract, active instructions and recorded verification. The plan separates approved fixes from proposals, gives each active/candidate item an acceptance boundary, distinguishes local testing from native validation, preserves privacy/compatibility and removes invented dates or automatic commitments. This is planning review, not an independent security assessment or a guarantee of future outcomes.

Maintain this one roadmap. When approving an item, record its owner if assigned, status, linked PR and verification evidence; mark Done only after the accepted change is merged, and track deployment separately. Review priorities after R1–R4 rather than automatically starting every candidate. `AGENTS.md` remains authoritative for agent behavior; detailed runtime facts belong in the linked owning guides.
