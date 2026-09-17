# Server security audit — project instructions

## Scope and starting points

This is an internal, read-only Ubuntu/Debian host audit using Python's standard library and available native tools. Read [README.md](README.md), then the relevant guide before changing behavior. The audit collects evidence; it does not certify security, prove external reachability or issue malware verdicts.

## External-tool approval

- Do not add, install, download, vendor, invoke or integrate a new external tool, scanner, third-party Python package or remote service without explicit user approval **before implementation**. Explain the exact dependency, purpose, alternatives, data access and maintenance implications first. An opt-in flag is not approval, and a useful feature request does not implicitly approve a dependency.
- Existing native host tools documented in the operator runbook remain in scope; this rule is not an instruction to remove unrelated integrations. Reuse within their existing purpose is allowed. A new tool or materially expanded use requires approval.
- For Git secret inspection, the approved exception is the local `git` executable strictly as a storage reader. Python owns detection. Do not reintroduce Gitleaks or another scanner, add network credential checks, or implement a Git packfile parser without a separately approved task.

## Repository layout

- Put runtime implementation in `server_audit/`, checks and domain-specific helpers in `server_audit/collectors/`, and runtime assets in `server_audit/templates/`. Keep `git_reader.py` beside `git_secrets.py`; it is not the ordinary command runner. Preserve the explicit runner and keep package `__init__.py` files free of eager imports or collection side effects.
- Put test modules in `tests/`, shared host fixtures in `tests/helpers.py`, and test data in `tests/fixtures/`. Keep genuinely shared domain-specific setup in small helpers such as `tests/git_helpers.py`; do not add universal fixture base classes. Helpers used by only one module stay there. Import shared fixtures rather than another test module. Run tests as package modules from the repository root; do not inject paths into `sys.path` or require `PYTHONPATH`.
- Keep `README.md`, `AGENTS.md`, repository settings and the two launchers at the root. Detailed guidance stays in `docs/`. Do not add generic utility layers, per-collector packages or a build/install workflow merely to place files in directories.
- Resolve templates relative to their owning module. Never change the process working directory to repair imports: relative user input and export paths remain relative to the caller. Document deployment as the two launchers plus the full runtime package, excluding caches and tests; use a clean destination instead of mixing old root modules with the package layout.

## Architecture and coding

- Keep root `audit.py` and `external_probe.py` as thin launchers only. `server_audit/cli.py` owns host CLI/platform setup and output selection, `server_audit/audit_runner.py` owns explicit collection order, collectors own evidence and interpretation, and `server_audit/reporting.py` owns presentation/export. Renderers must not run checks or create a second set of policy findings.
- Extend the responsible module first. Prefer small functions and pure parsers where useful. Follow existing names and data shapes. Prefer meaningful names, intermediate variables and ordinary control flow over code golf, nested conditional expressions or dense comprehensions that mix decisions and side effects. Extract helpers for repeated behavior with the same responsibility, not speculative reuse. Add a framework, registry or abstraction only when a concrete requirement justifies its maintenance cost; keep unrelated cleanup out of the change.
- Major collectors return JSON-serializable `(check, findings)` results; existing grouped domain helpers may retain their mapping interfaces. Do not print inside collectors. Inject the native command function so tests can supply deterministic responses.
- Preserve prerequisites: SSH collection precedes accounts; running-service and Docker evidence precede application environment sources. Keep order explicit rather than introducing a dependency scheduler.
- Use `server_audit/command_runner.py` for ordinary native tools, with argument lists and no shell execution. Preserve executable lookup, locale and deadlines. Use `server_audit/collectors/git_reader.py` for secret-bearing Git pipes: bounded capture, shared repository deadlines, isolated configuration and redacted diagnostics. Drain stderr without retaining its text; diagnostic presence makes coverage incomplete even with exit code zero. Stop/reap readers on timeout or interruption; unconfirmed shutdown is fatal and retains the private reader workspace. Cancellation must not become a completed report.
- Handle expected I/O, parsing and tool failures where their meaning is known. Return explicit incomplete/error evidence; do not swallow failures or convert them into a clean empty inventory. Avoid blanket exception handling that hides programming defects.
- Bound added filesystem/content scans and report limits reached. Never execute, source, expand or decode inspected payloads. Preserve each collector's documented link/special-file policy.

## Evidence and privacy invariants

- Keep host audits read-only: no installation, package refresh, configuration changes, chmod/chown, service startup, container execution or automatic remote probing. Report exports and generated private Git-reader metadata are intentional writes; inspected content is never copied into the reader workspace. The separately invoked external companion may connect only to explicitly selected targets; preserve its dry-run, bounds and offline import boundary.
- Preserve metadata-only `.env` inspection. Do not collect environment variable names/values or process environments. Docker may collect configured variable counts and allowlisted metadata only.
- Git content scanning requires explicit repository selection. Inspect only local configuration and stored objects, not working files. Export fixed rule IDs and locations, never secrets, matching text or commit messages. Do not execute source-repository policy, honor suppression comments or follow config includes/alternate stores/worktree indirection. Preserve limits, disabled protocols/lazy fetching and explicit incomplete coverage. Decoding Git storage through the approved reader is not permission to decode or execute inspected payloads.
- Scheduled-task collection must not export raw commands, script bodies, assignment values or matched payload strings. SSH account collection must not read private keys or password hashes; exported key evidence excludes public-key blobs, comments and option values.
- These exclusions are collector-specific. Native evidence can still contain sensitive operational details. Treat reports, logs and `.artifacts` as restricted data; use synthetic fixtures, never real credentials, in tests/docs.
- Preserve private, unique export directories and files, escaped HTML, offline assets and manifest-last completion. Do not replace incomplete export evidence with a success marker or silently overwrite an earlier audit.

## Status and compatibility

- Follow [report-format.md](docs/report-format.md). Missing optional tools may be `skipped` with a reason. Unselected opt-in checks are `not_requested`. Access denial, tool failure and unreachable daemons are not absence. A requested Git scan without its approved Git reader remains unavailable/Unknown; no readable kernel firewall backend produces a consolidated Unknown finding.
- `ok` means collection succeeded within scope, not that the host is secure. Keep nested failures visible. Collectors returning `partial` must emit an explanatory `UNKNOWN` finding; the runner does not infer all nested failures.
- Retain explicitly selected SSH configuration/context in report metadata, including failed attempts. Keep legacy scalar settings compatible and preserve repeated values in additive evidence.
- Preserve stable check names and fields. Intentional changes require updated consumers/tests and compatibility notes. Review schema-version implications before breaking the report contract; do not parse human finding messages as stable identifiers.
- Preserve the historical runner fixture. Assert intentional differences explicitly rather than rewriting the baseline to hide regressions.

## Verification

- Run affected tests first, for example `python3 -m unittest tests.test_docker_audit -q`. Run `python3 -m unittest discover -s tests -t . -p 'test_*.py' -q` for runner, shared helper, schema or cross-collector changes.
- Tests should exercise meaningful behavior and failure/redaction boundaries with injected command responses or temporary files. Test names must describe what their assertions prove. Preserve distinct regression scenarios and representative integration boundaries, not historical test or assertion counts. Consolidate duplicates without weakening assertions or broadening skips. Do not require root, a live daemon or developer-specific `.artifacts` paths for unit tests.
- Use Linux/Ubuntu WSL for POSIX behavior. Report platform, skipped tests and remaining integration gaps. Native Git tests use disposable synthetic repositories and an already installed Git executable; never download dependencies merely to remove a skip. A Windows pass does not establish Linux correctness.
- Use fixtures before a full host audit. A local code review or test task does not require collecting real host evidence. Live validation and distribution should stay within the user's requested scope.
- For affected HTML behavior, check real output at mobile/desktop sizes and light/dark themes. Preserve readable Review/Unknown states, uppercase SSH, the single-line “Host security audit.” title, escaping and offline operation. Check print/filter behavior when changed.
- For documentation-only changes, validate relative links, examples and claims against source; do not run host audits or repeat unrelated manual tests merely to update prose. The standard short CI job still runs automatically on documentation PRs.

## Documentation and decisions

- Assess documentation impact in every PR. Correct affected guides, examples, links and summaries in the same PR before merge, or give a specific no-impact reason. Do not require cosmetic Markdown edits. Keep [README.md](README.md) as the entry point. Update the owning guide in the same change: [operations](docs/operations.md) for setup/CLI/handling; [audit reference](docs/audit-reference.md) for scope and limits; [architecture](docs/architecture.md) for ownership/extensions; [report format](docs/report-format.md) for fields/statuses; [development](docs/development.md) for verification.
- Link to detailed facts instead of copying them into multiple guides. Distinguish implemented behavior, proposed behavior and dated verification. Do not invent supported versions, successful checks, operational owners, retention periods or release infrastructure.
- Record consequential architecture decisions in `docs/architecture.md`: context/problem, decision and status, alternatives considered, consequences/limits, and verification or migration impact. Routine local edits do not need decision records. Introduce separate ADR files only if decision history outgrows that page.
- Revisit an architecture decision when a concrete requirement changes its tradeoffs. Preserve the rationale and note what superseded it; do not treat the existing layout or standard-library choice as a permanent ban on justified evolution.
- When runtime layout or deployment requirements change, update the affected deployment lists, imports, mock targets, fixture/template lookups, documentation links and command examples. Verify copy-and-run from an unrelated working directory and retain the historical fixture bytes. Keep generated reports and local scanner binaries out of source distribution. Do not introduce CI, packaging or publication workflows without a task requiring them.

## Routine CI

The approved CI integration uses GitHub-hosted Ubuntu, official checkout/setup-python actions pinned to reviewed commit SHAs, and the standard-library runner `python -m tests.ci`. It requires existing Git and OpenSSH tools, rejects unexpected skips, and never enables the prepared lab or runs production audits. Keep permissions read-only, checkout credentials unpersisted, and test data synthetic. Do not use privileged PR triggers or add deployment, scanners or third-party test packages without separate approval. See [development workflow](docs/development.md#continuous-integration).

## PR completion

- Review the final diff for correctness, failure paths, readability, unnecessary complexity and unintended scope changes before presenting it as ready. Do not wait for an additional user request for self-review.
- Assess documentation impact and fill in the PR template explicitly, including PRs created through an API. Keep routine execution results in the PR and CI, not another growing verification-history section in the guides.
- Report checks actually run, their tested revision, failures, skips and limitations. Results from older code do not validate a changed implementation; a CI workflow file is not evidence that the job ran or is required for merge.
- Identify unresolved blockers. Distinguish local changes, published branches, open PRs, merges and deployment. Do not merge or deploy without authorization.
- Preserve unrelated work and evidence artifacts. Prefer the smallest clear solution that satisfies the requirements without weakening safety, evidence or compatibility guarantees.
