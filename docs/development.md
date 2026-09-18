# Development and verification

[Documentation index](../README.md) · Internal engineering documentation

Last substantive update: 2026-09-18 (Europe/Berlin).

Maintain the internal tool with focused changes, reproducible fixtures and explicit validation limits.

## Local setup

Use a trusted local copy and Python 3. No third-party Python dependencies are required. Run unit tests as package modules from the repository root. Runtime code lives in `server_audit/`, tests in `tests/`, shared host fixtures in `tests/helpers.py`, Git fixture helpers in `tests/git_helpers.py`, and data in `tests/fixtures/`. No editable install or import-path setup is required. Use Linux or Ubuntu WSL for POSIX coverage; Windows can run portable tests but intentionally skips Linux-specific cases. Avoid running a full host audit when a mocked collector test answers the question.

```bash
python3 -m unittest tests.test_docker_audit -q
python3 -m unittest discover -s tests -t . -p 'test_*.py' -q
```

Native Git tests create disposable local repositories with synthetic candidates using an already installed `git` executable. They run automatically on POSIX when Git is available; no Gitleaks binary or `AUDIT_TEST_GITLEAKS_PATH` is used. Pure detector/CLI tests do not need Git. Do not download or add external tools merely to remove a skip: new integrations require prior explicit user approval under [AGENTS.md](../AGENTS.md#external-tool-approval).

A green suite with skips is not complete native validation. Tests do not grant permission to run a production audit or probe external targets. Record the versions actually used and distinguish synthetic error injection from real permission failures.

Run the layout/copy checks and Git suite directly with:

```bash
python3 -m unittest tests.test_layout -v
python3 -m unittest discover -s tests -t . -p 'test_git_*.py' -v
```

Do not run a test by its file path as a standalone script, or use bare former module names such as `test_runner`. Standard discovery from the root also finds the ordinary `tests` package, but `-s tests -t .` is the documented command. Patch symbols where they are looked up (for example `server_audit.cli.audit` or `server_audit.collectors.git_reader.subprocess.Popen`). Subprocess fixtures use package imports with the repository root as their import directory, not path injection.

## Test ownership

| Tests | Coverage |
| --- | --- |
| `tests/test_ci.py` and `tests/test_live_ci.py` | Routine prerequisites/skip policy and strict live-test acceptance; no native tools required |
| `tests/test_layout.py` | Runtime-only copy, lazy initializers, thin-launcher exit codes, caller-relative paths and no-network companion operations |
| `tests/test_audit.py` | Command failures, network/SSH policy, optional-tool detection and orchestration behavior |
| `tests/test_runner.py` and `tests/fixtures/audit-contract.json` | Existing report shape and ordered command contract, with explicit intentional deltas |
| `tests/test_reliability.py` | Existing OS failure isolation and evidence preservation |
| `tests/test_git_reference_boundaries.py` | Literal/reference exclusions, multiline/comment boundaries, per-line deduplication and loose/packed SHA-1/SHA-256 cases |
| `tests/test_git_regressions.py` | Missing/unreadable primary config, storage-format integration, preserved findings and representative redacted exports |
| `tests/test_git_pack.py` | Native packed-storage failures, evidence preservation and redaction |
| `tests/test_git_reader.py` | Bounded pipes, ungated mocked protocol tests, native boolean-spelling parsing, shutdown/cancellation and native SIGINT |
| `tests/test_git_audit.py` | CLI budgets, failure propagation, no export on abort, redaction and legacy reports |
| `tests/test_ssh_evidence.py` | Attempted SSH scope, repeated values, additive compatibility and export/rendering |
| `tests/test_accounts.py` | Accounts, permissions, keys and observed usage |
| `tests/test_docker_audit.py` | Container projection, findings, absent CLI and daemon failures |
| `tests/test_env_files.py` | Metadata-only file handling, scope limits and application references |
| `tests/test_git_secrets.py` | Built-in rule families, ruleset metadata, synthetic native Git storage, local-only scope, redaction and limits |
| `tests/test_scheduled_tasks.py` | Cron/timers, bounded reads, script references, ownership and redaction |
| `tests/test_reporting.py` | Rendering, escaping, permissions, completion manifests and CLI output |
| `tests/test_live_integrations.py` | Opt-in disposable-lab SSH, Docker, firewall and socket checks; see [fixture contract](live-validation.md#repeatable-live-test-fixture-contract) |
| `tests/test_external_verification.py` | Loopback TCP, mocked public IPv4/IPv6 observations, import/schema limits, scope classification and no-network import/dry run |

Shared host fixtures stay in `tests/helpers.py`. `tests/git_helpers.py` contains only native Git invocation, repository initialization and byte snapshots; callers own temporary directories and assertions. Specialized damaged-storage and cancellation harnesses stay explicit in their tests. Neither helper module collects host evidence at import. Helpers used by one module remain there.

Reference scenarios have one unit-test owner in `test_git_reference_boundaries.py`; representative stored-object and export cases deliberately exercise additional integration boundaries. Cover the full boolean-spelling table at reader level and only implicit, empty, explicit-true and explicit-false forms through the collector in each hash format. Keep malformed mocked protocol cases outside native prerequisite gates. Consolidation must preserve distinct failure scenarios and useful diagnostics, not historical test counts.

## Change checklist

1. Inspect the responsible module and its tests. Preserve unrelated local changes and collected evidence.
2. Add focused regression proof for changed behavior. Use injected command responses and temporary files; include failure/partial paths and redaction checks where relevant.
3. Follow the [collector contract](architecture.md#architecture-and-extending-audits). Preserve explicit prerequisites and keep rendering separate from collection.
4. For layout/import changes, compare the discovered test identities and skip gates with the baseline; exercise packaged subprocess fixtures and the runtime-only copy tests. Run focused tests, then the full suite for changes affecting the runner, report contract or shared helpers. Record platform, failures and skips.
5. For HTML changes, inspect the actual report at desktop/mobile sizes and in light/dark themes. Check overflow, readable statuses, escaping, navigation and print behavior when affected.
6. Assess documentation impact in every PR. Update affected guides, examples and links in the same change, or give a specific no-impact reason in the PR. If report fields/statuses change, update contract tests and [format documentation](report-format.md).
7. Before distributing a snapshot, copy both root launchers and the complete `server_audit/` directory (including its template) into a clean destination, exclude reports/test artifacts, and retain the previous known-good snapshot for rollback. No deployment is implied by a local change.

Do not add a new framework, documentation generator, CI pipeline or release process merely to document this small project. These can be introduced when an actual maintenance requirement exists. Source is maintained in [novakin/Server-Audit](https://github.com/novakin/Server-Audit). Routine CI is defined in [ci.yml](../.github/workflows/ci.yml); release tagging and deployment remain separate, unconfigured workflows. Before committing, review the staged file list and diff. Keep actual host reports, local lab files and scanner binaries out of the source repository; ignore rules cannot cover every custom output path.

## Documentation maintenance

Every change needs an impact assessment; only affected or justified records need an update. Identify the impact, update the owning guide, search related current statements, reconcile contradictions, and record review evidence. A typo fix does not automatically need an Issue, changelog entry, decision record or review file.

| Information | Authoritative home |
| --- | --- |
| Agent duties and safeguards | [AGENTS.md](../AGENTS.md) |
| Current behavior and procedures | Owning guides: [operations](operations.md), [audit reference](audit-reference.md), [architecture](architecture.md), [report format](report-format.md), [live lab](live-validation.md), and this guide |
| Current actionable work, approval and dependencies | [GitHub Issues](https://github.com/novakin/Server-Audit/issues) |
| Change-specific verification and author self-review | PR description; comments for material findings or corrections |
| Substantive historical assessment | [docs/reviews/](reviews/README.md), not a live backlog |
| Direction and conditional opportunities | [Roadmap](roadmap.md), linking to Issues rather than duplicating their statuses |
| Notable user/contributor changes | [CHANGELOG.md](../CHANGELOG.md), not a commit or test log |

For each affected subject, search old names, prerequisites, limits and approval/implementation statements in related README/agent/roadmap/guide sections. Distinguish historical statements from current contradictions. For CI work, check both the workflow procedure and claims such as "CI is proposed" elsewhere. Identify unrelated drift without silently adding a runtime change. Name the checked sections and any gaps in the PR; a generic "documentation checked" is insufficient.

Significant architecture choices belong in the architecture guide; operational-policy choices belong in their owning guide. Include context, decision/status, rationale, alternatives, consequences, verification impact and a revisit condition. Record acceptance date and approval reference only where supported. A proposal, acceptance, code change, merge, release and deployment are different events. No separate decision framework is required for routine edits.

### Dates and historical records

Use YYYY-MM-DD (Europe/Berlin) for new human-written records. Preserve machine timestamps in UTC or with their explicit offset. Do not infer old timezones or update event dates because prose was edited.

Where a guide carries a maintenance date, `Last substantive update` records a change in meaning, not a typo fix. Routine scoped review dates/revisions belong in the PR; `Last reviewed` on a guide is optional and must identify full-guide or section scope. Do not automatically update both fields. Missing historical facts remain unrecorded, not guessed.

A substantial review uses `docs/reviews/YYYY-MM-DD-short-topic.md`, lowercase kebab-case, with the actual review date. Record scope/exclusions, reviewed revision, verification actually performed, evidence, findings, bounded conclusion and follow-up Issue links. Put PR numbers and SHAs inside the record, not necessarily in its filename. Do not create `latest`, `final-v3` or confidence-percentage filenames. Do not rename a report when a finding is resolved.

Preserve original results and limits. Clarify a historical error in a dated addendum, identifying whether new testing occurred. Issues own current resolution status; historical files do not need repeated open/closed updates. No raw chat, private reasoning, credentials, actual host reports or routine CI logs belong in these files. Existing clearly historical records need not move merely to satisfy naming consistency.

Keep `CHANGELOG.md` curated under `Unreleased` until an actual release exists. Include notable behavior, detection, compatibility, operating-requirement or contributor-workflow changes with implementation links. Do not reconstruct every commit or invent releases. Routine reruns, helper renames and minor wording fixes do not each need entries.

### Work tracking and agent handoff

At startup, identify the repository, branch and revision. Read the relevant issue/PR, substantive comments, approved scope, dependencies and owning documentation. Check existing work before creating a duplicate; consult related closed records when evaluating a claimed fix. Use authorized GitHub tools and task-scoped reads, not a full backlog scan for every small edit.

For a project-wide remaining-actions request, list the complete paginated open Issues and PRs. Distinguish Issues from PRs in API collections. Use these searches as starting points:

```text
repo:novakin/Server-Audit is:issue is:open
repo:novakin/Server-Audit is:pr is:open
```

Inspect each relevant item's body, substantive decisions, linked implementation and current checks before reporting it as approved, blocked, pending review/CI or resolved. For an inventory of Guillaume's work, add `assignee:novakin`; do not use that filter for a repository-wide inventory because it would hide unassigned or differently assigned work. An open Issue, assignment or absent label is not implementation approval.

During authorized repository work, proactively create or update a concrete actionable finding that will remain unresolved, unless the task restricts publication. Use the [follow-up template](../.github/ISSUE_TEMPLATE/follow-up.md) for evidence/context, actual versus expected behavior for defects, impact, smallest scope, approval source and observable acceptance criteria; include a bounded synthetic reproducer when relevant. Do not create an Issue for every observation, speculative improvement, small fix completed in the PR or ordinary CI failure being corrected there. Reuse an existing Issue. Recording work does not authorize implementation, remove an in-scope blocker or establish background monitoring.

#### Issue metadata

For this repository, new agent-created Issues default to **`novakin`**, unless the user specifies otherwise. Preserve existing deliberate assignments. Assignees own triage/follow-through, not automatic approval or a deadline. Keep ownership and category in GitHub's **Assignees** and **Labels** fields; do not mirror them in mutable body text. Record a target date only when actually agreed.

The single Markdown template sets `assignees: novakin` for submissions using that template. API-created Issues must explicitly pass `assignees: ["novakin"]` and the selected labels. Blank submissions or other integrations are not covered by this default. No assignment bot or additional workflow is configured.

Normally choose one primary category:

| Label | Use |
| --- | --- |
| `bug` | Existing behavior violates an established requirement or documented contract. |
| `enhancement` | New capability or improvement, including separately justified hardening. No separate feature/improvement labels. |
| `documentation` | The main deliverable is guidance, examples or instructions; not every code change that also updates docs. |
| `maintenance` | Tests, CI, repository settings or behavior-preserving internal upkeep. |

Optional flags are **`needs-approval`** for a pending implementation/scope decision and **`blocked`** for a named prerequisite with an explicit unblocking condition. Ordinary queueing is not blocked. An agent's missing tool access is not automatically a blocker for the assigned maintainer. Record actual approval and its scope before removing `needs-approval`; remove `blocked` when its stated prerequisite is resolved. Neither absence of a flag nor assignment grants permission.

Reuse these approved names; do not expand the vocabulary with a status ladder or a `development` label, or add a project board. Use open/closed state and PR relationships for progress. Do not delete other existing repository labels merely because they are outside this convention. The generic template does not force a category; web submissions can be classified during triage.

Read current metadata before changing it. Prefer additive assignment/label actions; replacement APIs must retain unrelated values. Confirm the write response or read back the Issue: requested metadata can be omitted when access is insufficient. If label listing or application is unavailable, disclose that specific gap rather than invent a catalogue or claim success. See GitHub's [template defaults](https://docs.github.com/en/communities/using-templates-to-encourage-useful-issues-and-pull-requests/configuring-issue-templates-for-your-repository) and [Issue API](https://docs.github.com/en/rest/issues/issues).

#### PR links and resolution

Use GitHub's **Development** relationship for a PR that resolves the Issue. Prefer `Fixes #N` in the **PR description** when merging into the default branch will satisfy the complete acceptance boundary. Do not rely only on a branch name or a commit message to establish the PR relationship. Verify the actual link through an available API or UI; if only the reference was published, state that limitation.

For partial work, historical evidence or separate settings/deployment/target-validation requirements, use a non-closing reference such as `Related to #N`. A plain reference is not a formal Development link; manually linked Development PRs can also auto-close Issues. Do not add a closing relationship merely to make the sidebar look complete. An Issue may span several PRs, and an administrative action need not have a PR at all.

Before authorized merge, confirm the acceptance criteria and required evidence. After merge, check the Issue's actual state: auto-closing depends on default-branch targeting and repository settings. Close manually only when authorized and the full boundary is met. Closed as not planned is not completed; a closed unmerged PR is not delivered. Keep material approval, blocker and verified-resolution decisions in the Issue discussion without narrating every edit. See [GitHub linking semantics](https://docs.github.com/en/issues/tracking-your-work-with-issues/using-issues/linking-a-pull-request-to-an-issue).

Keep one current acceptance record in the PR description, using the [PR template](../.github/pull_request_template.md): reviewed head, tested merge/revision, CI run and actual results, author self-review verdict, documentation impact and unresolved Issue links. Self-review is not independent approval. Use comments only for material findings, changed decisions or corrections of earlier acceptance. After further edits, reassess the relevant delta and identify the new evidence; older results retain their original scope.

Commit substantive documentation before final CI, then record its tested revision/results in the PR. Do not repeatedly commit a document solely to embed its own final SHA or newest test count. CI logs expire under repository retention settings, so the concise PR summary must stand on its own. Long-term release evidence needs a separate retention decision.

Before reporting publication complete, read back the actual written revision, scope, Issue/PR state and relevant CI. Verify administrative settings or deployment independently when required; merging prose does not configure them. Do not retrieve the entire repository or rerun identical checks merely to repeat reassurance.

Issues and PR discussions are not included in an ordinary clone. With GitHub unavailable, read local guidance/evidence but report "current GitHub action status is unverified"; never infer an empty backlog. Preserve any unposted finding as an explicitly unpublished handoff. Do not silently create a second canonical tracker.

Example inventory request: "Follow AGENTS.md. Read current Issues and related PRs, distinguish approved work, proposals, blockers and pending verification, and summarize remaining actions with evidence links. Do not implement anything."

Example implementation request: "Implement Issue #<number> within its approved scope. Update affected documentation, run the required checks, publish revision-specific self-review in the PR and track substantive unresolved findings. Do not merge or deploy."

Adoption/handoff check: using repository instructions and authorized GitHub reads, without relying on chat history, locate the concrete Issues, their approval/dependency state and the next permitted action. Also check that missing access is reported as unverified and that a small editorial change remains small. This is a human/agent walkthrough, not a new CI framework. Report its actual scope in the adoption PR rather than claim an independent agent was run.

## Continuous integration

[CI](../.github/workflows/ci.yml) starts with the `Linux tests` job on GitHub-hosted `ubuntu-24.04` with Python `3.13`. Pull requests (including stacked PRs), pushes to `main` and manual dispatch use the same routine suite. Documentation-only PRs follow the same two-job sequence; documentation accuracy still requires reviewing examples, links and claims.

The workflow compiles Python files, then invokes the standard-library [CI runner](../tests/ci.py) once:

```bash
python -m tests.ci
```

Run from the repository root. The runner requires Linux, Git and `ssh-keygen`; it installs nothing. The official setup-python action may provision Python on the disposable runner. Preflight refuses an enabled `AUDIT_LIVE_INTEGRATION`. Missing prerequisites, zero tests, test failures and unexpected skips fail the job. Only the four exact prepared-lab test identities listed in `tests/ci.py` may be skipped; additions or changes require review. There is no fixed total-test-count gate. Use ordinary unittest locally where those CI prerequisites are unavailable, and disclose its skips rather than weakening the CI policy.

Tests use disposable repositories, synthetic credentials, mocked public endpoints and loopback sockets. This job does not provision the SSH/Docker/firewall lab, audit production or deploy anything. After it succeeds, the separate `Ubuntu live integration` job prepares and checks those services on a fresh hosted VM, as described below.

The two official actions are pinned to full commit SHAs, with release labels in comments. Review upstream changes before updating those pins. Token permissions are `contents: read`, checkout does not persist credentials, and no production secrets are passed to tests. There are no caches, third-party testing packages, artifact uploads or privileged PR triggers. The routine job has a ten-minute timeout; the integration job has a twenty-minute timeout; a newer run cancels obsolete work for the same PR/ref.

Logs record OS/Python/Git versions and revision IDs; the job summary reports results and skip reasons. On a PR, the tested revision is the default checkout merge revision, not just the contributor's head SHA. Targeted tests are for local iteration; do not duplicate the focused Git suite and full suite within the same CI job. Push revised code and use its new CI result before approval.

### Why both PR and post-merge checks run

Decision retained on 2026-09-18 (Europe/Berlin): keep PR checks, pushes to `main` and manual dispatch. The trigger implementation is in [PR #7](https://github.com/novakin/Server-Audit/pull/7); the dependent live job is in [PR #10](https://github.com/novakin/Server-Audit/pull/10). This documentation records the user-approved decision to retain the existing behavior, not a new workflow change.

PR checks validate the proposed merge before acceptance. Push checks validate the revision that landed, including direct pushes. Both can test identical tracked files; that repetition is an accepted trade-off for a simple workflow and independent verification of `main`. A different SHA alone does not mean different source.

Post-merge checks detect problems after landing; they do not replace required pre-merge checks. Track enforcement in [Issue #13](https://github.com/novakin/Server-Audit/issues/13), rather than copying its current state here. Reconsider PR-only execution when up-to-date successful PR validation and bypass/direct-push controls are verified and duplicate execution has meaningful cost. Do not add custom result reuse merely to eliminate small repeat runs. [GitHub event semantics](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows) explain the tested revisions.

### Ubuntu live integration

`Ubuntu live integration` declares `needs: linux-tests`. It is not scheduled when routine tests fail or are skipped; a later push starts a new workflow run. Both jobs use the same event revision on separate hosted Ubuntu 24.04 VMs. All four live checks share one lab; they are not four separately provisioned jobs.

The [lab script](../tests/integration_lab.sh) installs native fixture packages, generates temporary keys, starts a loopback-only SSH daemon, imports a local BusyBox image and creates the two expected containers. It adds unhooked firewall evidence chains without flushing existing rules. Setup is allowed only with root and an explicit disposable-VM acknowledgement, and refuses conflicting fixture paths, containers, image names and firewall resources. These guards are not a sandbox: the fresh hosted VM is the isolation boundary. Never run preparation on an operational server.

The [live runner](../tests/live_ci.py) requires the exact four test identities excluded by routine CI. All must execute and pass with zero skips or expected failures. Provisioning, readiness, test and cleanup failures fail the job. Readiness is polled within deadlines. EXIT/INT/TERM handling cleans lab-owned processes, keys, containers, image, files and firewall resources; an original failure remains a failure even when cleanup also fails. Forced termination can prevent traps, so VM disposal remains the final boundary. Packages are not uninstalled; they disappear with the VM.

No registry image, self-hosted runner, external probe target or new runtime dependency is introduced. Package downloads occur only during CI setup. This job validates the recorded Ubuntu toolchain, not every Ubuntu release or a new Debian run. See [live validation](live-validation.md#automated-ubuntu-lab) for the fixture contract, invocation and evidence limits.

### Make the checks required

After both jobs have succeeded on GitHub, a repository administrator should require both `Linux tests` and `Ubuntu live integration` for `main`, preferably bound to the GitHub Actions app. Requiring both avoids treating an integration job skipped after an upstream failure as successful overall verification. Retain existing access and review rules. The workflow does not configure branch protection, and a running job is not proof of enforcement. Verify the setting in repository rules/branch protection; availability depends on repository plan and permissions. Do not claim enforcement until it is read back successfully.

For stacked work, merge the dependency first, retarget the dependent PR to `main` and confirm successful checks on the resulting revision. Do not merge a dependent change into its temporary base branch.

### Documentation and completion

Use the [PR template](../.github/pull_request_template.md) and [work-tracking procedure](#work-tracking-and-agent-handoff). API-created PRs must explicitly populate the same sections. The author assesses documentation meaning; CI checks executable requirements. Do not require a Markdown edit for every change, add a documentation bot/link-check framework, query live Issue state from runtime tests, or grant workflow write permissions merely to post an AI acceptance. [AGENTS.md](../AGENTS.md#pr-completion) defines readiness.

## Final revised-corrections verification — 2026-09-17

Historical record: [Final revised-corrections verification — 2026-09-17](reviews/2026-09-17-development-verification.md#final-revised-corrections-verification--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Multiline reference-boundary follow-up — 2026-09-17

Historical record: [Multiline reference-boundary follow-up — 2026-09-17](reviews/2026-09-17-development-verification.md#multiline-reference-boundary-follow-up--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Git scanner corrections — 2026-09-17

Historical record: [Git scanner corrections — 2026-09-17](reviews/2026-09-17-development-verification.md#git-scanner-corrections--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Package layout verification — 2026-09-17

Historical record: [Package layout verification — 2026-09-17](reviews/2026-09-17-development-verification.md#package-layout-verification--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Historical verification records

Historical record: [Historical verification records](reviews/2026-09-17-development-verification.md#historical-verification-records). Original dates, revisions and results are preserved; this pointer is not a new run.

## Packed-storage coverage follow-up — 2026-09-17

Historical record: [Packed-storage coverage follow-up — 2026-09-17](reviews/2026-09-17-development-verification.md#packed-storage-coverage-follow-up--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Built-in local Git inspection — 2026-09-17

Historical record: [Built-in local Git inspection — 2026-09-17](reviews/2026-09-17-development-verification.md#built-in-local-git-inspection--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Scanner shutdown failure follow-up — 2026-09-17

Historical record: [Scanner shutdown failure follow-up — 2026-09-17](reviews/2026-09-17-development-verification.md#scanner-shutdown-failure-follow-up--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Reliability and SSH fixes — 2026-09-17

Historical record: [Reliability and SSH fixes — 2026-09-17](reviews/2026-09-17-development-verification.md#reliability-and-ssh-fixes--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.

## Recorded verification — 2026-09-17

Historical record: [Recorded verification — 2026-09-17](reviews/2026-09-17-development-verification.md#recorded-verification--2026-09-17). Original dates, revisions and results are preserved; this pointer is not a new run.
