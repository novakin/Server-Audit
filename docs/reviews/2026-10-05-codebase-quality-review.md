# Codebase quality plan and reassessment

Assessment date: **2026-10-05 (Europe/Berlin)**. Assistant assessment with an Ultra supporting plan/source review, not independent human approval or security certification.

## Scope and approval

Baseline: `main` at [`bb7d3f4a42f5b59827342ecf13761435c01940ef`](https://github.com/novakin/Server-Audit/commit/bb7d3f4a42f5b59827342ecf13761435c01940ef). The preceding whole-code review rated this baseline approximately 80/100 and reproduced scheduled-task privacy and coverage defects. This record assesses the resulting local `improve/codebase-quality-20261005` change set. The [implementation PR #40](https://github.com/novakin/Server-Audit/pull/40) owns the final reviewed head, CI-tested revision/run, readiness and merge state; this document is not a live backlog.

The owner requested creation of both scheduled-task issues, implementation of an Ultra improvement plan, then clarified the objective as the highest defensible rating rather than a 90/100 threshold. Subsequent requests confirmed PR publication, documentation and closure of solved issues. Issue closure follows verified merge; publication is not merge or deployment. No production host audit, new runtime dependency, operational-host package install, repository-policy mutation or deployment was performed by this task. The separately approved hosted integration job may provision native fixture packages on its disposable VM.

## Selected plan and results

1. **Cron privacy, [#38](https://github.com/novakin/Server-Audit/issues/38):** separate the first unquoted shell control boundary from literal paths, retain quoted/escaped names, exclude percent-delimited cron stdin with correct escape parity, and keep timer argv interpretation separate. Unsupported tails, invalid quoting, NUL-bearing paths and dynamic references remain redacted incomplete evidence. Regression exports prove synthetic assignment/stdin values absent from JSON, HTML and text.
2. **Cron coverage, [#39](https://github.com/novakin/Server-Audit/issues/39):** distinguish missing main crontab from links and metadata errors with no-follow presence inspection. Valid/dangling links remain partial/Unknown and later collection survives.
3. **Native capture, [#12](https://github.com/novakin/Server-Audit/issues/12):** enforce independent 8 MiB stdout / 1 MiB stderr raw-byte caps while concurrently draining pipes and delivering optional stdin. Preserve completed success/nonzero records and locale/newline behavior. Overflow, deadline and capture failure withhold both streams. Owned process-group shutdown/reaping handles pipe-owning descendants and cancellation; unconfirmed shutdown aborts. Default main-thread Python SIGINT is deferred across construction until cleanup owns the child, without changing ignored/custom handlers.
4. **Socket interpretation, [#27](https://github.com/novakin/Server-Audit/issues/27):** preserve valid rows/raw evidence and command status while reporting observed/parsed/unparsed counts and one Unknown when short nonblank records are lost.
5. **Application coverage, [#28](https://github.com/novakin/Server-Audit/issues/28):** expose fixed Docker coverage explanations and retained/successfully inspected counts alongside independent discovery. Keep documented aggregate meanings and existing authoritative Docker findings, avoiding duplicate warnings or a global status redesign.
6. **Report scanability, [#31](https://github.com/novakin/Server-Audit/issues/31):** add optional known resource metadata at responsible finding producers and group only in HTML. Preserve full messages/levels, duplicate findings, flat JSON order and legacy fallback. Fixed totals are labelled, search includes the displayed group identity for every row, filters hide empty groups, and print restores all parents/rows. Semantic headings, stacked mobile counts, 44-pixel filter controls and single-line UTC display retain the existing visual direction. Full collector scope notes use expandable topics while general boundaries stay visible; no notes are suppressed.

The correctness changes intentionally add incomplete-coverage findings in affected cases. Grouping uses the corrected behavior as its starting point; it makes no additional policy/message/count change. Historical fixture bytes are unchanged, with tests asserting intentional additive fields separately. Neither message parsing nor a generic resource registry, relationship graph, plugin system or scoring model was introduced.

## Review findings and corrections

The Ultra final review found and verified fixes for three additional boundaries: every same-resource row must match the displayed heading even with missing/different display metadata; a periodic script's permission and pattern findings must share the same resource type/identity; and interruption during shutdown followed by failed kill/reap must retain cancellation classification. The native-capture author also reproduced and corrected the process-construction SIGINT ownership gap with an actual synthetic signal. All cases have focused regressions. The final source review found no remaining in-scope blocker; it is an assistant review rather than independent maintainer approval.

Architecture remains explicit: collectors own interpretation/metadata, the ordinary runner owns native process lifecycle, the Git reader retains its separate secret-bearing boundary, orchestration labels common failures, and reporting only presents existing evidence. Audit-wide/collective findings remain general rather than receiving invented identities.

## Reassessment

**Approximately 92/100 (9.2/10)** is defensible for the reviewed implementation once its PR's required hosted jobs pass. This is a subjective whole-codebase judgment, not measured compliance, a promise of perfection or a host-security score.

| Area | Assessment |
| --- | --- |
| Architecture and maintainability | 9/10: clear ownership and small domain helpers; added native-pipe complexity is necessary for capture/cancellation invariants. |
| Collector correctness | 9/10: confirmed interpretation/privacy gaps corrected, existing valid evidence retained, conservative scope made visible. |
| Failure handling and limits | 9.2/10: output bounded before retention and process lifecycle tested at failure/cancellation boundaries; OS process creation is not itself preempted by the capture deadline. |
| Privacy and exports | 9.5/10: deliberate metadata/redaction boundaries, regression export proof, escaped offline HTML and private unique manifest-last bundles. Reports still contain intentionally sensitive operational metadata. |
| Tests and validation | 9.2/10: meaningful parser, native-process, storage, compatibility and rendering regressions; a wider OS/Python/native-tool matrix remains unproven. |
| Reporting and documentation | 9.3/10: semantic grouping, explicit totals/coverage and retained scope notes; full PDF pagination and assistive-technology certification remain unverified. |

No arbitrary additional collectors or frameworks were added to raise a score. Further work should follow concrete operator requirements or observed failures rather than a numerical chase.

## Verification basis and limits

Repository-native routine tests were run on Ubuntu WSL/Python 3.12.3, including real synthetic process capture, simultaneous streams, stdin, deadline, overflow, actual spawn-time SIGINT and descendant cleanup. The routine runner allows exactly the five prepared-lab skips; hosted live validation remains the separate required PR gate. Test/run identities and final results belong to the PR acceptance record.

Chrome DevTools MCP checked synthetic offline output at 1440-pixel desktop and 390/320-pixel mobile sizes, light/dark themes, long/escaped labels and enlarged text. Metadata-plus-level search, empty groups/results, fixed totals, semantic/unique headings, and script-free fallback were checked. Print CSS was activated in the browser with print events: all findings/parents and evidence/scope topics became visible, with prior open state restored afterward. This verifies inclusion/restoration, not complete PDF pagination or assistive-technology behavior. Generated stress-test reports and logs remain private local artifacts and are not shipped.

Owning operation, architecture, audit-reference and report-format guidance, README and Unreleased notes were updated. Roadmap and AGENTS statements were checked without relabelling historical deliveries or introducing another live backlog. Main required-check enforcement was read back as disabled with no applicable branch rules during this review; [#13](https://github.com/novakin/Server-Audit/issues/13) remains a separate administrative action. Green CI is not enforcement.
