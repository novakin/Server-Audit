# Ubuntu integration CI — acceptance and focused hardening review

Reviewed: 2026-09-18 (Europe/Berlin).

## Accepted CI implementation

PR: https://github.com/novakin/Server-Audit/pull/10

Head: `177e72beb69d93d5703c8b1bee9abd9b73e703b6`.
Tested GitHub merge: `8618aa48248292774dbdf02ddc2c6e01681f13e4`.
Successful run: https://github.com/novakin/Server-Audit/actions/runs/35288664492

- Routine Linux job: 213 discovered, 209 passed, four intentional live-lab skips; no failures/errors. Actual test execution: 4.199 seconds.
- Dependent Ubuntu live job: all four native tests passed, zero skips. Actual test execution: 0.187 seconds; setup/readiness/tests/cleanup step approximately 18 seconds in this run, excluding runner/action setup.
- Ubuntu 24.04.5, Python 3.13.15, Git 2.55.0, Docker 28.0.4, OpenSSH 9.6p1 Ubuntu-3ubuntu13.19, nftables 1.0.9, iptables 1.8.10.
- Existing native-test assertions and activation guards retained. Only the authorized-key fixture path changes, avoiding existing root authorization and unsuitable /opt ancestry.
- Production subtree is unchanged: `75ed96af2e5ab33d178b0c5451382d3138b3b6f1`.
- Bash syntax, refusal without disposable-VM acknowledgement, and four local live-runner policy tests passed. Five stubbed cleanup-exit cases confirmed success, retained original failure, cleanup failure turning success into failure, both failures, and retained interruption status. These are logic checks, not five native cleanup runs.
- Actual earlier hosted setup failures exercised cleanup and failed the job. Final native cleanup also succeeded. Forced termination can prevent traps; disposable VM teardown remains the final boundary.
- Final diff, uploaded file identities, new documentation links and preserved historical development records reviewed. No further CI implementation blocker identified. No code changed after the successful run.

The four routine skips are intentional separation, not missing workflow-level execution. `needs: linux-tests` gates provisioning. Required-status enforcement is separate repository administration; this PR does not configure it, merge itself or deploy anything.

## Focused assessment of the proposed hardening list

This is not a new exhaustive security audit. Runtime source was checked at main `045c1c6c25155e00af67b27806ce0ffbcaa8a280`; the CI PR leaves it unchanged.

### Specific collection-error gap

`server_audit/collectors/system_audit.py`, `collect_reboot_state()`, uses `Path.exists()` without handling inspection errors. Fault injection of `PermissionError` propagated out of the collector. A fully mocked audit reproduced the propagated error and showed later account collection was not reached. No production host or real permission failure was used.

Minimal reproducer from the repository root:

```python
from unittest.mock import patch
from server_audit.collectors import system_audit

with patch.object(system_audit.Path, "exists", side_effect=PermissionError("synthetic denial")):
    system_audit.collect_reboot_state()  # Currently raises PermissionError.
```

Recommended follow-up: distinguish a genuinely missing reboot marker from an unreadable marker; return explicit error/Unknown evidence and preserve later collection. Use a direct metadata operation with separate missing-file and other-I/O handling rather than relying on version-dependent `exists()` error suppression. Add narrow collector and orchestration regressions. No generic exception framework.

### Ordinary command output is not size bounded

`server_audit/command_runner.py` has a 30-second command timeout but uses `capture_output=True` without byte limits. A harmless synthetic process writing 1 MiB to each stream returned all 1,048,576 bytes of stdout and all 1,048,576 bytes of stderr with status `ok`. Source inspection, rather than that particular size alone, establishes the absence of a byte ceiling. This was not a memory-exhaustion test or a measured production incident.

Injected OSError and TimeoutExpired already produced explicit `error` results. Keep those behaviours. A focused follow-up can bound capture while reading, cover both streams and identify incomplete evidence; truncating only presentation or only after capture does not bound memory. Do not redesign unrelated collector interfaces or the separately bounded Git reader.

### Keep or defer

- Real native validation: the current CI change now provides Ubuntu evidence for these four integrations. Historical Debian evidence is not a fresh run of this revision; broader systemd/journal and production-host coverage remains separate.
- Whole-audit/collector deadlines: defer until an operational runtime requirement or measured problem justifies them. Existing per-command and Git scan budgets are not a total-audit deadline.
- Partial timeout output: optional; explicit failure is an acceptable default. Any later retention needs careful incomplete-evidence and privacy semantics.
- CI: implemented, not a future backlog item. Stable finding IDs, priorities and extra report provenance are independent enhancements, not prerequisites for accepting this CI change.

Neither identified runtime follow-up was bundled into PR #10. The next corrective change should address the demonstrated reboot-marker failure first. Output bounding is a justified, separately scoped hardening item; neither calls for a database, plugin system, severity framework or broader compatibility matrix.

## Archiving and action-tracking addendum — 2026-09-18 (Europe/Berlin)

The review above is the original author/assistant assessment retained from the project conversation, not an independent assessment or a new test run. Its reviewed runtime, tested merge, result counts, timings and limits are unchanged. PR #10 was subsequently merged as `a6599fe930bc565b3d13e39eb87faeb964f4b068`; that is delivery evidence, not a new execution of the hardening probes. The documentation-adoption PR records its own verification separately.

Current follow-up state and approval boundaries live in [Issue #11: reboot-marker inspection failures](https://github.com/novakin/Server-Audit/issues/11), [Issue #12: ordinary-command output bounds](https://github.com/novakin/Server-Audit/issues/12), and [Issue #13: required CI checks](https://github.com/novakin/Server-Audit/issues/13). Those links do not imply implementation or completion. The first two are separate runtime work; the third is administrative verification. No speculative deadline, severity model, plugin system or database is made mandatory by this review.

Follow the [review-record policy](README.md) and [work-tracking procedure](../development.md#work-tracking-and-agent-handoff). Do not refresh the original conclusions to match later issue states; use dated corrections when necessary.
