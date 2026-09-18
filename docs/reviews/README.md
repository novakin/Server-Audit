# Historical reviews and validation records

These records describe their stated revisions, not today's backlog. [GitHub Issues](https://github.com/novakin/Server-Audit/issues) own current actionable work; [development](../development.md#work-tracking-and-agent-handoff) explains approval, evidence and handoff. Routine self-reviews and CI results belong in the PR description, not a new file for every PR.

| Record | Purpose |
| --- | --- |
| [2026-09-18 code and functional assessment](2026-09-18-code-functional-assessment.md) | Original assessment and proportionality clarification, with separate revision reconciliation and canonical follow-up Issues |
| [2026-09-18 Ubuntu CI and hardening](2026-09-18-ubuntu-ci-hardening.md) | Original CI acceptance and focused runtime findings, with canonical follow-up Issues |
| [2026-09-17 development verification](2026-09-17-development-verification.md) | Preserved pre-CI execution history; commands/results remain tied to their original revisions |
| [2026-09-17 Debian live validation](2026-09-17-debian-live-validation.md) | Historical Debian namespace/chroot validation, not a current Ubuntu or fresh Debian run |
| [Historical agent-instruction review](../agents-review.md) | Earlier instruction assessment, retained at its existing path |

Use `YYYY-MM-DD-short-topic.md` for new substantive records, dated in Europe/Berlin. Include scope/exclusions, reviewed revision, verification actually performed, evidence, bounded conclusion and Issue links. Older date-only records keep their recorded date and disclose missing timezone information. Preserve historical findings; dated addenda correct errors without implying a new test run. Do not duplicate live issue status, raw chat, private reasoning, credentials, host reports or routine logs. See [date and record conventions](../development.md#dates-and-historical-records).
