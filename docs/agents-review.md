# Agent instruction proposal review — 2026-09-17

[Documentation index](../README.md) · [Active project instructions](../AGENTS.md)

This is a historical review of the original instructions, before the built-in Git replacement and package layout. Gitleaks references describe that revision, not current requirements. Code links point to current locations; [AGENTS.md](../AGENTS.md) owns the active layout and external-tool approval policy.

## Scope and outcome

Independent subagent review at xhigh reasoning effort examined the source, current documentation and proposed project instructions. The parent incorporated the refinements below. No architecture blocker was identified in this scope; this was not a full security assessment or a new runtime validation pass.

Keep the explicit runner, focused collectors, standard-library runtime and separate rendering layer. Document consequential architecture decisions in the existing architecture guide with context, alternatives, consequences and verification impact. A separate ADR framework is unnecessary at the current scale.

## Incorporated findings

- Clarified that Git scans must not honor repository-provided Gitleaks configuration, ignore files or allow comments; this is a scan-policy boundary, not merely an export restriction.
- Added the SSH account boundary against reading private keys and password hashes, alongside existing key-output exclusions.
- Made missing-evidence exceptions explicit: requested Git scanning without Gitleaks and no readable kernel firewall backend remain Unknown.
- Corrected the operator tool table: extended ACL detection uses Python `os.getxattr`; `getfacl` is manual follow-up only.
- Corrected integration-test documentation: an unset scanner path/non-Linux platform skips the test; a supplied unusable executable on Linux fails.

## Remaining follow-up

In [audit_runner.py](../server_audit/audit_runner.py), the general SSH limitation says “installed default configuration” even when the caller selects `--ssh-config`. The CLI/guide correctly describe the selected configuration. A focused future change should make this report wording conditional or configuration-neutral and verify both default/custom cases. Runtime code was not changed for this documentation/proposal task.

Follow-up: the reliability/SSH evidence change on 2026-09-17 resolves the wording above and records attempted configuration/context in the SSH check. The original review remains historical; see the [current contract](report-format.md#ssh-scope-and-repeated-settings) and [verification record](development.md#reliability-and-ssh-fixes--2026-09-17).

## Verification and adoption

The proposal's module references, commands and invariants were checked against source; local Markdown links were validated. No tests or host audits were rerun because only documentation changed. Existing runtime verification remains dated in the [development guide](development.md).

The user approved adoption on 2026-09-17. The proposal is now root `AGENTS.md`, with its proposal-only paragraph removed. These project instructions are active; runtime behavior is unchanged. The review findings above remain the historical review record.
