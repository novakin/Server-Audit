# Agent instruction proposal review — 2026-09-17

[Documentation index](../README.md) · [Inactive proposal](../AGENTS.proposed.md)

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

In [audit_runner.py](../audit_runner.py), the general SSH limitation says “installed default configuration” even when the caller selects `--ssh-config`. The CLI/guide correctly describe the selected configuration. A focused future change should make this report wording conditional or configuration-neutral and verify both default/custom cases. Runtime code was not changed for this documentation/proposal task.

## Verification and adoption

The proposal's module references, commands and invariants were checked against source; local Markdown links were validated. No tests or host audits were rerun because only documentation changed. Existing runtime verification remains dated in the [development guide](development.md).

`AGENTS.proposed.md` is deliberately inactive. Adoption would rename it to root `AGENTS.md` and remove its proposal-only paragraph. No active agent instruction file, runtime behavior, deployment or release was changed.
