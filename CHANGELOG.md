# Changelog

Selected notable changes; not an exhaustive reconstruction of repository history.
No release version or release date is implied by these entries. Detailed test
results belong in the linked PRs and dated reviews.

## Unreleased

### Added

- Routine Linux CI and dependent Ubuntu SSH/Docker/firewall/socket integration checks ([PR #7](https://github.com/novakin/Server-Audit/pull/7), [PR #10](https://github.com/novakin/Server-Audit/pull/10)). Required-check enforcement is a separate administrative action.
- Documentation consistency and action/evidence ownership rules, a follow-up Issue template, and dated review records. Issues own actionable work; PR descriptions own change-specific acceptance. See the [development procedure](docs/development.md#documentation-maintenance).

### Changed

- Issue handling defaults new agent-created Issues and pull requests to `novakin`, uses a small category/approval label set, and distinguishes resolving Development links from non-closing references. Ownership stays in GitHub metadata; no issue-management bot is added. See [Issue metadata](docs/development.md#issue-metadata).
- Runtime, collectors, templates and tests use a shallow package layout while retaining the two launchers and copy-and-run operation ([PR #4](https://github.com/novakin/Server-Audit/pull/4)). Copy the complete runtime package into a clean destination; do not mix old root modules with it.

### Fixed

- Docker listing validation now retains earlier container inventory and findings when a later ID is malformed, stops further inspection and preserves explicit error/Unknown coverage reporting. Error results retain endpoint and limitations for JSON/HTML/text compatibility; malformed listing text and excluded inspect fields remain unexported ([Issue #26](https://github.com/novakin/Server-Audit/issues/26)).
- The account named exactly `root` with UID `0` retains its full inventory without the two generic sudo/privilege Review findings. Other administrative identities, service accounts and specific root concerns remain visible ([Issue #30](https://github.com/novakin/Server-Audit/issues/30), account portion only).
- Environment-file read advice now describes group/other read bits and makes confidentiality restrictions conditional while preserving required service access. Write/integrity, ancestor, executable/special, ACL and coverage findings remain visible; metadata-only collection and file references are unchanged ([Issue #30](https://github.com/novakin/Server-Audit/issues/30)).
- SSH forwarding advice respects explicit `DisableForwarding yes` while retaining the override and subordinate settings in scalar/multivalue evidence. Disabled or absent overrides preserve existing advice, and unrelated SSH findings remain unchanged ([Issue #25](https://github.com/novakin/Server-Audit/issues/25)). The existing native SSH lab check also evaluates synthetic override cases without changing the daemon or probing forwarding.
- SSH account/key attribution retains selected evaluation scope. User-specific paths apply only to that user; other accounts retain qualified conventional candidates, and shared-key observations no longer imply effective authorization across accounts ([Issue #23](https://github.com/novakin/Server-Audit/issues/23)). Scope fields are additive; findings and Unknown counts intentionally change.
- Unevaluated systemd EnvironmentFile wildcards now retain unknown presence for both optional and mandatory references, with partial coverage and Unknown findings. Repeated native property lines retain every configured reference. Literal bracket filenames, literal absence and independent metadata discovery remain distinct; escaped references remain explicitly unevaluated. No glob expansion or content inspection is added ([Issue #24](https://github.com/novakin/Server-Audit/issues/24)). A fifth opt-in native lab test covers systemd serialization; the existing CI jobs and zero-skip live requirement are preserved.
- Account permission checks no longer treat symbolic-link mode bits as target write access. Link ownership remains checked, uninspected target permissions produce Unknown evidence, and repeated parent-link evidence does not duplicate its findings ([Issue #18](https://github.com/novakin/Server-Audit/issues/18)). Key contents remain subject to the existing no-follow policy.
- Reboot-marker inspection failures now retain explicit error/Unknown evidence and allow unrelated collection to continue, rather than aborting the audit or appearing as an absent marker ([Issue #11](https://github.com/novakin/Server-Audit/issues/11)). Successful results and report schema are unchanged.
- HTML report text uses its available section width, including Scope & limitations. Narrow/enlarged layouts reflow, evidence keyboard focus is visible, direct evidence fragments open their panels, and printed headings stay together ([Issue #17](https://github.com/novakin/Server-Audit/issues/17)). Evidence and report schemas are unchanged.
- Git scan coverage reporting for missing primary configuration, valid Git boolean metadata, and overbroad credential-reference exclusions, including multiline continuations. Detector ruleset 2 identifies the behavior change; report schema remains unchanged ([PR #6](https://github.com/novakin/Server-Audit/pull/6)).
