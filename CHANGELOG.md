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

- HTML report text uses its available section width, including Scope & limitations. Narrow/enlarged layouts reflow, evidence keyboard focus is visible, direct evidence fragments open their panels, and printed headings stay together ([Issue #17](https://github.com/novakin/Server-Audit/issues/17)). Evidence and report schemas are unchanged.
- Git scan coverage reporting for missing primary configuration, valid Git boolean metadata, and overbroad credential-reference exclusions, including multiline continuations. Detector ruleset 2 identifies the behavior change; report schema remains unchanged ([PR #6](https://github.com/novakin/Server-Audit/pull/6)).
