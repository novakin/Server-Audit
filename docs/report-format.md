# Report format and status semantics

[Documentation index](../README.md) · Internal engineering documentation · Reviewed 2026-09-17

Contract for internal consumers of JSON, text and HTML. Read status and limitations together; no field is a security pass score.

## JSON report

The authoritative serialized evidence is `data/report.json` in an export bundle, or stdout from `--json`. Both use the same assembled report. Current `schema_version` is `1`.

| Top-level field | Meaning |
| --- | --- |
| `schema_version` | Report format identifier |
| `timestamp_utc` | Audit start timestamp as an ISO 8601 UTC string |
| `host` | Host identity reported by the local platform |
| `checks` | Mapping of stable check names to collector evidence dictionaries |
| `findings` | List of `{level, message}` records; current levels `REVIEW` and `UNKNOWN` |
| `summary` | Counts of top-level findings by level, not counts of vulnerable services |
| `limitations` | General scope limitations; collectors can also supply their own `limitations` |

Evidence shapes differ by collector. Inspect the matching collector and tests when consuming nested data. Account/native-command records may contain status/output/detail; inventories use structured objects. Missing fields, null values and empty inventories have different meanings. Do not treat an absent inventory as an empty successful scan.

## SSH scope and repeated settings

The following additive fields in `checks.ssh` do not change `schema_version: 1`:

| Field | Contract |
| --- | --- |
| `configuration_source` | `default` or `custom`, recording the configuration selection attempted, even if collection fails. |
| `configuration_path` | The `--ssh-config` argument exactly as supplied, or `null` for the sshd default. A relative argument is not a resolved absolute path or proof of the running daemon's configuration. |
| `connection_context` | The `--ssh-context` argument exactly as supplied, or `null`. It describes the requested evaluation, not an observed SSH session. |
| `selected_settings` | Existing scalar mapping, unchanged: the last occurrence for each selected setting. Retained for older consumers; not a complete multivalue inventory. |
| `selected_setting_values` | On successful collection, the same selected keys mapped to lists of all observed values in output order, including single occurrences. Each value is one entire value portion of an output line; it is not additionally tokenized. |

For example, `port 22` followed by `port 2222` retains legacy `selected_settings.port: "2222"` and adds `selected_setting_values.port: ["22", "2222"]`. `listenaddress` and any other repeated selected key receive the same treatment. Raw `output` and existing policy findings are preserved. Failed collection has attempted scope but no invented effective settings.

Consumers needing all values should prefer the new map. For older reports without it, inspect raw output rather than assuming the legacy scalar is complete. Old reports still render. New text reports add scope lines before SSH raw evidence; HTML exposes the additive fields in collected evidence. The general SSH limitation now describes the selected on-disk configuration, not unconditionally the installed default. No evidence establishes what configuration the running daemon loaded.

## Check statuses

| Status | Meaning |
| --- | --- |
| `ok` | Collection succeeded in the stated scope; findings or nested failures may still exist |
| `skipped` | Optional prerequisite missing; reason retained; no successful inspection implied |
| `not_requested` | Opt-in collection was not selected, currently Git secret scanning |
| `unavailable` | Required evidence/tool unavailable; review coverage findings |
| `error` | Collection failed, including denied access, tool failure or timeout |
| `partial` | Some evidence collected but coverage incomplete; collector must emit an Unknown finding |

Nested records may use additional domain statuses such as `unknown`, `inspected` or `binary_metadata_only`. Do not apply the top-level table blindly to every nested object. In particular, Docker can have top-level `ok` while one container inspection failed; inspect findings and nested statuses.

`REVIEW` means observed evidence merits a local decision. `UNKNOWN` means a relevant conclusion cannot be reached from available evidence. There is no severity ranking, compliance certification or malware verdict. Missing optional firewall tools do not create individual findings, but lack of any readable kernel backend creates a consolidated Unknown finding.

OS metadata read/decode errors return an `error` check and the runner adds an Unknown finding. Requested Git scratch setup/access errors preserve other evidence: affected repositories are `error` without scan evidence or `partial` with evidence, and the overall Git check is `partial` with an Unknown finding. On cleanup failure, the repository additionally records `cleanup_status: error` and `scratch_path`; report handling remains restricted. See [scanner handling](operations.md#scanner-failures-and-interruption). These changes do not redefine Docker/account statuses or turn interruption into a completed report.

## Export manifest

Current `export_schema_version` is `1`, separate from the report schema. `manifest.json` contains `status`, `exported_at_utc`, `audit_timestamp_utc`, `host` and relative `files` paths. The manifest is published last with `status: complete`; this marks artifact writing completion, not audit coverage success or cryptographic authenticity. The producer does not perform an fsync-based durability guarantee.

Consumers should require a complete manifest, parse the report, verify expected artifacts exist and inspect findings/coverage. A valid manifest alone does not validate the host. See [bundle layout and permissions](operations.md#export-an-audit).

## Compatibility

Keep existing fields and check names stable where possible. Consumers should tolerate additional fields/checks and handle unfamiliar statuses conservatively. Do not parse human finding messages as stable identifiers. The project currently has no published machine-readable JSON Schema or versioned API support policy.

A breaking report change requires an explicit compatibility decision, schema-version review, updated fixtures/consumers and migration notes in these docs. Historical note: structured `checks.docker` replaced an earlier text-only `checks.docker_ports` field; that older format is not reproduced by current collectors.

The [runner fixture](../fixtures/audit-contract.json) captures the pre-refactor contract. Tests separately assert intentional additions and optional-tool status changes. HTML and text are presentation formats; JSON is preferable for automation.

## External verification extension

The optional `checks.external_verification` check is added only by offline companion import, not by host collection. Host `schema_version: 1`, original audit timestamp, existing checks and findings are retained. The export manifest gets a new export time and unique folder. Import refuses an already enriched source; import all chosen probe files into the original snapshot together.

| Field | Meaning |
| --- | --- |
| `status` | `ok` for interpretable selected-scope observations; `partial` when Unknown observations or stale correlation exist |
| `observations` | Derived exposure rows, including untested local-inventory ports |
| `probes` | Validated, allowlisted source probe documents; no unknown imported fields retained |
| `limitations` | Source assertion, scope, timing and attribution limits |

Each observation records `target`, `port`, `family`, `protocol`, `observation`, `observed_at_utc`, `source_address`, `location`, `exposure`, `reason` and `local_candidates`. Tested rows also contain `snapshot_age_seconds`. Untested inventory rows have target/family `Not tested`, observation `not_tested`, null observation time/source address and exposure `unknown`; they are coverage markers rather than network attempts.

The three exposure values are `externally reachable`, `not observed from this probe` and `unknown`. These are distinct from collector statuses and finding levels. Connected TCP endpoints only receive the reachable label for public/global addresses with an explicit independent-source assertion. A negative observation never becomes a “secure” or “protected” verdict.

Probe documents use independent `probe_schema_version: 1` and contain `audit` (host, timestamp and host schema), `targets`, `ports`, `location`, `probe_host`, `independent`, `timeout_seconds`, `started_at_utc`, `finished_at_utc` and `results`. Each result includes target/port/family, protocol `tcp`, timestamp, optional local source address and one raw observation: `connected`, `refused`, `timeout` or `local_or_network_error`. All declared address/port pairs must appear exactly once. Times are timezone-aware ISO 8601 strings.

These files are not authenticated evidence. Bounds, validation, clock handling, private storage and exact CLI usage are documented in the [external-verification runbook](external-verification.md).
