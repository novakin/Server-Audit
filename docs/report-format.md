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

## Built-in Git secret evidence

`checks.git_secrets` retains the `status`, `repositories` and `limitations` containers. The additive `detector: "builtin"`, `ruleset_version: 2`, `rule_ids` and `limits` identify the implementation and selected bounds even when the check is not requested. A requested scan without the approved local Git reader is `unavailable`, not a clean or skipped scan.

Ruleset 2 narrows assignment-reference exclusions; rule IDs, candidate regexes, limits and detection field types are unchanged. This can reveal candidates previously suppressed by broad prefixes. Host `schema_version` remains 1. Old reports retain their original detector/ruleset metadata and remain renderable; compare versions and scope before interpreting changed findings. See [reference exclusions](audit-reference.md#ruleset-2-reference-exclusions).

A missing or unreadable primary Git `config` prevents object inspection for that repository. Its status and the overall Git status are partial, an Unknown finding explains the unconfirmed coverage, and neither a successful `local_objects` scan nor an invented `object_format` is emitted. Earlier configuration findings and subsequent repositories survive. Readable ordinary SHA-1 configuration still permits omitted optional format settings. Complete export manifests do not override these coverage failures.

Each repository retains `path`, `status` and `scans`, and adds safe `issues`, `detections_found`, and `elapsed_seconds`. Successful scope resolution records `git_directory`; completed storage preflight records `storage_entries_examined`; recognized storage records `object_format`. Missing fields do not imply success. Current scan modes are:

| Mode | Evidence |
| --- | --- |
| `git_configuration` | Content inspection of `config` and `config.worktree` only, with `files_scanned`. Includes are not followed. |
| `local_objects` | Stored blob/commit/tag bytes, including unreachable objects still present. Records `objects_seen`, `objects_scanned`, `oversized_objects`, `bytes_read`. Tree objects count as seen but are not content-scanned. |

Every detection retains `rule`, `file`, `start_line`, `end_line`, `commit` and adds `object_id`, `object_type`, `byte_offset`. `rule` is a fixed detector ID. Configuration locations use fixed filenames, null object IDs and `object_type: "configuration"`. Stored-object locations use `file: "git-object:<object-id>"`; this is a location label, **not an original working filename**. `commit` contains an ID only when the detection is in that commit object; for blobs/tags/config it is the existing empty-string type, not an invented containing commit. Line numbers are one-based positions of the candidate start in the inspected raw object/config bytes; byte offsets are zero-based. At most one record per rule per line per source is retained. Matching text, values and messages are excluded.

Compatibility decision: host `schema_version` stays at 1 because container shapes and legacy detection field types remain compatible. **Coverage has intentionally changed:** the former Gitleaks `history` and `working_directory` modes are no longer emitted, working files are not scanned, and rules are not equivalent to Gitleaks. Consumers must inspect detector/ruleset/mode before comparing audits; disappearance of an old finding is not proof of remediation. Old Git reports still render, including their original mode names and any legacy scratch-failure fields. The historical runner fixture remains byte-for-byte unchanged; tests assert the intentional new metadata and scope.

Limits and rule definitions are owned by [Git coverage](audit-reference.md#git-secrets). A complete export manifest can contain partial Git coverage; interruption or unconfirmed reader shutdown does not create a completed audit.

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

OS metadata read/decode errors return an `error` check and the runner adds an Unknown finding. Expected Git access, format, workspace and budget failures preserve earlier detections and other repositories: the affected repository is `error` without scan records or `partial` with records, and the overall Git check is `partial` with an Unknown finding. Safe issue messages identify the reason; raw Git stderr and OS error text are withheld. Workspace cleanup failure is recorded as a repository issue. Unconfirmed reader shutdown is fatal and prevents final report export; see [reader handling](operations.md#scanner-failures-and-interruption). Docker/account status semantics are unchanged.

## Export manifest

Current `export_schema_version` is `1`, separate from the report schema. `manifest.json` contains `status`, `exported_at_utc`, `audit_timestamp_utc`, `host` and relative `files` paths. The manifest is published last with `status: complete`; this marks artifact writing completion, not audit coverage success or cryptographic authenticity. The producer does not perform an fsync-based durability guarantee.

Consumers should require a complete manifest, parse the report, verify expected artifacts exist and inspect findings/coverage. A valid manifest alone does not validate the host. See [bundle layout and permissions](operations.md#export-an-audit).

## Compatibility

The package-layout change moves implementation imports to `server_audit.*` and the historical fixture to `tests/fixtures/audit-contract.json`; it does not change `schema_version`, check names, field types, CLI options, collector order or report semantics. The JSON fixture and offline template bytes are preserved. Internal Python import paths are not a supported compatibility API.

Keep existing fields and check names stable where possible. Consumers should tolerate additional fields/checks and handle unfamiliar statuses conservatively. Do not parse human finding messages as stable identifiers. The project currently has no published machine-readable JSON Schema or versioned API support policy.

A breaking report change requires an explicit compatibility decision, schema-version review, updated fixtures/consumers and migration notes in these docs. Historical note: structured `checks.docker` replaced an earlier text-only `checks.docker_ports` field; that older format is not reproduced by current collectors.

The [runner fixture](../tests/fixtures/audit-contract.json) captures the pre-refactor contract. Tests separately assert intentional additions and optional-tool status changes. HTML and text are presentation formats; JSON is preferable for automation.

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
