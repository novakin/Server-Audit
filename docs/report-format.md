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
| `findings` | Flat list of `{level, message}` records with optional grouping metadata; current levels `REVIEW` and `UNKNOWN` |
| `summary` | Counts of top-level findings by level, not counts of vulnerable services |
| `limitations` | General scope limitations; collectors can also supply their own `limitations` |

Evidence shapes differ by collector. Inspect the matching collector and tests when consuming nested data. Account/native-command records may contain status/output/detail; inventories use structured objects. Missing fields, null values and empty inventories have different meanings. Do not treat an absent inventory as an empty successful scan.

## Finding metadata and grouped HTML

New finding producers can add `check`, `resource_type`, `resource_id` and `resource_name`. `check` uses an existing check key. The resource identity is `(check, resource_type, resource_id)`; `resource_name` is display/search text only. All fields are optional strings. These fields are additive within schema version 1: levels, full messages and the flat JSON finding sequence are retained. Grouping never deduplicates findings or changes detection policy.

| Resource | Identity convention |
| --- | --- |
| Docker container | Full daemon-provided container ID; name is display metadata |
| Account | Account username within the snapshot |
| Shared SSH key | Observed fingerprint, attributed once to the shared key rather than copied under every account |
| Environment file / ancestor directory | Collected path string, without new filesystem resolution |
| Git repository | Selected repository path string |
| Selected SSH configuration/context | JSON-encoded configuration/context pair; the existing selected scope remains authoritative |
| Scheduled definition / referenced script / timer | Definition/script path or timer unit name; parent-permission findings use the directory path |
| System service | Unit name when a finding concerns one known service |
| External endpoint | Protocol, literal target and port; IPv6 targets are bracketed in the ID |

HTML groups checks and resources in first-appearance order and retains original finding order within each group. Separate IDs with identical display names remain separate groups. A known check without a complete resource identity uses its General bucket. Findings without a meaningful single check, including audit-wide and collective firewall findings, remain under General findings. Older reports and mixed legacy/new findings render without inferred identities; messages are never parsed as keys.

Every finding appears once, including identical duplicates, with its complete message and level. Check/resource badges display separate **fixed totals** for Review and Unknown and explicitly say Totals. Search combines finding text, resource display/identity metadata and the displayed resource heading. Filters hide unmatched rows and empty groups while global/group totals remain unchanged; one live result message announces the shown finding count. Print restores every group and row regardless of screen filters and uses the same complete totals. Resource headings are semantic `h4` headings below check `h3` headings; findings remain visible without JavaScript and are not placed in accordions.

The visible capture time is formatted in UTC on one line where it fits, for example `01 Jan 2026 - 12:00:00 UTC`; machine timestamps remain ISO 8601.

General scope boundaries stay visible. Full collector limitations are retained under expandable topics using their existing check ownership, including repeated notes; no text-based classification or suppression is performed. Print opens these topics alongside collected evidence and restores their prior state afterward.

## Native-command capture and parser coverage

Ordinary host commands have a 30-second capture/execution deadline and fixed raw-byte caps of 8 MiB stdout and 1 MiB stderr, enforced independently during concurrent pipe reads. This allows substantial normal inventories while bounding retained output; exceeding a cap is incomplete collection rather than a successful truncated inventory. Deadline, overflow or capture/pipe-cleanup failure returns `error` with a payload-free explanation and withholds both captured streams, including partial output. Normal completed nonzero commands retain their bounded stdout/stderr and exit code. Cancellation propagates after shutdown rather than generating a completed report; unconfirmed shutdown aborts the audit. Shutdown has a separate bounded cleanup allowance. The secret-bearing Git reader keeps its separate existing limits and diagnostics policy.

Successful socket collection adds `checks.ports.parser_coverage` with `status`, `records_observed`, `records_parsed` and `records_unparsed`. Counts cover nonblank records. Short nonempty rows produce parser `partial` and one explanatory Unknown while valid listeners and existing raw output survive. The top native command status remains `ok`: it describes command collection, not complete interpretation. Empty successful output has all-zero counts and parser `ok`; wholly unparsed nonempty output remains visibly different.

## Application-source coverage

`checks.environment_files.applications.status` retains its existing systemd-reference aggregate meaning; it is not a promise that every Docker container was inspected. `docker_status` retains the source inventory status. Additive `docker_coverage` contains a fixed safe `detail`, `status`, `containers_retained` and `containers_inspected` (successful inspections). Retained containers are a lower bound when inventory failed. Optional Docker absence is `skipped`, missing evidence is `unavailable`, inventory/inspection failures are `partial`, and successful empty or fully inspected inventories are `ok` within the documented endpoint scope.

HTML and text show this explanation/counts alongside application sources. Independent directory discovery and successful sources survive. Existing Docker collector/runner Unknown findings remain authoritative; this clarification adds no duplicate finding or global status redesign. Older reports without the additive field still render their existing source evidence.

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

`disableforwarding` is included in both selected-setting maps when present, alongside the retained `allowtcpforwarding` and `x11forwarding` values. An explicit scalar `yes` prevents contradictory TCP/X11 recommendations; `no` and absent values retain existing advice. Missing values are not invented, repeated values retain their order and legacy last-value interpretation, and raw output remains unchanged. This additive evidence remains within schema version 1; findings/counts intentionally change for an explicit override, rather than being preserved as a presentation-only change.

## Account key-path scope

`checks.accounts.ssh_scope` retains the selected SSH check's `status`, `configuration_source`, `configuration_path` and `connection_context`, including failed attempts. Each account adds `key_path_scope` with `source`, `applicability` and an explanatory `detail`. `applicability: "selected_context"` means the successful evaluation names that account; it does not establish every connection or the running daemon's behavior. `applicability: "unknown"` identifies conventional fallback, context without an unambiguous user, or base-configuration candidates without per-account Match evaluation. An Unknown finding summarizes accounts with unverified applicability.

A user-specific path is not reused for unrelated accounts. Those accounts retain conventional candidate files and observations. Output without a user context retains selected candidates with uncertainty instead of claiming universal applicability or dropping the inventory. Failed SSH output is not used for paths. The existing top-level `key_path_source` indicates whether AuthorizedKeysFile was available in selected output; consumers must use each account's new scope for applicability. Legacy direct collector calls supplying only output have unknown configuration provenance and no evaluated connection context.

Shared-key Review messages describe fingerprints observed in candidate files for multiple accounts and qualify effective authorization as unverified. This intentionally changes finding wording and can add Unknown counts; it is a policy correction separate from presentation-only grouping. Existing key-file field shapes, status types and privacy exclusions remain unchanged. Schema version 1 is retained for these additive fields. JSON/HTML evidence includes the scope; text adds explicit scope lines. Older records without these fields still render without invented applicability.

## Account permission evidence

Only an account with `user: "root"` and `uid: 0` is exempt from the two generic sudo-grant and UID/privileged-group Review findings. Account inventory fields, command evidence and specific root-related findings are unchanged. Other UID-0 identities and noncanonical `root` accounts retain applicable reviews; service-account shells do not filter the inventory. New audits can have fewer Review findings for normal root, but renderers preserve findings in older reports. This changes finding policy rather than presentation and does not change schema version 1.

Entries in `checks.accounts.accounts[].permissions` retain `path`, `mode`, `owner_uid`, `symlink` and Boolean `unsafe` when metadata is available. For ordinary files/directories, `unsafe` still flags an owner other than root/the account or group/other write bits. For `symlink: true`, it evaluates **link ownership only**, not mode bits or target access. An additional `unknown` explanation identifies uninspected target permissions; `unsafe: false` is not a safe-target verdict. The collector emits an Unknown finding for that uncertainty and a separate ownership-specific Review finding when needed. Identical repeated symlink records retain their evidence but do not repeat their findings within one account.

A failed metadata lookup retains `path` and `unknown` rather than inventing a mode or `unsafe` value. The account collection status remains `ok` for a collected inventory with nested uncertainty; read its findings and permission records. Schema version 1 and existing field types are unchanged. Older reports retain their original findings when rendered; only a new audit uses the corrected interpretation. See [account scope](audit-reference.md#accounts-access-and-ssh-keys).

## Unevaluated systemd environment references

In `checks.environment_files.applications.sources[].files`, every native `EnvironmentFiles=` property line is retained, as are combined reference lists. Wildcard systemd EnvironmentFile references retain `path` and `optional` and add `status: "unknown"` and an explanatory `detail`. Their containing systemd source and application-reference aggregate are `partial`; the environment-file check also becomes `partial` and emits explicit Unknown evidence. A matching file might exist, but an unevaluated pattern establishes neither its presence nor its absence. The `skipped` record retains the pattern, reason, application and optional flag.

Literal optional absence keeps its existing non-failure behavior. Mandatory literal errors remain incomplete. Unmatched brackets and empty/negation-only bracket sequences remain literal and retain inspection/application attribution. Nonempty bracket classes, including leading-`]` classes, are unevaluated; a bracket class cannot span path components. Glob-escaped references are likewise explicitly unknown, with an escape-specific detail, rather than interpreted as literal absence. Independently discovered metadata stays in `files`, without claiming the expression was evaluated or assigning its application by guessed matching. Docker bind paths remain literal, including filenames containing glob characters. No contents are read and no scope, link policy or traversal budgets are expanded. Fields are additive within schema version 1; existing JSON/HTML evidence and text skipped-path output retain the explanation. Older reports are not reinterpreted.

## Environment-file permission advice

File modes, ownership, application references, ACL and parent metadata remain unchanged. Read-bit findings describe observed group/other bits and make confidentiality advice conditional; they do not establish file contents or effective access. Mixed read/write modes retain independent integrity advice, and executable/special bits, ACL concerns and incomplete inspection remain visible. Finding wording intentionally changes, while levels and the one mode-review finding per file remain unchanged. Schema version stays 1; JSON, HTML and text preserve the same evidence. Older reports retain their original findings and counts rather than being reinterpreted.

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

A malformed Docker listing retains the existing top-level `error` and `detail`, plus `containers`, `endpoint` and `limitations`. Collection stops at the first invalid ID; prior allowlisted container evidence and findings remain in their original order, including earlier inspection failures. The runner adds one Unknown for the listing error. JSON, HTML and text retain the available inventory alongside the failure; zero retained containers with `error` is not a successful empty inventory. These error-result fields are additive within schema version 1; normal successful, empty, missing-CLI and daemon-failure behavior is unchanged. Older reports retain their original evidence rather than reconstructing missing containers.

`REVIEW` means observed evidence merits a local decision. `UNKNOWN` means a relevant conclusion cannot be reached from available evidence. There is no severity ranking, compliance certification or malware verdict. Missing optional firewall tools do not create individual findings, but lack of any readable kernel backend creates a consolidated Unknown finding.

OS metadata read/decode errors return an `error` check and the runner adds an Unknown finding. Expected Git access, format, workspace and budget failures preserve earlier detections and other repositories: the affected repository is `error` without scan records or `partial` with records, and the overall Git check is `partial` with an Unknown finding. Safe issue messages identify the reason; raw Git stderr and OS error text are withheld. Workspace cleanup failure is recorded as a repository issue. Unconfirmed reader shutdown is fatal and prevents final report export; see [reader handling](operations.md#scanner-failures-and-interruption). Docker/account status semantics are unchanged.

`checks.reboot_required` inspects metadata for `/var/run/reboot-required`, without reading its contents. A successful lookup retains `status: "ok"`, `output: "True"` and the existing reboot Review finding. A missing path retains `status: "ok"`, `output: "False"`; this means no marker was found, not proof that a reboot is unnecessary. Other metadata-inspection failures return `status: "error"` with `detail` and no Boolean-looking `output`. The existing summary adds one Unknown finding for that check, and unrelated collection continues. Direct `stat()` avoids Python-version-dependent error suppression by `exists()`; the existing symlink-following lookup behavior is unchanged. These use the existing error contract and do not change schema version 1.

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
