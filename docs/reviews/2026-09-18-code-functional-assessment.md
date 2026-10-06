# Server-Audit — updated code and functional assessment

[Historical review index](README.md) · Author/assistant assessment

Archive and reconciliation date: **2026-09-18 (Europe/Berlin)**.

> **Historical record, not the current backlog or an independent approval.** The original assessment below describes `main` at `3d0c635`; its “current”, “next” and rating statements belong to that scope. Later changes are identified separately in the reconciliation. Current work and approval decisions belong in the linked GitHub Issues.

## Record scope

This is the owner-supplied assessment and its substantive proportionality clarification, retained at the original level of detail. Editorial changes repair table headers and heading nesting, normalize whitespace, replace pasted attachment labels with evidence references, and remove interface/conversation chrome. The original findings, ratings, recommendations and qualifications have not been silently updated.

The original assessment names `3d0c635` and the unchanged runtime baseline `a6599fe930bc565b3d13e39eb87faeb964f4b068`. The diagnostic result records execution at **2026-09-18T07:07:01.002320+00:00**, on Linux with Python 3.13.5. The exact writing time of the original prose is not recorded. The later reconciliation is a source/evidence comparison at `7353f2e5f0b9e502ff9b22d76891bb4709a08c5c`, not a fresh diagnostic or native-lab run.

Statements below that no repository changes were made refer to the original assessment response, not this archival publication. Supporting attachment names are historical references, not promises that those files are installed in this repository. The [recorded evidence section](#recorded-diagnostic-evidence) preserves their scope and points to self-contained follow-ups.

## Original assessment

**My overall assessment remains: 7.5/10 for code and design, and 8.5/10 for operational usefulness in guided server reviews and handovers.**

The project has a useful scope and a sensible architecture. Its main weakness is **uneven handling of interpretation, incomplete coverage and failures**, not a lack of features. I would keep the existing check categories and correct the specific issues below rather than redesign the application.

### 1. Review scope and latest repository changes

I checked the latest `main`, **`3d0c635`**. The runtime and test Git trees are unchanged from the reviewed baseline, **`a6599fe`**, so the earlier code findings still apply. The intervening change updated documentation and project instructions.

**One previous finding is now resolved:** the roadmap correctly records delivered CI, `CHANGELOG.md` exists, and `AGENTS.md` contains more explicit documentation-consistency and completion requirements. These should no longer be presented as missing improvements.

The technical assessment rests on source inspection, relevant tests and **14 recorded isolated diagnostic cases against seven hash-verified modules**. Those cases include positive controls and hardening observations—not 14 separate defects. They are not a full-suite rerun, a production-host audit or a measured detection-accuracy benchmark. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

### 2. Ratings by check

**Code** considers correctness within the stated scope, error handling, maintainability and supporting verification. **Usefulness** considers how effectively the evidence supports an operational decision.

These are provisional engineering judgments, not mathematical measurements. Deliberately unsupported capabilities are not automatically defects.

| Check | Code /10 | Usefulness /10 | Main conclusion |
| --- | --- | --- | --- |
| SSH configuration | 7 | 9 | Valuable evidence; interpretation needs better handling of interacting settings. |
| Accounts, sudo and SSH keys | 6.5 | 9 | High-value inventory; account attribution needs correction. |
| Listening sockets | 7 | 9 | Useful inventory; parsing losses should be explicit. |
| UFW / nftables / IPv4 and IPv6 iptables | 7.5 | 8 | Good evidence collection, deliberately limited policy interpretation. |
| Docker | 8 | 9 | Strong collection design; improve preservation of partial evidence. |
| Environment files | 6.5 | 8 | Useful privacy-preserving check; reference and coverage handling need correction. |
| Git secret inspection | 8 | 8 | Carefully bounded reader; deliberately limited detection scope. |
| Cron and systemd timers | 7 | 8 | Useful review signals; needs more representative native validation. |
| OS identity | 8 | 7 | Simple and appropriately scoped. |
| Running services | 7.5 | 7 | Useful inventory, not application-health monitoring. |
| Failed services | 7.5 | 8 | Actionable evidence, without root-cause analysis. |
| Available updates | 6.5 | 8 | Useful when cache and parsing limitations are understood. |
| APT metadata | 6.5 | 7 | Helpful timestamps, but limited interpretation. |
| Reboot-required marker | 5.5 | 7 | Useful signal with a specific error-handling weakness. |
| External verification companion | 8 | 8 | Sensible separation and conservative reachability conclusions. |

### 3. What each check does, excludes and should improve

#### SSH configuration

**What it does.** Runs `sshd -T`, optionally against a custom configuration and connection context. It records the attempted scope, raw output, selected settings and repeated values. Findings cover root login, password and empty-password authentication, forwarding and keyboard-interactive authentication.

**What it does not establish.** It does not prove which configuration the running daemon loaded, evaluate every possible `Match` combination, perform an authentication attempt or provide a comprehensive cryptographic or vulnerability assessment. Those boundaries are documented.

**Identified issue: interacting settings are not always interpreted together.** Diagnostic C04 supplied:

```
disableforwarding yes
allowtcpforwarding yes
x11forwarding yes
```

The collector still recommended restricting TCP and X11 forwarding. The individual values were retained, but the overriding setting was absent from the selected summary. This produces context-insensitive advice: OpenSSH specifies that `DisableForwarding` overrides the other forwarding-related options. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence) [OpenBSD Manual Pages](https://man.openbsd.org/sshd_config)

**What it should do.** Respect explicit overrides before generating recommendations. Similarly, present password authentication alongside `AuthenticationMethods`; an enabled password method does not necessarily permit password-only authentication. [OpenBSD Manual Pages](https://man.openbsd.org/sshd_config)

**Recommended scope:** add focused interpretation rules and representative native regressions. Do not build a complete SSH-policy engine.

#### Accounts, sudo and SSH keys

**What it does.** Enumerates accounts and groups; collects password, expiry and sudo-policy evidence; inspects candidate authorised-key files; validates public-key fingerprints; identifies weak/shared keys; and correlates retained successful key-authentication events with usernames and fingerprints. It appropriately distinguishes password locking from account disablement and missing usage evidence from an unused key.

**What it does not establish.** It does not resolve all directory-service identities, effective privileges, PAM restrictions, certificates, revocation conditions or `AuthorizedKeysCommand` results. Permission checks exclude effective ACL rights and some ancestors. It is an access-evidence inventory, not proof that every listed account can authenticate.

**Identified issue: selected SSH scope can be over-applied.** The runner supplies one selected SSH result to the account collector. That collector extracts one `AuthorizedKeysFile` setting and applies it across all enumerated accounts without receiving the connection context.

In C05, settings representing an Alice-specific evaluation were supplied alongside Alice and Bob. The collector associated the same file with both and produced a shared-key finding. This establishes the attribution behaviour under the supplied scenario—not that those keys actually authenticate Bob. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**What it should do.** Carry the SSH evaluation scope into account evidence. Where applicability to another account is unknown, avoid definite associations or shared-key conclusions based on that unverified association.

**Recommended scope:** correct attribution while preserving the general account inventory. Validate with a native configuration containing different per-user key paths. Exhaustively testing every user/address combination is unnecessary.

#### Listening sockets

**What it does.** Collects TCP/UDP listeners, addresses and available process ownership using `ss`. It distinguishes loopback from non-loopback bindings, including IPv4-mapped loopback addresses.

**What it does not establish.** A listener does not prove internet reachability or application health. The inventory is limited to the current network namespace; other container/network namespaces require separate consideration.

**Identified issue: unparsed records are not reflected in coverage.** C06 supplied one valid listener and one malformed non-empty record. The result retained one listener and returned `ok` without a parsing warning. Raw output remained available. This was injected malformed output, not evidence of an ordinary `ss` compatibility failure. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**What it should do.** Preserve successfully parsed listeners and record interpretation losses. An empty successful inventory should remain distinct from output that could not be parsed.

**Recommended scope:** a small parser-coverage improvement. Do not replace the collector with a broader network scanner.

#### Firewalls: UFW, nftables, IPv4 iptables and IPv6 iptables

**What they do.** Collect four separate evidence sources: UFW status, the nftables ruleset and IPv4/IPv6 iptables exports. Missing optional commands are skipped; lack of any readable kernel backend produces a consolidated `UNKNOWN`. UFW status alone does not establish filtering coverage.

**What they do not establish.** They do not calculate effective packet paths, verify provider firewalls, reconcile every overlapping backend or prove that a particular service is protected. The presence of rules is deliberately not treated as a security pass.

**Usefulness limitation.** The evidence remains heavily dependent on an experienced reviewer. That is not inherently wrong, but the generic review finding gives limited help in identifying coverage gaps.

**What they should do.** Make readable backends, failed collections and missing address-family evidence easy to distinguish. Keep the native rules available.

**Recommended scope:** improve the coverage summary. A general firewall-policy simulator or automatic remediation would be disproportionate.

#### Docker

**What it does.** Inspects running and stopped containers on the default local Docker socket. It records selected state, health, ports, mounts, configured privileges and resource limits. Findings cover privileged operation, host namespaces, Docker-socket mounts, sensitive writable mounts, published ports and problematic container states.

**What it does not establish.** It is not image-vulnerability scanning, live resource monitoring or complete daemon-hardening assessment. Rootless/remote daemons and other runtimes are excluded. Configured identities and limits are not measurements of every process’s effective privileges.

**Strong point.** Its explicit metadata projection avoids capturing environment values, labels, command arguments and health-check logs. This is one of the better collection boundaries in the project.

**Identified issue: malformed listing data can discard earlier evidence.** In C12, one container was successfully inspected before an invalid ID appeared. The result retained an earlier finding but dropped the accumulated container inventory. This is a resilience defect demonstrated with malformed synthetic output, not a demonstrated ordinary Docker failure. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**What it should do.** Return the collected container evidence alongside the failure, and visibly distinguish successful from failed inspections.

**Recommended scope:** preserve evidence and improve coverage counts. No rewrite of the Docker integration is required.

#### Environment files

**What it does.** Discovers `.env`-like filenames and supported application references, then checks ownership, permission bits, ACL presence and parent directories. Systemd references and Docker bind-mount candidates supplement directory traversal. Candidate contents are not opened.

**What it does not establish.** It does not inspect credential values, calculate complete effective access, recover original Docker `--env-file` paths or prove that an application loaded a particular file. Ownership is recorded without assuming the correct service identity.

##### Issue A: application coverage is aggregated inconsistently

Systemd failures affect the application aggregate status; Docker failures do not. C07/C08 demonstrated `ok` environment/application aggregates despite Docker-related collection errors. Those errors can still produce `UNKNOWN` elsewhere in the complete host report. **This is an asymmetric summary, not evidence that every failure is hidden.** [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**Improvement:** expose incomplete Docker application references while keeping independently successful directory discovery visible. Do not automatically treat an absent optional Docker installation as a failed inspection.

##### Issue B: optional wildcard references can become false absence

Systemd accepts wildcard `EnvironmentFile` references. The collector currently treats the supplied path as a literal filename. [Debian Manpages](https://manpages.debian.org/trixie/systemd/systemd.exec.5.en.html)

C09 created a matching temporary file and supplied an optional wildcard reference. With independent directory discovery excluded, the collector inspected no files and recorded “Optional application file absent.” Directory traversal might discover the file separately in another run, but that does not correct the reference interpretation. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**Improvement:** at minimum, recognise an unsupported wildcard reference and report incomplete coverage. Bounded expansion is an alternative, but must preserve scope, symlink and resource limits.

##### Presentation improvement

Show the discovery source and associated application beside the file. Much of that evidence already exists but is spread between separate HTML tables.

Keep the conclusions proportionate: `0640` means “confirm the intended group,” not automatically “insecure”; a template-looking name is not proof of harmless contents; no discovered application reference does not mean “unused.”

**Recommended scope:** correct reference handling and coverage first, then improve context. Retain metadata-only collection.

#### Git secret inspection

**What it does.** Performs opt-in inspection of selected Git configuration and stored objects using eight candidate-rule families: private-key headers, GitHub/GitLab token shapes, AWS access-key identifiers, Slack token shapes, credential-bearing URLs, authorisation headers and credential assignments. It includes retained unreachable and packed content, while exporting rule/location metadata rather than matching secrets.

**What it does not establish.** It does not scan current working files, recover pruned objects or external LFS payloads, validate credentials remotely, decode arbitrary embedded content or reconstruct original filenames and every containing commit. An AWS identifier alone is not proof of usable credentials.

**Strong points.** The reader uses isolated metadata, constrained Git configuration, bounded content and explicit subprocess ownership. Partial results preserve earlier detections; unconfirmed shutdown remains fatal instead of being converted into a successful scan.

**Main improvement:** make the supported detection cases representative of your actual repositories, and make object-location findings easier to investigate locally. Existing tests already cover substantial history, reference and storage scenarios; another parallel dataset framework would add little by itself.

**Important combined scope limitation:** the environment-file check does not read contents, and the Git check excludes current working files. Therefore, these two checks together must not be presented as comprehensive scanning of credentials currently deployed in application files.

**Recommendation:** retain the current design. Expand scope only for an explicitly agreed detection requirement.

#### Cron and systemd timers

**What it does.** Reads scoped cron definitions, periodic scripts and loaded system-manager timers. It records schedules, users, file metadata and selected script references, and identifies patterns involving downloads, decoding, dynamic evaluation, inline code and temporary paths. It reads text locally but does not execute or export command bodies.

**What it does not establish.** Discovery does not prove execution or enablement. It does not fully cover user-manager/unloaded timers, arbitrary shell syntax, recursive script chains or effective ACL rights. Pattern matches are review signals, not malware verdicts.

**Code-review observations.** Cron parsing checks supported syntax rather than fully validating numeric schedule semantics. Script references cover a deliberately narrow set of literal forms. Timer parsing depends on supported `systemctl` serialisation. These should not be described as complete execution validation.

**What it should do.** Keep definition discovery, target inspection and execution evidence distinct. Add representative native timer/service cases and clearly label unsupported forms.

**Recommendation:** strengthen native validation and interpretation before adding more suspicious-pattern rules.

#### OS, services and maintenance

These checks share `system_audit.py`; their collection and interpretation are compact and explicit.

| Check | What it does | What it does not establish | Proportionate improvement |
| --- | --- | --- | --- |
| **OS identity** | Reads `/etc/os-release`, with a fallback when absent and error reporting for failed reads. | Supported lifecycle, vulnerabilities or patch compliance. | Keep it simple; add structured fields only for a real consumer. |
| **Running services** | Lists systemd services in the running state. | Application health or completeness against an expected service inventory. | Make the inventory scope explicit. |
| **Failed services** | Lists failed units and produces findings. | Root cause, failure duration or business impact. | Preserve unit evidence and concise investigation guidance. |
| **Available updates** | Parses upgradable packages from cached APT information. | Complete security-update coverage or that “none listed” means fully patched. | Present cache limitations alongside results and improve parser compatibility. |
| **APT metadata** | Records the oldest matching package-index timestamp. | Successful recent refresh of every configured source. | Surface metadata age/missing evidence without inventing a universal freshness policy. |
| **Reboot marker** | Checks `/var/run/reboot-required` and flags its presence. | That absence proves no reboot or service restart is needed. | Distinguish present, absent and inspection failure. |

##### Reboot-marker correction

C02/C03 injected permission and I/O errors into the filesystem check. Both escaped the collector rather than returning evidence. The runner invokes that collector directly, so an unhandled exception can prevent report completion; that pipeline consequence follows from the code rather than a production-host reproduction. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

The correction should use an explicit filesystem-status operation with separate absence and error handling. This also avoids relying on version-sensitive `Path.exists()` behaviour: Python 3.14 suppresses operating-system errors into `False`, potentially conflating inaccessible and missing paths. That version-specific behaviour was checked in documentation, not executed in the recorded diagnostics. [Python documentation](https://docs.python.org/3.14/library/pathlib.html)

##### APT improvement

The collector parses `apt list`, whose interface is designed for interactive use and is not guaranteed stable for scripts. Evaluate a suitable scripting interface when improving the check, with representative fixtures—not an untested command substitution.  [Debian Manpages](https://manpages.debian.org/trixie/apt/apt.8.en.html)

**Do not refresh package indexes or install updates automatically.** That would change the read-only operating boundary rather than merely improve reporting.

#### External verification companion

**What it does.** Performs explicitly selected TCP connection attempts, records observations and timestamps, and imports validated results into a new report. It bounds inputs, targets, ports and concurrency. Public-reachability labels require an operator-declared independent source; matching local services remain unverified same-port candidates.

**What it does not establish.** It does not probe UDP, identify applications through HTTP/TLS, discover every public address, prove NAT mappings or authenticate imported evidence cryptographically. A refusal or timeout does not establish universal protection.

**What it should do.** Preserve the separation between observed connectivity and assumed host/service attribution. Keep stale correlation and untested scope visible.

**Recommendation:** no major expansion is justified by this review. This is a proportionate companion rather than an unnecessary platform.

### 4. Cross-cutting code and consistency findings

#### Collection success is not complete coverage

The report contract deliberately allows `ok` with nested failures. Therefore, changing every such result to `partial` is not automatically a correction; it can affect compatibility and report consumers.

The practical improvement is clearer summaries:

> Nine containers inspected; one inspection failed.

> Directory discovery completed; application references remain incomplete.

These are proposed presentations. They distinguish successful work from missing evidence without redefining every status.

#### Shared command execution needs proportionate hardening — 6.5/10

The ordinary runner is shell-free and time-limited, but captures complete outputs without a byte ceiling and discards partial output supplied in timeout exceptions.

C14 confirmed full capture of a synthetic 4 MiB output. **It did not demonstrate memory exhaustion or unacceptable production runtime.** C13 confirmed discarded partial timeout output, while the result still correctly reported failure. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

Python documents that captured pipe data is buffered in memory. A capture limit can therefore be useful, but the implementation must mark incomplete output and avoid passing truncation into normal parsers as successful evidence. [Python documentation](https://docs.python.org/3.13/library/subprocess.html)

I would not introduce a general subprocess framework, blanket exception handling or concurrency rewrite. Preserve cancellation and explicit fatal-shutdown behaviour.

#### Reporting and export are comparatively strong — 8.5/10

Private permissions, unique export directories, HTML escaping and manifest-last completion are supported by focused tests. These controls deserve to remain intact.

The useful improvements are clearer coverage summaries, file/application context and identification of the tool revision in retained reports. A complete manifest already means export completion—not complete audit coverage, durability after a crash or cryptographic authenticity. Those documented limitations are not newly discovered defects.

#### Finding prioritisation should improve without a policy framework

The current `REVIEW` category covers materially different situations: expected administrator access, group-readable configuration files and privileged container operation. The evidence can be valid while still requiring substantial operator triage.

I would first improve **affected resource, observed condition, qualification and next investigation step**. A configurable severity model or exception engine is not necessary now. Stable finding IDs become more useful when automated comparison is an actual requirement.

#### Documentation governance has improved

The current roadmap now distinguishes delivered CI from broader validation work. The changelog records selected notable changes, and the updated instructions require affected cross-document statements to be checked against the final change.

**The next task is applying that process to the runtime fixes—not adding more instructions.** The new completion requirements already distinguish author self-review, actual CI evidence, unresolved issues and permission to merge.

### 5. Validation and acceptance criteria

The runtime baseline has a successful GitHub CI run. The live suite covers four specific areas: native SSH configuration/login, Docker projection, firewall-rule collection and socket ownership. It does not provide complete environment-file, timer or journal-correlation validation.

For each correction, I would require a small set of evidence:

| Validation | Purpose |
| --- | --- |
| **Focused regression** | Demonstrates the incorrect behaviour and the independently defined intended result. |
| **Positive control** | Confirms that already-correct neighbouring cases still work. |
| **Native case where applicable** | Confirms that supplied SSH/systemd examples represent real tool output and configuration semantics. |
| **Report-level assertion** | Confirms evidence, coverage and redaction survive JSON/HTML/text presentation where affected. |

Do not merely convert the diagnostic script into a passing regression suite: it currently asserts **the old behaviour**, including defects. Its value is documenting the observations. [`review_reproductions.py` (historical)](#recorded-diagnostic-evidence)

A fixture-based detection corpus should extend the existing tests, not duplicate them. Likewise, a new native systemd case belongs in the existing lab, with its acceptance expectations updated—not in another testing platform.

### 6. Recommended implementation sequence

This is a technical sequence, not an instruction to implement everything or create a competing backlog.

| Order | Change | Observable completion criterion |
| --- | --- | --- |
| **1** | Correct SSH account/key attribution. | User-specific evaluation does not create definite associations for unrelated accounts; native configuration behaviour is verified. |
| **2** | Correct environment wildcard-reference interpretation. | An unevaluated wildcard cannot be labelled simply absent; discovered evidence and scope limits remain explicit. |
| **3** | Correct reboot-marker error isolation. | Present, absent and inaccessible cases are distinguished; expected errors do not escape the collector. |
| **4** | Respect explicit SSH forwarding overrides. | Advice matches the combined settings, verified against representative native output. |
| **5** | Improve parsing and application-coverage reporting. | Malformed records and incomplete sources remain visible without discarding successful work. |
| **6** | Preserve Docker inventory after malformed listing entries. | Earlier container evidence survives alongside the error. |
| **7** | Improve report context and targeted native coverage. | Operators can identify the resource, source, concern and missing evidence without reconstructing it from separate sections. |

The first three affect correctness or report availability directly. Malformed-output resilience is worthwhile but should not be presented as an emergency production incident. Output bounding, additional provenance and richer presentation remain proportionate hardening or usability improvements.

For every accepted change, update the relevant tests, owning documentation and changelog where the change is notable. Use existing issue records for implementation status and dependencies.

#### What I would not add now

I would defer automatic remediation, comprehensive ACL evaluation, a firewall-policy engine, expanded working-file secret scanning, a database, plugin architecture, generic collector framework and a new severity system.

Those may answer future requirements, but **none is necessary to correct the issues established by this review**.

### Final conclusion

**Keep the architecture and check categories. Improve the reliability of the conclusions they already produce.**

The most valuable next milestone is:

> **Within the declared scope, evidence is attributed to the correct resource; unsupported inputs do not become empty successes; recoverable failures preserve useful results; and missing coverage is obvious to the reviewer.**

That is the basis for the current **7.5/10 code/design and 8.5/10 usefulness** ratings. The documentation update is a genuine improvement, but unchanged runtime code should not receive a higher correctness rating merely because its process documentation improved.

The supporting [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence) and [`review_reproductions.py` (historical)](#recorded-diagnostic-evidence) remain available. **No repository changes were made as part of this response.**

## Original proportionality clarification

**Yes—as a prioritised assessment, not as a mandatory list of everything to implement.** The core recommendation fits your requirement: **correct existing behaviour with focused changes, preserve the architecture, and add capabilities only when there is a demonstrated need.**

The part I would make more explicit is that **the seven-item implementation sequence is not one large change request**. It separates immediate corrections from subsequent resilience and usability improvements.

### What I would actually do first

| Correction | Smallest useful solution | What would be excessive |
| --- | --- | --- |
| **SSH account attribution** | Preserve the selected SSH context and avoid definite key associations for accounts to which it may not apply. | Building a comprehensive engine that evaluates every user, address and authentication combination. |
| **Environment-file wildcard handling** | Report an unevaluated wildcard as incomplete coverage rather than claiming the file is absent. | Automatically adding a general configuration parser or unrestricted file discovery. |
| **Reboot-marker errors** | Distinguish present, absent and inaccessible states through targeted filesystem-error handling. | Introducing a generic collector lifecycle or exception-handling framework. |

The recorded diagnostic cases support these three corrections. **They address incorrect attribution, misleading absence and error propagation—not missing product features.** [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

### What should remain separately prioritised

**Malformed-output handling is secondary resilience work.** The socket and Docker cases demonstrate responses to deliberately malformed inputs; they do not establish that normal production output is failing. Small evidence-preservation corrections are reasonable, but those cases do not justify redesigning either integration. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**Output bounding and report enhancements are not prerequisites for those three fixes.** The capture test demonstrated an absent output limit—not memory exhaustion. Improvements to capture limits, provenance and presentation should have their own practical justification and bounded scope, rather than being bundled into a “make everything robust” project. [`reproduction_results.json` (historical)](#recorded-diagnostic-evidence)

**Documented exclusions should remain exclusions unless your requirements change.** I would not add working-file secret scanning, automatic permission changes, comprehensive ACL evaluation or a firewall-policy engine merely because the review identifies that they are not covered.

### Testing must also stay proportionate

For a correction, use the existing suite to demonstrate the changed behaviour and preserve relevant valid cases. Add native integration coverage where the fix depends on actual SSH or systemd semantics; add report assertions where the report changes.

**Do not interpret the validation table as requiring four separate testing layers for every small patch.** Reuse existing cases and setup wherever they already provide the necessary evidence. Tests have maintenance costs too; Google’s review guidance explicitly recommends tests appropriate to the change and warns against unnecessary complexity in test code. [Google GitHub](https://google.github.io/eng-practices/review/reviewer/looking-for.html)

The same applies to documentation: update the owning explanation and affected summaries, not every guide. **No further expansion of** **`AGENTS.md`** **is needed to implement these corrections.**

### The stopping point

I would consider the initial corrective work complete when:

> **The three identified behaviours are corrected, relevant regressions pass, affected documentation is accurate, and no unrelated functionality or infrastructure has been introduced.**

Then reassess the remaining recommendations individually—not automatically start the next seven improvements.

**So yes, the assessment respects the commitment to avoid overengineering. The boundary is that we fix evidenced problems, keep optional improvements optional, and do not turn the rating into an endless attempt to reach 10/10.**

## Reconciliation — 2026-09-18 (Europe/Berlin)

This addendum is separate from the original assessment. The source comparison and repository-state verification used `main` at [`7353f2e5f0b9e502ff9b22d76891bb4709a08c5c`](https://github.com/novakin/Server-Audit/commit/7353f2e5f0b9e502ff9b22d76891bb4709a08c5c). It does not re-rate the project, claim a production incident, re-execute the diagnostic script, or turn every optional recommendation into approved work.

### Subsequent corrections

The reboot-marker error handling discussed in the original implementation sequence was subsequently delivered by [PR #20](https://github.com/novakin/Server-Audit/pull/20), merge `1b068101381b58a8cd2241cddffa6c5c95490833`, for [issue #11](https://github.com/novakin/Server-Audit/issues/11). Its revision-specific tests and limits belong to that PR. It should not be treated as unfinished merely because the historical sequence above still includes it.

The separate symbolic-link mode false positive was subsequently corrected by [PR #22](https://github.com/novakin/Server-Audit/pull/22), merged as the reconciliation revision, for [issue #18](https://github.com/novakin/Server-Audit/issues/18). That permission correction did not change the SSH account/context attribution path described in C05. No historical host report was rewritten and no deployment is established by either merge.

### Canonical follow-up records

These links map the historical findings to their action records; the table is not a live status checklist. Read each Issue for current decisions, evidence, approval and implementation. The owner's approval to log/archive this material does not approve the runtime changes or further design investigations.

| Historical finding | Action record | Bounded direction |
| --- | --- | --- |
| C05 — SSH account/key attribution | [#23](https://github.com/novakin/Server-Audit/issues/23) | Preserve evaluation scope and uncertain applicability; retain legitimate shared observations. First recommended correctness task. |
| C09 — EnvironmentFile wildcard interpretation | [#24](https://github.com/novakin/Server-Audit/issues/24) | Unsupported interpretation must not become absence; full wildcard expansion is not a prerequisite. Second recommended correctness task, not a dependency. |
| C04 — SSH forwarding override | [#25](https://github.com/novakin/Server-Audit/issues/25) | Respect DisableForwarding in the existing advice and evidence. |
| C12 — Docker inventory loss | [#26](https://github.com/novakin/Server-Audit/issues/26) | Preserve earlier evidence alongside malformed-listing failure; secondary resilience work. |
| C06 — Socket parsing losses | [#27](https://github.com/novakin/Server-Audit/issues/27) | Retain valid listeners and expose unparsed non-empty records; secondary resilience work. |
| C07/C08 — Application-reference aggregation | [#28](https://github.com/novakin/Server-Audit/issues/28) | Establish the coverage contract before deciding on a minimal summary/status change; a separate design investigation. |

The SSH context diagnostic supplied an Alice-specific interpretation; it did not establish that native sshd had produced it or that a login succeeded. Native per-user configuration evidence is therefore part of the proposed acceptance, not an already performed test. The environment wildcard case likewise used an injected property response. The malformed Docker/socket cases do not establish ordinary native-output failures.

The report contract permits `ok` alongside nested uncertainty. In particular, the application-reference observation does not justify mechanically changing all nested failures into a top-level `partial`, or claiming that Docker errors were entirely hidden. Existing successful discovery must remain visible.

### Output-bounding tracking correction

Ordinary command capture at this reconciliation revision still has no output-byte ceiling; see [command_runner.py](https://github.com/novakin/Server-Audit/blob/7353f2e5f0b9e502ff9b22d76891bb4709a08c5c/server_audit/command_runner.py). [Issue #12](https://github.com/novakin/Server-Audit/issues/12) remains the canonical proposal. Its earlier completed state did not establish implementation.

During archival preparation, issue #12 was reopened and one out-of-scope sentence in PR #22 was corrected because it accidentally contained a closing-keyword pattern. The timing and wording support that as the likely closure cause, but the REST closure event did not name the triggering PR. The [issue correction](https://github.com/novakin/Server-Audit/issues/12#issuecomment-5730379579) records the actual metadata changes and relationship-verification limit; the [PR clarification](https://github.com/novakin/Server-Audit/pull/22#issuecomment-5730381148) preserves the correction without replacing its original code/CI evidence. Scope and limit selection still need separate approval. This was not a runtime fix or a new diagnostic run.

[Issue #13](https://github.com/novakin/Server-Audit/issues/13) owns required merge-check administration, independently of this assessment. This archive changes no repository settings, plan, visibility or CI enforcement.

### Approval and stopping point

On 2026-09-18 (Europe/Berlin), the owner approved the logging proposal with “ok do”: correct the existing tracking records, archive this assessment and create the bounded follow-ups after duplicate checks. The assistant records that approval; no public conversation URL is available. It does not authorise runtime implementation, a new dependency, merge, deployment or production collection.

Optional provenance, richer presentation, additional detection patterns and broader native coverage remain recommendations until a concrete requirement and scope are accepted. The original ratings remain historical judgments. A satisfactory scoped correction does not establish that the entire application is defect-free.

## Recorded diagnostic evidence

The original `review_reproductions.py` and `reproduction_results.json` were supplied as supporting artifacts and retrieved for the source/evidence comparison. They are not committed as a second test suite. The script checks seven pinned module hashes and asserts the **observed old behavior**, including defects; it must not be copied into CI as desired-behavior acceptance tests. Focused follow-up Issues retain equivalent synthetic reproduction snippets and their recorded results so the actionable findings do not depend only on temporary-chat attachments.

Original runtime: [`a6599fe930bc565b3d13e39eb87faeb964f4b068`](https://github.com/novakin/Server-Audit/tree/a6599fe930bc565b3d13e39eb87faeb964f4b068). Recorded execution: **2026-09-18T07:07:01.002320+00:00**, Linux, Python 3.13.5. The seven modules were `command_runner`, `accounts`, `docker_audit`, `env_files`, `network_audit`, `ssh_audit` and `system_audit` in their existing package locations. This is historical evidence, not a fresh execution by the archive task.

| Cases | Recorded observation | Interpretation boundary |
| --- | --- | --- |
| C01 | OS read failure returned an error check. | Positive control, injected read failure. |
| C02/C03 | Reboot permission/I/O errors escaped collection. | Injected errors; later correction is linked above. |
| C04 | Two forwarding recommendations despite supplied DisableForwarding override; override absent from selected summary. | Synthetic sshd-shaped text, not native evaluation. |
| C05 | Alice-only scenario file associated with Alice and Bob; shared-key finding emitted. | Injected account/key/command responses; no authentication proof. |
| C06 | One listener retained from two non-empty records, with no parsing warning. | Malformed synthetic record; original raw output remained available. |
| C07/C08 | Environment/application aggregates stayed `ok` alongside nested Docker errors. | Isolated collector; other report sections may already expose the failure. |
| C09 | A matching temporary file was not inspected through an optional wildcard reference; false literal-absence reason. | Real temporary file, injected systemd property, independent discovery excluded. |
| C10/C11 | Literal optional absence stayed `ok`; mandatory absence produced `partial` and Unknown. | Positive controls, temporary missing paths. |
| C12 | Earlier Docker finding survived but its accumulated container evidence did not. | Injected malformed listing after a valid record. |
| C13 | Partial timeout output was discarded while status remained error. | Injected timeout; a diagnostic trade-off, not a silent success. |
| C14 | One harmless subprocess returned 4 MiB of stdout without a capture ceiling. | No memory-exhaustion, production-load or whole-audit runtime test. |

This record preserves fourteen cases, not fourteen defect tickets. The source-comparison conclusions, future implementation tests and archival PR's routine CI each have different scopes. Routine CI results for publishing this file belong in that PR description, not as a new execution date on these historical diagnostics.
