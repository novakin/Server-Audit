# Audit coverage and limits

[Documentation index](../README.md) · Internal engineering documentation · Reviewed 2026-09-17

Reference for what each audit observes, what it exports and what remains unverified. Configuration evidence and review signals are not a security certification.

Runtime collectors and their domain helpers are under `server_audit/collectors/`; the two public launchers remain at the repository root. The layout change does not extend the scopes or detection rules described here.

## Checks

- Effective default SSH settings using `sshd -T`, with recommendations for root login, password authentication, empty passwords and forwarding.
- Listening TCP/UDP sockets, addresses and owning process names/PIDs using `ss`. Loopback bindings are distinguished from other bindings; non-loopback includes private addresses and does not mean publicly reachable.
- UFW, nftables and IPv4/IPv6 iptables rules. These are evidence for review, not an automated firewall verdict. Inactive UFW alone does not mean no firewall exists.
- Docker inventory, published ports, health, resource limits and security findings. The script explicitly targets the local `/var/run/docker.sock`; remote contexts and rootless Docker sockets are not audited. See Docker scope below.
- Running/failed systemd services, available package updates from cached APT metadata, metadata timestamps and reboot-required state.
- User accounts, groups, password/expiry state, sudo policy, authorized public keys and retained login evidence. See account scope below.
- Environment-file ownership/modes, ACL presence and ancestor permissions; systemd file references and Docker environment counts/mount candidates.
- Optional built-in secret detection in explicitly selected local Git configuration and stored objects.
- Cron definitions, systemd timers, scheduled-file ownership/modes and suspicious-pattern findings, without executing or exporting command bodies.

Missing commands, denied access and timeouts are reported explicitly. Missing optional firewall tools and Docker remain visible in evidence without creating individual findings. If no kernel firewall backend can be inspected, a consolidated unknown finding is emitted. Permission failures remain findings. Available updates and failed services produce review findings. Summary counts are not a security score.

Text output limits command evidence sections to 80 lines; structured inventories are shown in full. JSON preserves collected evidence. Host inspection commands have a 30-second timeout each and resolve through standard system directories, including `/usr/local/bin`. Optional local Git inspection has a shared per-repository budget described below.

## Environment files and application sources

The default metadata scan searches `/etc`, `/opt`, `/srv`, `/var/www`, `/home` and `/root` for `.env`, `.env.*` and `*.env`. Templates and backups match too; names alone do not establish that secrets are present. Repeat `--env-root` to replace these discovery roots:

```bash
sudo python3 audit.py --env-root /srv/apps --env-root /opt/services --export ./audits
```

Reports record mode (for example `0600`), UID/GID, owner/group names and extended POSIX access-ACL presence. Findings cover group/world read/write access, executable/special bits and non-sticky writable ancestor directories. Extended ACL presence prompts manual review with `getfacl`; the audit does not calculate effective ACL rights. ACL lookup failures remain unknown. `0600` is a common default; `0640` may be appropriate with an explicitly trusted service group. Ownership is recorded rather than judged without a known service identity. No chmod/chown changes occur.

The file scan never opens candidate contents or collects variable names, values, hashes or atime-based usage guesses. It skips symlink paths and non-regular candidates. Traversal stays on each root's filesystem and excludes `.git`, `node_modules`, `.venv`, `venv` and `__pycache__`. Bounds are 50,000 directory entries, 500 candidate files and 12 directory levels, with a 15-second traversal budget checked between filesystem operations. Slow filesystem calls can exceed that budget. Roots, exclusions, skipped paths and incomplete coverage are recorded. Missing default roots are not findings; an explicitly requested missing root produces incomplete coverage.

Application metadata is collected separately from directory discovery:

- Up to 100 running systemd services are queried for `EnvironmentFiles` and `MainPID` only. Referenced files, such as `/etc/default/cron`, receive metadata checks even when their names do not match `.env`. Optional absent files are recorded without a failure. These references are inspected even when `--env-root` narrows directory discovery.
- Docker inspection includes only the **count** of configured environment entries, including image defaults and overrides. Variable names and values are excluded. Env-like bind mount sources/destinations are recorded as file candidates; mounting a file does not prove the app loaded it.

This provides configured-source evidence, not proof of the effective environment of a running process. Files may have changed since startup. Docker does not retain original `--env-file` or Compose `env_file` paths, and Compose's `.env` interpolation file is not necessarily a container environment source. The audit does not read `/proc/*/environ`, inline systemd `Environment` values, Compose YAML, PM2/Supervisor configuration or application-specific loaders. Applications started through those mechanisms require separate investigation.

## Git secrets

Secret detection is built into Python. The approved local `git` executable is used only to read its own storage format; Gitleaks and other scanners are not required or invoked. The check remains opt-in because it inspects stored content. An explicitly requested check without Git is unavailable/Unknown, not clean. Nothing is installed or downloaded automatically.

```bash
sudo python3 audit.py --git-root /srv/app --git-scan-seconds 60 --export ./audits
sudo python3 audit.py --git-root /srv/app/.git --git-root /opt/another-repo --export
```

Select a normal repository root, its actual `.git` directory, or a bare repository. SHA-1 and SHA-256 storage are supported by the reader design and exercised with native Git tests. Git-file indirection, shared-worktree `commondir`, alternate object stores, symlink/special-file storage and cross-filesystem object directories are rejected with incomplete coverage rather than followed outside the selected storage. Select standalone repositories individually. Config includes are not followed; their presence produces an incomplete-scope issue.

The two reported modes are `git_configuration` (config/config.worktree only) and `local_objects` (stored blobs, commits and annotated tags). Objects are inspected once, including unreachable objects still present, loose objects and packed/delta objects. **Current working files are not scanned**, even if untracked or ignored files contain credentials. Deleted historical content is inspected only while its objects remain locally available. Reflogs, index files, hooks and other administrative-file contents are not scanned. Tree objects are counted but not used to reconstruct filenames. Missing/pruned history, LFS payloads and submodule repositories need separate coverage; shallow/partial-clone markers are reported.

### Built-in candidate rules

Ruleset version 1 has eight fixed IDs:

| Rule ID | Candidate pattern, not validation |
| --- | --- |
| `private-key` | PEM/OpenSSH-style private-key headers and PGP private-key block headers. No decryption or key validation. |
| `github-token` | Classic GitHub-style token prefixes and fine-grained token-shaped strings. |
| `gitlab-token` | GitLab-style personal-access-token prefixes. |
| `aws-access-key-id` | AKIA/ASIA-style identifiers. An identifier alone is not the secret key or proof of usable AWS access. |
| `slack-token` | Selected Slack-style token prefixes. |
| `credential-in-url` | Scheme URLs containing a username and password. |
| `authorization-header` | Basic/Bearer credential-shaped header values. No decoding or validation. |
| `credential-assignment` | Bounded literal password, token, API-key or secret-key assignments; selected exact placeholders and environment/template references are excluded. |

Exact regexes and exclusions live in [git_secrets.py](../server_audit/collectors/git_secrets.py), not a downloaded ruleset. Repository allow comments and suppression files do not disable detection. These are intentionally focused heuristics: there can be false positives and missed secrets, including unsupported providers/formats and encoded/encrypted data. No equivalence to Gitleaks or exhaustive credential coverage is claimed. Detection must be reviewed locally before remediation.

### Bounds, isolation and evidence

| Limit | Current value |
| --- | --- |
| Shared scan budget per repository | 60 seconds by default; `--git-scan-seconds` accepts greater than 0 through 3600 seconds |
| Objects enumerated | 10,000, including trees |
| Content per object | 2 MiB; oversized objects are not requested and coverage becomes partial |
| Total object content read per repository | 64 MiB |
| Each config file | 256 KiB |
| Detection records per repository | 500, deduplicated by rule and line within each source |
| Object-store entries checked | 50,000; unexpected nesting or filesystem transitions are rejected |

Limits are enforced before unbounded capture; earlier findings survive budget exhaustion. Time is checked between filesystem operations, bounded inspections and pipe reads. Filesystem stalls, one bounded regex operation and up to a five-second stop/reap grace per reader can extend wall time beyond the scan budget. Git's internal memory use is not capped by the Python object-buffer limits. This is not a filesystem snapshot: use a controlled, preferably quiescent repository; the preflight link/scope checks do not eliminate concurrent path-replacement races.

Git is launched through an isolated bare reader view containing generated metadata only. Its source object directory is explicitly selected, inherited Git/loader settings are not passed through, source-repository execution policy is not active, stderr is discarded, and protocols/lazy fetching are disabled. No hooks, filters, clone, fetch, remote search, credential validation or remediation is performed. Config parsing requests only storage-format fields without includes. Object bytes are analyzed in memory; no secret-bearing scratch report is written. Unconfirmed reader shutdown aborts the audit and retains generated reader metadata for local follow-up; see [operator handling](operations.md#scanner-failures-and-interruption).

Exported detections contain fixed rule IDs, config/object locations, object IDs/types, line numbers and byte offsets. Raw secret values, matching lines, commit/tag text and author/email fields are excluded. A blob ID is not an original filename or a containing commit; those associations are not invented. Input repository paths remain operational metadata and should not contain credentials. See [the evidence contract](report-format.md#built-in-git-secret-evidence).

If a finding is genuine, revoke/rotate the credential and investigate exposure. Removing a file or commit does not revoke it. No detections means only that the selected rules found no candidates within the completed scope.

## Cron and systemd timers

Scheduled-task checks run automatically. Cron scope includes `/etc/crontab`, `/etc/cron.d`, `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly` and Debian/Ubuntu user crontabs in `/var/spool/cron/crontabs`. Definitions record file path, mode, ownership, schedule, run-as user and pattern labels. Environment assignment values, raw commands, script contents, URLs and matched text never enter the report. Candidate file presence does not establish that cron or run-parts will execute it.

The module flags download-to-interpreter pipelines, network download tools, common decoding operations, `eval`, inline interpreter code, references to temporary/shared-memory paths and long encoded-looking tokens. These are **review signals, not malware verdicts**. Legitimate maintenance can trigger them, and malicious code can evade them. No decoding, command execution, shell sourcing or remediation occurs.

Literal absolute executable/script references receive bounded file inspection; binary executables receive metadata only. Dynamic paths, relative paths, shell expansions and arbitrary command arguments are not resolved. Job definitions and referenced scripts are checked for group/world write bits, unexpected owners and immediate parent-directory write permissions. Extended ACLs and all ancestor-directory rights are outside this module's permission checks.

Systemd coverage includes up to 100 loaded system-manager timers (including inactive ones), active state, last/next realtime triggers where available, associated service user and suspicious patterns in effective `ExecStart`. Timer/service fragments, reported drop-ins and supported literal executable/script targets receive file inspection. Unsupported or escaped command serialization leaves explicit unknown target coverage. Shared script ownership is evaluated separately for each run-as UID. User-manager timers, unloaded/disabled units, transient pre/post commands without source fragments and recursive script/include chains need separate review.

Limits are 500 inspected files and 256 KiB per text definition. Symlink paths, special files, oversized definitions, unreadable locations and exceeded limits remain explicit coverage issues. Raw command output is discarded after local analysis; a failed timer lookup does not appear as a clean result. Permission or syntax findings should be reviewed on the host before changing schedules.

## Docker containers

Audits detect command availability before launching a process. If the Docker CLI is absent from the audit PATH, Docker collection is **Skipped**, with the reason shown in HTML, text and JSON; no container inspection is attempted. This does not prove that no daemon exists (for example, a rootless or remote installation). An installed CLI with an inaccessible, stopped or unreachable daemon remains an **Unknown** finding. A reachable daemon with no containers is a successful, empty inventory.

Missing optional firewall tools also show **Skipped**. If no kernel firewall backend can be inspected, overall filtering coverage remains **Unknown**. Required evidence tools still report unavailable coverage, and explicitly requested Git secret scans still report missing Git rather than silently skipping the request.

Docker checks run automatically for all containers, including stopped containers. Reports include:

- Container name/ID, configured image reference and image ID, creation/start/finish times, status, exit code, restart count, OOM state and health status.
- Published and configured TCP/UDP port mappings, attached network names/IP addresses and network mode. Configured bindings on stopped containers are not proof of active listeners.
- Bind mounts/volumes with source, destination and write access.
- Configured user, privileged mode, added/dropped capabilities, security options, device mappings, host namespace settings and read-only root filesystem setting.
- Restart policy, logging driver and configured memory/swap, CPU and PID limits. These are configured limits, not live usage; zero/null values may inherit daemon or parent-cgroup limits.

Findings flag root/default configured users, privileged mode, host namespaces, added capabilities/devices, unconfined profiles, Docker socket mounts, writable sensitive host mounts, non-loopback published ports, unhealthy containers, OOM kills, restarting state and nonzero exits. These are review items, not proof of exploitation. An image's configured user does not establish the identity of every running process; namespace mappings can also change host privileges. A read-only Docker socket bind does not make Docker API operations read-only.

The inspect command requests an explicit allowlist of metadata. Only the environment entry count is captured; variable names/values, command arguments, labels, health-check logs/output and log-driver options are excluded. No container commands are executed and no images are pulled. Paths, names, addresses and image references remain potentially sensitive operational details. Containers disappearing during inspection produce unknown findings while other container results remain available.

Docker may publish ports without a corresponding userspace listener, so compare Docker bindings with host sockets and firewall rules. Host/macvlan/ipvlan networking may expose services without published-port mappings. This is not an image vulnerability scan, registry freshness check, live resource monitor or Docker daemon hardening assessment. Rootless daemons, remote contexts, Podman and Swarm service specifications are outside scope.

Structured Docker results now live under `checks.docker`; this replaces the earlier text-only `checks.docker_ports` field.

## SSH Match rules

Evaluate the intended connection when `Match` blocks are used:

```bash
sudo python3 audit.py --ssh-context 'user=alice,addr=198.51.100.10,host=client.example,laddr=192.0.2.10,lport=22'
```

Repeat for relevant users and source networks. `sshd -T` reads the default on-disk configuration; a running daemon may use different arguments or an older configuration. Authentication methods may interact: enabled passwords do not necessarily mean password-only login is possible. Keyboard-interactive may be required for MFA. Verify a second working SSH session before applying any recommended access changes.

For a daemon using a custom configuration file, add `--ssh-config /path/to/sshd_config`. This evaluates that file; it does not establish which configuration the running daemon loaded or reproduce command-line overrides.

## Accounts, access and SSH keys

Account checks run automatically. Each enumerated NSS account includes UID/GID, home, shell, groups, `passwd -S` password state, `chage -l` local expiry evidence and `sudo -n -l -U USER` policy evidence. Root is required for complete results. The script flags UID 0, common privileged groups, sudo grants and empty passwords for review. A locked password does not prove SSH key access is disabled. Sudo command scope, run-as users and `NOPASSWD` rules remain visible in native policy output; group names alone cannot establish all privileges.

Key files follow `AuthorizedKeysFile` from the selected SSH configuration/context, including `%h`, `%u`, `%U` and `%%` expansion. Without effective settings, conventional `.ssh/authorized_keys` and `.ssh/authorized_keys2` paths are inspected and labeled as defaults. `none` disables file inspection. This inventories possible authorization files; it does not prove each user can authenticate. Per-account or source-address `Match` rules, `AuthorizedKeysCommand`, certificate authorities, revoked keys and PAM policy need separate review. The audit never executes commands from key options or an AuthorizedKeysCommand.

For each public key, OpenSSH validates the key and supplies its SHA256 fingerprint and bit length. Reports omit key blobs, comments and option values; `options_present` identifies entries whose restrictions require manual review. Shared fingerprints across accounts, DSA keys and RSA keys below 2048 bits produce findings. Home, key directory and key file ownership/modes are checked for unexpected owners and group/other write access. These checks do not cover ACLs or every ancestor directory. Symlink paths, non-regular files and files above 1 MiB are skipped with an unknown result. Private key files and password hashes are not read.

`lastlog` supplies account-level login evidence. For key-level history, the audit reads up to 10,000 journal entries from the last 30 days tagged `sshd` or `sshd-session`. It correlates successful `Accepted publickey` messages by both username and SHA256 fingerprint, reporting the latest observed timestamp and source address. This is the last **observed use in available history**, not a lifetime last-use date. A missing match is **unknown**, never evidence that a key was unused. Rotated, inaccessible or differently formatted logs, older fingerprint formats, certificates and file-only `/var/log/auth.log` logging may not be covered. Account expiry, password state and effective SSH authorization are separate facts.

## Confirm internet exposure

The project now provides an [explicit TCP companion and offline import workflow](external-verification.md). It records selected IPs/ports, operator-declared source location, timestamps and conservative exposure labels. The manual Nmap examples below remain optional separate checks; the companion neither invokes Nmap nor imports Nmap output.

The local report cannot prove external reachability. From a separate network, scan only server addresses you own or are authorized to test. For example, with Nmap already installed:

```bash
nmap -Pn -sT -sV --open -p- YOUR_SERVER_IPV4
nmap -6 -Pn -sT -sV --open -p- YOUR_SERVER_IPV6
sudo nmap -Pn -sU --top-ports 100 YOUR_SERVER_IPV4
```

TCP examples cover all ports. The UDP example samples common ports; `open|filtered` is inconclusive. External service identification is heuristic. Check every public address and provider firewall/NAT configuration. Correlate scan results with local processes and Docker mappings. Other container runtimes and network namespaces require separate inspection.
