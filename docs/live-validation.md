# Debian live integration validation — 2026-09-17

[Documentation index](../README.md) · [Development guide](development.md)

This page preserves a historical native-lab run, including its original flat-layout commands and former Gitleaks integration. Those dated results are not a new validation of the current package. The [automated Ubuntu lab](#automated-ubuntu-lab) below describes the current integration job; revision-specific results belong in its CI run and PR. For current test commands, use the [development guide](development.md#local-setup). The automated workflow, triggers, prerequisites, skip policy and required-check setup are documented under [Continuous integration](development.md#continuous-integration).

## Environment and scope

Validation used a disposable Debian 13 (trixie) root filesystem bootstrapped from Debian's signed archive, running on the WSL2 Linux kernel. Separate mount, PID and network namespaces isolated the test services and firewall rules. This exercised real Debian tools, not mocked command responses. It was not a standalone Debian VM or a production deployment.

| Component | Version |
| --- | --- |
| Python | 3.13.5 |
| OpenSSH server | 10.0p1-7+deb13u4 |
| Docker daemon and CLI | 26.1.5+dfsg1-9+deb13u1 |
| nftables | 1.1.3-1 |
| iptables | 1.8.11-2 |
| Git | 2.47.3-0+deb13u1 |
| Gitleaks | 8.30.1, existing checksum-verified test binary |

Only the disposable root filesystem received packages and configuration. Debian 13's minimal Docker setup required both `docker.io` and `docker-cli`; installing the daemon alone did not provide the CLI. Docker used the `vfs` storage driver and a local BusyBox image assembled from a Debian package. No registry image or external host was probed.

## Results

| Check | Observed result |
| --- | --- |
| Existing suite | 68 passed, including real Gitleaks scanning; discovery also skipped the four separately gated live tests |
| Live suite | Four tests passed, no skips |
| SSH | Real key-authenticated login on loopback port 22222; effective custom configuration and Match override verified; native public-key fingerprinting succeeded |
| Docker | Running HTTP container and stopped container inspected; published loopback port served the expected response; user, read-only rootfs, memory/PID limits and environment count checked |
| Docker health/redaction | Containers with and without health-check data inspected; null environment list returned count zero; fake environment/label/health-command secret excluded |
| Firewall | Real nftables rule and IPv4 iptables rule collected; IPv6 iptables ruleset collection succeeded |
| Sockets | SSH loopback binding and owning `sshd` process identified |
| Export | CLI generated HTML, identical structured JSON and a complete manifest; fake secret absent from HTML and JSON |

The normal suite command was `AUDIT_TEST_GITLEAKS_PATH=/usr/local/bin/gitleaks python3 -m unittest discover -s . -p 'test_*.py' -q`. The separately prepared fixture used `AUDIT_LIVE_INTEGRATION=1 python3 -m unittest test_live_integrations -v`.

## Bugs found and fixed

Real Docker inspection exposed two template errors that mocked responses had not exercised:

1. Containers without health checks omit `State.Health`. Direct field access failed. The projection now uses a guarded map lookup and exports `null` when absent.
2. Containers can have a null `Config.Env`. Applying `len` directly failed. The projection now exports zero for null/absent environment entries.

The changes remain in `server_audit/collectors/docker_audit.py`, the owning collector. `tests/test_live_integrations.py` retains native regression coverage for both cases. No architecture layer or dependency was added to the audit runtime.

## Automated Ubuntu lab

Reviewed: 2026-09-18 (Europe/Berlin).

The `Ubuntu live integration` job in [ci.yml](../.github/workflows/ci.yml) uses a fresh Ubuntu 24.04 hosted VM only after `Linux tests` succeeds. One shared environment runs the four existing native checks. It does not create a managed server, use production credentials or change the auditor's read-only behavior.

[tests/integration_lab.sh](../tests/integration_lab.sh) owns preparation and cleanup. The VM must have a reachable, empty local Docker daemon; the script refuses existing containers and fixture resources. It installs the native SSH, BusyBox, socket and firewall packages through APT. The image is imported from the installed static BusyBox binary and synthetic files, without a registry pull. Temporary private keys stay under `/opt/lab`, and the fixture authorization file is `/run/server-security-audit-authorized_keys`; neither `/root/.ssh/authorized_keys` nor the normal sshd configuration is replaced. The fixture daemon requires key authentication and listens only on loopback.

Firewall evidence uses a lab-owned nftables table and an unhooked iptables chain. No global flush, default-policy change or hook into live traffic is needed. The disposable VM, rather than an additional namespace/VM service, is the isolation boundary for this hosted job. Docker may create its ordinary container networking rules within that VM.

The script uses bounded readiness checks and traps ordinary exit/interruption to remove only its own daemon, containers, image, rules, keys and files. Cleanup failure prevents success, and does not overwrite an earlier failure with success. Forced termination may prevent traps; GitHub VM disposal is the final cleanup boundary. Installed packages are not uninstalled. Do not upload private keys or complete host reports as artifacts.

On a deliberately disposable VM, from the repository root:

```bash
sudo bash tests/integration_lab.sh --disposable-vm "$(command -v python3)"
```

The acknowledgement and marker prevent accidental use; they do not establish isolation. Never use this command on an operational server. The script ends with `python -m tests.live_ci`, which requires the exact four expected identities, all executed, no failures and zero skips/expected failures. Failed preparation fails CI rather than falling back to skipped tests.

The job log records native versions and the tested revision; its summary records completion or failure. This is Ubuntu evidence for that revision/toolchain, not a new Debian or full production-host validation. The historical results above remain unchanged. CI trigger/security details and required-check configuration have one owner: [Continuous integration](development.md#continuous-integration).

## Repeatable live-test fixture contract

The same fixture contract targets **Ubuntu and Debian**. The tests do not check a distribution name; they require the native tools and prepared fixtures listed below. The historical run above establishes Debian results only, not an equivalent Ubuntu live validation.

Routine GitHub CI runs on Ubuntu 24.04 with `AUDIT_LIVE_INTEGRATION=0`. The four live-test skips mean that the lab has not been provisioned and enabled, **not that Ubuntu is unsupported**. The routine CI runner rejects live activation. Its successful completion enables the separate hosted integration job described above.

The opt-in tests do not provision a server. Prepare an isolated, disposable Ubuntu or Debian environment first; do not run the fixture setup against a production host. Normal test discovery skips these checks. Explicit activation requires root and `/run/server-security-audit-integration-lab`; the marker is a misuse guard, not an isolation mechanism.

For an already prepared authorised disposable lab, run from the current repository root:

```bash
AUDIT_LIVE_INTEGRATION=1 python3 -m unittest tests.test_live_integrations -v
```

The fixture must provide:

- Real `sshd`, `ssh-keygen`, `docker`, `ss`, `nft`, `iptables-save` and `ip6tables-save`, with a reachable local default Docker socket.
- SSH on `127.0.0.1:22222`, a generated lab key in `/run/server-security-audit-authorized_keys` selected by that fixture configuration, and `/opt/lab/sshd_config`. Base settings disable password authentication and TCP forwarding; a `Match User root Address 127.0.0.1` block enables forwarding.
- A successful key login that prints `audit-live-ssh-ok` into `/results/ssh-client.txt`, with sshd authentication output in `/results/sshd.log`.
- Exactly two Docker containers: `audit-integration-web` running an HTTP endpoint at `127.0.0.1:18080` mapped to container port 80, and `audit-integration-stopped`, created but not running.
- The web container has 64 MiB memory and 64 PID limits, configured environment entries, and a starting/healthy health check. Use fake marker `PRIVATE_SENTINEL_LIVE` in environment, label and health-command data. The HTTP response body is `audit-live-http-ok`.
- The stopped container has user `1000:1000`, a read-only root filesystem, no health check and zero configured environment entries.
- An nftables rule comment `audit-integration-ssh` and an IPv4 iptables rule comment `audit-integration-docker`, created only inside the disposable lab. The hosted setup uses unhooked evidence chains; the historical Debian run used a separate network namespace.

For the historical Debian run, local one-run setup scripts and evidence were retained under `.artifacts/debian-integration/`; they contain machine-specific paths and are not runtime/deployment files. The daemon cleanup trap removes test containers and stops SSH/Docker. Namespace teardown removes the lab network and rules. Host checks after the run found no listeners on ports 22222/18080 and no remaining Docker daemon from the lab.

## Remaining limits

The historical Debian chroot did not run a systemd manager as PID 1. Service checks reported errors, while application-environment and scheduled-task coverage remained partial. These statuses were retained in the final report rather than treated as clean coverage. Live journal-based key-use correlation, systemd timer metadata and standalone Debian boot/service behavior still require a full systemd test host.

Firewall tests validate collection of known rules, not correctness of production filtering. The HTTP probe ran inside the isolated namespace; it establishes the local Docker binding, not public internet exposure. Rootless Docker, other Docker versions/storage drivers, provider firewalls, NAT and remote IPv4/IPv6 reachability remain outside this validation.
