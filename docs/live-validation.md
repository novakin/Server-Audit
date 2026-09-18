# Live integration guide

[Documentation index](../README.md) · [Development guide](development.md)

Last substantive update: 2026-09-18 (Europe/Berlin).

This page owns current lab preparation, execution and limits. The [original Debian validation](reviews/2026-09-17-debian-live-validation.md) and [Ubuntu CI/hardening review](reviews/2026-09-18-ubuntu-ci-hardening.md) are dated historical evidence. Current action status belongs in linked Issues. CI triggers, security and required-check setup belong in [Continuous integration](development.md#continuous-integration).

## Automated Ubuntu lab

The `Ubuntu live integration` job in [ci.yml](../.github/workflows/ci.yml) uses a fresh Ubuntu 24.04 hosted VM only after `Linux tests` succeeds. One shared environment runs the four existing native checks. It does not create a managed server, use production credentials or change the auditor's read-only behavior.

[tests/integration_lab.sh](../tests/integration_lab.sh) owns preparation and cleanup. The VM must have a reachable, empty local Docker daemon; the script refuses existing containers and fixture resources. It installs the native SSH, BusyBox, socket and firewall packages through APT. The image is imported from the installed static BusyBox binary and synthetic files, without a registry pull. Temporary private keys stay under `/opt/lab`, and the fixture authorization file is `/run/server-security-audit-authorized_keys`; neither `/root/.ssh/authorized_keys` nor the normal sshd configuration is replaced. The fixture daemon requires key authentication and listens only on loopback.

Firewall evidence uses a lab-owned nftables table and an unhooked iptables chain. No global flush, default-policy change or hook into live traffic is needed. The disposable VM, rather than an additional namespace/VM service, is the isolation boundary for this hosted job. Docker may create its ordinary container networking rules within that VM.

The script uses bounded readiness checks and traps ordinary exit/interruption to remove only its own daemon, containers, image, rules, keys and files. Cleanup failure prevents success, and does not overwrite an earlier failure with success. Forced termination may prevent traps; GitHub VM disposal is the final cleanup boundary. Installed packages are not uninstalled. Do not upload private keys or complete host reports as artifacts.

On a deliberately disposable VM, from the repository root:

```bash
sudo bash tests/integration_lab.sh --disposable-vm "$(command -v python3)"
```

The acknowledgement and marker prevent accidental use; they do not establish isolation. Never use this command on an operational server. The script ends with `python -m tests.live_ci`, which requires the exact four expected identities, all executed, no failures and zero skips/expected failures. Failed preparation fails CI rather than falling back to skipped tests.

The job log records native versions and the tested revision; its summary records completion or failure. This is Ubuntu evidence for that revision/toolchain, not a new Debian or full production-host validation. The [historical Debian results](reviews/2026-09-17-debian-live-validation.md) remain unchanged. CI trigger/security details and required-check configuration have one owner: [Continuous integration](development.md#continuous-integration).

## Repeatable live-test fixture contract

The same fixture contract targets **Ubuntu and Debian**. The tests do not check a distribution name; they require the native tools and prepared fixtures listed below. The [historical run](reviews/2026-09-17-debian-live-validation.md) establishes its Debian results only. The [Ubuntu acceptance review](reviews/2026-09-18-ubuntu-ci-hardening.md) describes the later four-test hosted run; neither record proves all releases or untested integrations.

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

## Remaining limits

The automated Ubuntu job exercises the four SSH, Docker, firewall and socket tests on its recorded toolchain, not a full production-host audit or a fresh Debian validation. Journal-based key-use correlation, timer metadata, application EnvironmentFiles and standalone Debian boot/service behavior are not established by these four tests. The historical Debian chroot's systemd limitation remains in its [original record](reviews/2026-09-17-debian-live-validation.md#remaining-limits).

Firewall tests establish collection of known evidence, not correctness of production filtering. Loopback HTTP success does not establish public exposure. Rootless Docker, other versions/storage drivers, provider firewalls, NAT and remote IPv4/IPv6 reachability remain outside that validation.

## Historical Debian validation

<a name="debian-live-integration-validation--2026-09-17"></a>

The original historical sections are retained at the following destinations. These forwarding headings preserve earlier links; they do not announce new runs.

## Environment and scope

Historical record: [Environment and scope](reviews/2026-09-17-debian-live-validation.md#environment-and-scope).

## Results

Historical record: [Results](reviews/2026-09-17-debian-live-validation.md#results).

## Bugs found and fixed

Historical record: [Bugs found and fixed](reviews/2026-09-17-debian-live-validation.md#bugs-found-and-fixed).
