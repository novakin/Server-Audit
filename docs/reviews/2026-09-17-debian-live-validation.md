# Debian live integration validation — 2026-09-17

[Current live-lab procedure](../live-validation.md) · [Review records](README.md)

Historical evidence, not a current Ubuntu or Debian run. The original date is preserved; its timezone was not recorded. Retained from [live-validation.md at a6599fe](https://github.com/novakin/Server-Audit/blob/a6599fe930bc565b3d13e39eb87faeb964f4b068/docs/live-validation.md) on 2026-09-18 (Europe/Berlin). Commands and former Gitleaks references describe the original environment, not current dependencies. No tests were rerun to move this record.

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

## Historical fixture cleanup

For the historical Debian run, local one-run setup scripts and evidence were retained under `.artifacts/debian-integration/`; they contain machine-specific paths and are not runtime/deployment files. The daemon cleanup trap removes test containers and stops SSH/Docker. Namespace teardown removes the lab network and rules. Host checks after the run found no listeners on ports 22222/18080 and no remaining Docker daemon from the lab.

## Remaining limits

The historical Debian chroot did not run a systemd manager as PID 1. Service checks reported errors, while application-environment and scheduled-task coverage remained partial. These statuses were retained in the final report rather than treated as clean coverage. Live journal-based key-use correlation, systemd timer metadata and standalone Debian boot/service behavior still require a full systemd test host.

Firewall tests validate collection of known rules, not correctness of production filtering. The HTTP probe ran inside the isolated namespace; it establishes the local Docker binding, not public internet exposure. Rootless Docker, other Docker versions/storage drivers, provider firewalls, NAT and remote IPv4/IPv6 reachability remain outside this validation.
