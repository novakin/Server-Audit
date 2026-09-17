# External verification runbook

[Documentation index](../README.md) · Reviewed 2026-09-17

## Purpose and trust boundary

The server audit observes local configuration. The companion `external_probe.py` tests selected TCP endpoints from another machine, then imports the observations into a new offline HTML/JSON bundle. The host audit never launches the companion or makes remote connections automatically.

Use only addresses you own or are authorized to test. Select literal IP addresses explicitly; there is no DNS lookup, CIDR expansion, automatic public-IP discovery or target discovery from report text. IP ownership and the relationship between the address and audited host are operator assertions. A TCP handshake can reach a NAT gateway, proxy or CDN rather than the locally recorded process.

Run the probe on a genuinely independent network, such as a separate VPS or another internet connection. Running on the audited host or the same private network does not establish internet exposure. `--independent` records your assertion; the tool cannot verify it automatically. VPN routing may invalidate an apparent independent vantage point. The location label is descriptive, not geolocation proof.

## 1. Export the server snapshot

On the audited Ubuntu/Debian server:

```bash
sudo python3 audit.py --export /var/lib/server-security-audit
```

Keep the original bundle. Transfer its `data/report.json` to the independent probe machine through your normal secure transfer process. It contains sensitive host evidence. Copy the project runtime files there as well, including both `external_*.py` modules, `reporting.py` and `report_template.html`. The companion uses Python's standard library and supports portable Python socket APIs; it does not require root or Nmap. It does not run the Linux host audit on the probe machine.

## 2. Review the selected scope

The documentation addresses below are reserved examples. Replace them with your explicitly authorized real server addresses. Reserved/private targets can be tested for diagnostics, but their internet-exposure label remains Unknown.

```bash
python3 external_probe.py probe --audit report.json --target 203.0.113.10 --target 2001:db8::10 --location "Independent VPS, provider and region" --independent --dry-run
```

The dry run prints target addresses, selected TCP ports and connection count. It opens no sockets and writes no result file. By default, ports are the union of local TCP listeners and actual published bindings of running Docker containers. Loopback-only listeners are included as candidates; this does not imply that they should be exposed. Stopped-container configured bindings are excluded. UDP is not probed.

Override the port set when testing a defined perimeter, ports absent from the local snapshot, or translated public ports:

```bash
python3 external_probe.py probe --audit report.json --target 203.0.113.10 --ports 22,80,443,8000-8010 --location "Independent VPS, provider and region" --independent --dry-run
```

An empty derived port set requires explicit `--ports`; it is not treated as a successful scan. IPv4 and IPv6 addresses are separate targets. An IPv4-only probe says nothing about IPv6 exposure.

## 3. Run the probe

Use the same reviewed arguments, replace `--dry-run` with a new output filename, and run from the independent machine:

```bash
python3 external_probe.py probe --audit report.json --target 203.0.113.10 --ports 22,80,443,8000-8010 --location "Independent VPS, provider and region" --independent --timeout 2 --output probe-vps.json
```

Each selected address/port pair receives one TCP connect attempt. The socket is closed without sending application data or reading banners. The attempt can still trigger server/network logging and monitoring. This is not a stealth scan or an application security test.

Probe files record the declared location, probe hostname, independence assertion, target IP/family, protocol, selected ports, start/end and observation timestamps, timeout and raw observation. A socket's local source address is recorded when available; it may be private behind NAT and is not proof of the internet-visible source IP. No external IP-discovery service is contacted.

The destination parent must already exist. Output uses exclusive creation with Linux mode `0600` and never overwrites existing files, including symlinks. Windows/mounted-filesystem ACL behavior still governs effective access. Interrupted or failed runs can leave an empty/partial file; import rejects it. Use a new filename for a retry and manage the old artifact explicitly.

Limits: at most eight target addresses and 1,024 address/port pairs, eight concurrent connections, and a per-connect timeout greater than zero and at most five seconds (default two). There are no retries. Timeouts bound individual sockets, not a strict whole-process deadline; a maximum-size run can take several minutes. Scoped IPv6, IPv4-mapped IPv6, multicast and unspecified addresses are rejected. Ordinary private/loopback diagnostics are allowed but remain Unknown for internet exposure.

## 4. Import offline

Copy probe files back to your internal review machine. Import into the exact original report used for the probe:

```bash
python3 external_probe.py import --audit report.json --results probe-vps.json --export ./verified-audits
```

Several independent observations can be included together:

```bash
python3 external_probe.py import --audit report.json --results probe-vps.json --results probe-other-network.json --export ./verified-audits
```

Import runs no host commands and opens no network sockets. It creates a new unique bundle using the existing private export mechanism. The original audit/file timestamps and findings are preserved; imported evidence lives under `checks.external_verification`. The new manifest records the new export time. Text rendering also includes the imported evidence.

Use the original report for every import, not a previously enriched report. Import accepts at most eight probe files together and rejects identical duplicates, mismatched audit identity, unsupported schemas, duplicate/missing observations, inconsistent scope/family/protocol and invalid times. Original audit input is limited to 32 MiB, each probe file to 2 MiB, and local correlation inventory to 4,096 entries. Input must be regular JSON files. Unknown fields in probe files are discarded; only validated fields enter evidence.

Identity binding uses the original host, audit timestamp and schema version. It prevents accidental cross-audit mixing, but it is not a signature, content hash or authentication mechanism. Import only results from trusted operators/storage. A malicious editor can fabricate an observation. Probe clocks more than five minutes ahead of the importer are rejected. A probe before the snapshot or more than 24 hours afterward adds an Unknown finding about stale service correlation; actual observation time remains visible.

## Interpretation

| Exposure label | Required evidence and meaning |
| --- | --- |
| Externally reachable | TCP connection succeeded to a public/global address and the operator asserted an independent source. This applies to that endpoint and time, not proven application identity. |
| Not observed from this probe | TCP connection was refused or timed out, with a public/global target and independent-source assertion. It does not prove universal protection. |
| Unknown | Local/network failure, nonpublic target, unconfirmed independent source, UDP, or an inventory port outside selected scope. |

“Public/global” follows Python's IP address classification. Raw observations (`connected`, `refused`, `timeout`, `local_or_network_error`) remain visible even when the conservative exposure label is Unknown. Imported reachable endpoints produce Review findings. Unknown rows and stale correlation produce Unknown findings; these are not severity scores.

The report shows same-port listeners and Docker bindings as **unverified candidates**. It deliberately does not assume identical address families, addresses or service identities across NAT/proxies. A public port absent from the local snapshot can still be reachable and will have no candidate. Reverse-proxy routing, virtual hosts, TLS/SNI, CDN/origin distinction and translated ports require a separate application-level review. No HTTP requests, TLS negotiation, DNS resolution, UDP scan or application identification is performed by this companion.

## CLI and automation

`external_probe.py probe --help` and `external_probe.py import --help` list the options. Successful probing/import returns `0`; this is completion, not a security pass. Validation/I/O failures return `1`; argument errors return `2`. Ctrl+C returns `130`, cancels queued endpoints and waits for active sockets to finish within their individual timeout; any incomplete output must not be imported. Probe status does not change the exit code. Import requires complete declared result coverage; a local/network error is a complete but Unknown observation, not a missing row. The companion requires Python 3.9 or newer for queued-future cancellation; it is verified on Python 3.12/3.13.

The original host-only limitation that no external scan was performed still describes host collection. Imported observations are separate evidence from a different source/time, displayed in the External verification section. Keep both when handing a report to another reviewer.

## Verification

`test_external_verification.py` covers real loopback TCP connections, mocked public IPv4/IPv6 observations, timeout/refusal distinctions, conservative labels, candidate extraction, redaction/projection, malformed/mismatched inputs, exclusive private output, no-network dry run/import and completed enriched exports. Public addresses in fixtures are mocked; the suite makes no external scans. Native IPv6 loopback passed on Ubuntu. The Windows test host denied its native IPv6 control connection with WSAEACCES; that test is skipped when platform/network policy blocks it, and actual probe failures remain Unknown. Existing runtime tests remain separate. HTML was reviewed at desktop/mobile sizes in light/dark themes; exposure states remain distinct and wide tables scroll within the report.
