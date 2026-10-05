"""Socket inventory and firewall evidence; no external probes."""

import ipaddress


def _parse_listeners(output):
    entries = []
    records = 0
    unparsed = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        records += 1
        fields = line.split(None, 6)
        if len(fields) < 6:
            unparsed += 1
            continue
        address = fields[4]
        host = address.rsplit(":", 1)[0].strip("[]")
        try:
            parsed = ipaddress.ip_address(host.split("%", 1)[0])
            loopback = parsed.is_loopback or bool(getattr(parsed, 'ipv4_mapped', None) and parsed.ipv4_mapped.is_loopback)
        except ValueError:
            loopback = False
        entries.append({
            "protocol": fields[0], "address": address,
            "binding": "loopback" if loopback else "non-loopback (reachability unverified)",
            "process": fields[6] if len(fields) > 6 else "unknown (permissions or kernel socket)",
        })
    coverage = {"status": "partial" if unparsed else "ok", "records_observed": records,
                "records_parsed": len(entries), "records_unparsed": unparsed}
    return entries, coverage


def listeners(output):
    return _parse_listeners(output)[0]


def collect_ports(run):
    check = run(["ss", "-H", "-lntup"])
    findings = []
    if check["status"] == "ok":
        check["listeners"], check["parser_coverage"] = _parse_listeners(check["output"])
        unparsed = check["parser_coverage"]["records_unparsed"]
        if unparsed:
            findings.append({"level": "UNKNOWN", "message": f"Socket inventory incomplete: {unparsed} nonempty ss records could not be parsed. Review the retained command output; listed sockets remain available.", "check": "ports"})
        count = sum(item["binding"] != "loopback" for item in check["listeners"])
        if count:
            findings.append({"level": "REVIEW", "message": f"{count} non-loopback TCP/UDP sockets. Confirm each service is needed and restricted by firewall where appropriate.", "check": "ports"})
    return check, findings


def collect_firewalls(run):
    checks = {name: run(command) for name, command in {
        "ufw": ["ufw", "status", "verbose"],
        "nftables": ["nft", "list", "ruleset"],
        "iptables_ipv4": ["iptables-save"],
        "iptables_ipv6": ["ip6tables-save"],
    }.items()}
    for check in checks.values():
        if check["status"] == "unavailable":
            check["status"] = "skipped"
    return checks


def firewall_findings(checks):
    findings = []
    firewall_backends = ("nftables", "iptables_ipv4", "iptables_ipv6")
    readable = [name for name in firewall_backends if checks.get(name, {}).get("status") == "ok"]
    if not readable:
        findings.append({"level": "UNKNOWN", "message": "No kernel firewall rules could be inspected. UFW status alone cannot establish filtering coverage."})
    else:
        findings.append({"level": "REVIEW", "message": "Firewall evidence available from " + ", ".join(readable) + ". Review input and forwarding chains for both IP families; rule presence does not prove protection."})
        if all(not checks[name].get("output", "").strip() for name in readable):
            findings.append({"level": "REVIEW", "message": "Readable firewall backends returned no rules. Verify host and provider filtering; uninspected backends may still contain rules."})
    return findings
