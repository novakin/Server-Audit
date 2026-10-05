"""Offline HTML and private, collision-safe audit export bundles."""

import datetime
import html
import json
import os
import re
import tempfile
from pathlib import Path
from string import Template


CHECK_NAMES = {"ssh": "SSH", "ufw": "UFW", "iptables_ipv4": "iptables / IPv4",
               "iptables_ipv6": "iptables / IPv6", "apt_metadata": "APT metadata",
               "os": "Operating system", "environment_files": "Environment files", "git_secrets": "Git secrets", "scheduled_tasks": "Scheduled tasks", "external_verification": "External verification"}


def escape(value):
    return html.escape(str(value), quote=True)


def badge(value):
    style, label = {
        "ok": ("collected", "Collected"), "REVIEW": ("review", "Review"),
        "UNKNOWN": ("unknown", "Unknown"), "error": ("unknown", "Error"),
        "unavailable": ("neutral", "Unavailable"),
        "partial": ("unknown", "Incomplete"),
        "not_requested": ("neutral", "Not requested"),
        "skipped": ("neutral", "Skipped"),
        "unknown": ("unknown", "Unknown"),
        "externally reachable": ("review", "Externally reachable"),
        "not observed from this probe": ("neutral", "Not observed from this probe"),
    }.get(value, ("neutral", str(value)))
    return f'<span class="badge {style}">{escape(label)}</span>'


def table(headers, rows, empty, badge_columns=()):
    if not rows:
        return f'<p class="empty">{escape(empty)}</p>'
    head = ''.join(f'<th scope="col">{escape(item)}</th>' for item in headers)
    body = ''.join('<tr>' + ''.join(f'<td>{badge(item) if index in badge_columns else escape(item)}</td>' for index, item in enumerate(row)) + '</tr>' for row in rows)
    return f'<div class="table-scroll" role="region" aria-label="{escape(headers[0])} inventory" tabindex="0"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def finding_groups(findings):
    """Group explicit metadata without changing, inferring or deduplicating findings."""
    groups = {}
    for index, item in enumerate(findings):
        check = item.get('check')
        if not isinstance(check, str) or not check:
            check = None
        resource_type, resource_id = item.get('resource_type'), item.get('resource_id')
        identity = None
        if check and all(isinstance(value, str) and value for value in (resource_type, resource_id)):
            identity = (resource_type, resource_id)
        resources = groups.setdefault(check, {})
        resources.setdefault(identity, []).append((index, item))
    return groups


def finding_totals(items):
    counts = {level: sum(item.get('level') == level for item in items) for level in ('REVIEW', 'UNKNOWN')}
    return '<span class="finding-totals"><span>Totals:</span> ' + ' '.join(
        f'<span class="count-pill {level.lower()}{" zero" if counts[level] == 0 else ""}">{counts[level]} {label}</span>'
        for level, label in (('REVIEW', 'Review'), ('UNKNOWN', 'Unknown'))
    ) + '</span>'


def render_findings(findings):
    if not findings:
        return '<p class="empty">No findings were recorded. This does not establish that the host is secure.</p>'
    sections = []
    for group_index, (check, resources) in enumerate(finding_groups(findings).items()):
        title = CHECK_NAMES.get(check, check.replace('_', ' ').capitalize()) if check else 'General findings'
        all_items = [item for rows in resources.values() for _, item in rows]
        sections.append(f'<section class="finding-check" aria-labelledby="finding-check-{group_index}"><div class="finding-group-header"><h3 id="finding-check-{group_index}">{escape(title)}</h3>{finding_totals(all_items)}</div>')
        for resource_index, (identity, rows) in enumerate(resources.items()):
            name = 'General'
            if identity:
                candidate = rows[0][1].get('resource_name')
                name = candidate if isinstance(candidate, str) and candidate else identity[1]
            heading = f'finding-resource-{group_index}-{resource_index}'
            if identity or len(resources) > 1:
                sections.append(f'<div class="finding-resource" aria-labelledby="{heading}"><div class="finding-resource-header"><h4 id="{heading}">{escape(name)}</h4>{finding_totals([item for _, item in rows])}</div><ul class="findings">')
            else:
                sections.append('<div class="finding-resource"><ul class="findings">')
            for index, item in rows:
                search = name + ' ' + ' '.join(str(item.get(key, '')) for key in ('check', 'resource_type', 'resource_id', 'resource_name'))
                level = item.get('level', 'UNKNOWN')
                sections.append(f'<li class="finding" data-finding-index="{index}" data-search="{escape(search)}" data-level="{escape(level)}">{badge(level)}<p>{escape(item.get("message", ""))}</p></li>')
            sections.append('</ul></div>')
        sections.append('</section>')
    return ''.join(sections)


def application_coverage_text(applications):
    coverage = applications.get('docker_coverage')
    if not coverage:
        return ''
    return (str(coverage.get('detail', 'Docker application coverage unknown.')) +
            f" Successfully inspected {coverage.get('containers_inspected', 0)} of {coverage.get('containers_retained', 0)} retained containers. " +
            'Directory discovery is independent; application status does not certify complete Docker references.')


def render_limitations(report):
    """Keep general boundaries visible and full collector limits under their owner."""
    sections = ['<ul class="limitations">' + ''.join(f'<li>{escape(item)}</li>' for item in report.get('limitations', [])) + '</ul>']
    for name, check in report.get('checks', {}).items():
        limits = check.get('limitations', [])
        if limits:
            title = CHECK_NAMES.get(name, name.replace('_', ' ').capitalize())
            items = ''.join(f'<li>{escape(item)}</li>' for item in limits)
            sections.append(f'<details class="limitation-topic"><summary><span>{escape(title)}</span><span class="badge neutral">{len(limits)} scope notes</span></summary><ul class="limitations">{items}</ul></details>')
    return ''.join(sections)


def render_html(report):
    timestamp = str(report.get("timestamp_utc", "Unknown"))
    try:
        captured = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if captured.tzinfo is None:
            raise ValueError("Timestamp must include timezone")
        captured = captured.astimezone(datetime.timezone.utc)
        display_timestamp = captured.strftime("%d %b %Y - %H:%M:%S UTC")
    except ValueError:
        display_timestamp = escape(timestamp)
    checks = report.get("checks", {})
    findings = report.get("findings", [])
    review = sum(item.get("level") == "REVIEW" for item in findings)
    unknown = sum(item.get("level") == "UNKNOWN" for item in findings)
    collected = sum(check.get("status") == "ok" for check in checks.values())
    finding_rows = render_findings(findings)
    coverage = ''.join(
        f'<a class="coverage-item" href="#check-{index}"><span>{escape(CHECK_NAMES.get(name, name.replace("_", " ").capitalize()))}</span>{badge(check.get("status", "unknown"))}</a>'
        for index, (name, check) in enumerate(checks.items())
    )
    evidence = ''.join(
        f'<details id="check-{index}"><summary><span>{escape(CHECK_NAMES.get(name, name.replace("_", " ").capitalize()))}</span>{badge(check.get("status", "unknown"))}</summary><pre>{escape(json.dumps(check, indent=2, ensure_ascii=False))}</pre></details>'
        for index, (name, check) in enumerate(checks.items())
    )
    ports = checks.get("ports", {})
    port_table = table(["Address", "Protocol", "Binding", "Owning process"], [
        [entry.get("address", "Unknown"), entry.get("protocol", "Unknown"), entry.get("binding", "Unknown"), entry.get("process", "Unknown")]
        for entry in ports.get("listeners", [])
    ], "No listening sockets recorded." if ports.get("status") == "ok" else "Socket inventory unavailable. Review collection evidence below.")
    accounts = checks.get("accounts", {})
    account_rows = []
    for account in accounts.get("accounts", []):
        keys = [key for file in account.get("key_files", []) for key in file.get("keys", [])]
        uses = [key["last_observed_use"]["timestamp"] for key in keys if key.get("last_observed_use")]
        account_rows.append([account.get("user", "Unknown"), account.get("uid", "Unknown"),
                             ", ".join(account.get("groups", [])) or "None recorded", account.get("shell", "Unknown"),
                             str(len(keys)) + " observed entries", max(uses) if uses else "Unknown"])
    account_table = table(["Account", "UID", "Groups", "Shell", "Key inventory", "Latest observed key use"], account_rows,
                          "No accounts recorded. Review account collection evidence below.")
    docker = checks.get("docker", {})
    container_rows = []
    for container in docker.get("containers", []):
        bindings = []
        for port, entries in (container.get("published_ports") or {}).items():
            for binding in entries or []:
                bindings.append(f"{binding.get('HostIp') or '*'}:{binding.get('HostPort', '?')} to {port}")
        inspected = container.get("inspection_status") == "ok"
        container_rows.append([container.get("name") or container.get("id", "Unknown")[:12], container.get("image", "Unknown"),
                               container.get("status", "Inspection failed"), container.get("health") or "Not reported",
                               (container.get("user") or "Root/default") if inspected else "Unknown", "; ".join(bindings) or "None reported"])
    docker_empty = "No containers found on the inspected daemon." if docker.get("status") == "ok" else "Docker inventory unavailable. Review collection evidence below."
    if docker.get("status") == "skipped":
        docker_empty = docker.get("detail", "Docker audit skipped. See collection evidence for the reason.")
    container_table = table(["Container", "Image", "State", "Health", "Configured user", "Published bindings"], container_rows, docker_empty)
    environment = checks.get("environment_files", {})
    environment_table = table(["Environment file", "Mode", "Owner / group", "Extended ACL", "Inspection"], [
        [item.get("path", "Unknown"), item.get("mode", "Unknown"), str(item.get("owner", item.get("uid", "Unknown"))) + " / " + str(item.get("group", item.get("gid", "Unknown"))), item.get("extended_acl", "Not inspected"), item.get("status", "Unknown")]
        for item in environment.get("files", [])
    ], "No candidates recorded in the scanned scope. Review roots and skipped paths in evidence; this is not a host-wide absence check.")
    applications = environment.get('applications', {})
    application_coverage = application_coverage_text(applications)
    application_table = table(["Application", "Source", "Configured variables", "File references", "Collection"], [
        [source.get("name", "Unknown"), source.get("kind", "Unknown"), source.get("configured_variable_count") if source.get("configured_variable_count") is not None else "Not collected",
         "; ".join(item.get("path", "Unknown") for item in source.get("files", [])) or "None reported", source.get("status", "Unknown")]
        for source in environment.get("applications", {}).get("sources", [])
    ], "No application source metadata recorded.")
    git_checks = checks.get("git_secrets", {})
    git_rows = []
    for repository in git_checks.get("repositories", []):
        if not repository.get("scans"):
            git_rows.append([repository.get("path", "Unknown"), "Not scanned", repository.get("status", "Unknown"), "Unknown"])
        for scan in repository.get("scans", []):
            git_rows.append([repository.get("path", "Unknown"), scan.get("mode", "Unknown"), scan.get("status", "Unknown"),
                             str(len(scan.get("detections", []))) if scan.get("status") == "ok" else "Incomplete"])
    git_table = table(["Repository", "Scope", "Collection", "Possible secrets"], git_rows,
                      "Git secret scanning was not requested. Use --git-root to select local repositories." if git_checks.get("status", "not_requested") == "not_requested" else "Git secret scanning unavailable. See collection evidence.")
    scheduled = checks.get("scheduled_tasks", {})
    scheduled_rows = []
    for definition in scheduled.get("cron_files", []):
        for job in definition.get("jobs", []):
            scheduled_rows.append([str(definition.get("path", "Unknown")) + ":" + str(job.get("line", "?")), job.get("schedule", "Unknown"), job.get("user", "Unknown"), ", ".join(job.get("patterns", [])) or "None detected"])
        if definition.get("kind") == "periodic":
            scheduled_rows.append([definition.get("path", "Unknown"), "Periodic cron file", definition.get("owner", "Unknown"), ", ".join(definition.get("patterns", [])) or "None detected"])
    for timer in scheduled.get("timers", []):
        scheduled_rows.append([timer.get("unit", "Unknown"), timer.get("active_state") or timer.get("status", "Unknown"), timer.get("user", "Unknown"), ", ".join(timer.get("patterns", [])) or "None detected"])
    scheduled_table = table(["Definition", "Schedule / state", "Run as", "Review signals"], scheduled_rows,
                            "No scheduled entries recorded. Check collection status and scope before inferring that none exist.")
    external = checks.get('external_verification', {})
    external_table = table(['Target / port', 'Family / protocol', 'Exposure', 'Probe location / time (UTC)', 'Observation', 'Same-port local candidates (unverified)'], [
        [str(item.get('target', 'Unknown')) + ':' + str(item.get('port', '?')),
         str(item.get('family', 'Unknown')) + ' / ' + str(item.get('protocol', 'unknown')).upper(),
         item.get('exposure', 'unknown'), str(item.get('location', 'Unknown')) + ' / ' + str(item.get('observed_at_utc') or 'Not tested'),
         str(item.get('observation', 'unknown')) + ' — ' + str(item.get('reason', '')), '; '.join(item.get('local_candidates', [])) or 'No same-port candidate in snapshot']
        for item in external.get('observations', [])
    ], 'No external probe results imported. Internet exposure remains unknown.', badge_columns=(2,))
    template = Template(Path(__file__).with_name("templates").joinpath("report_template.html").read_text(encoding="utf-8"))
    return template.substitute(
        host=escape(report.get("host", "Unknown host")), timestamp=display_timestamp,
        review=review, unknown=unknown, collected=collected, total=len(checks), findings_count=len(findings),
        finding_rows=finding_rows, coverage=coverage, evidence=evidence, port_table=port_table,
        account_table=account_table, container_table=container_table, environment_table=environment_table,
        application_table=application_table, application_coverage=f'<p class="note">{escape(application_coverage)}</p>' if application_coverage else '',
        git_table=git_table, scheduled_table=scheduled_table, external_table=external_table,
        limitations=render_limitations(report),
        schema=escape(report.get("schema_version", 1)),
    )


def private_write(path, content):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
        output.write(content)


def export_report(report, destination):
    """Manifest is written last: its presence marks a fully written bundle."""
    rendered = render_html(report)
    serialized = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
    root = Path(destination).expanduser().resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    timestamp = datetime.datetime.now(datetime.timezone.utc)
    hostname = re.sub(r"[^A-Za-z0-9._-]+", "-", str(report.get("host", "host"))).strip(".-")[:64] or "host"
    folder = Path(tempfile.mkdtemp(prefix=timestamp.strftime("%Y%m%dT%H%M%SZ-") + hostname + "-", dir=root))
    try:
        (folder / "data").mkdir(mode=0o700)
        private_write(folder / "data" / "report.json", serialized)
        private_write(folder / "report.html", rendered)
        manifest = {
            "export_schema_version": 1, "status": "complete", "exported_at_utc": timestamp.isoformat(),
            "audit_timestamp_utc": report.get("timestamp_utc"), "host": report.get("host"),
            "files": ["report.html", "data/report.json"],
        }
        private_write(folder / ".manifest.pending", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
        (folder / ".manifest.pending").rename(folder / "manifest.json")
    except OSError as error:
        raise OSError(f"Export incomplete at {folder}: {error}") from error
    return folder


def account_text_report(check):
    lines = []
    if "ssh_scope" in check:
        lines.append("SSH key-path evaluation: " + json.dumps(check["ssh_scope"]))
    for account in check["accounts"]:
        lines.append(f"{account['user']} uid={account['uid']} gid={account['gid']} shell={account['shell']} groups={','.join(account['groups'])}")
        if "key_path_scope" in account:
            lines.append("  Key-path scope: " + json.dumps(account["key_path_scope"]))
        for name in ("password_state", "password_and_account_expiry", "sudo_policy"):
            evidence = account[name]
            lines.append(f"  {name}: {evidence['status']}")
            output = (evidence.get("output", "") + "\n" + evidence.get("detail", "")).strip().splitlines()
            lines.extend("    " + line for line in output[:15])
            if len(output) > 15:
                lines.append("    [Truncated; use --json for full evidence]")
        for permission in account["permissions"]:
            lines.append(f"  {permission['path']}: mode={permission.get('mode', 'unknown')} owner={permission.get('owner_uid', 'unknown')}" + (" " + permission['unknown'] if 'unknown' in permission else ""))
        for inventory in account["key_files"]:
            lines.append(f"  {inventory['path']}: {inventory['status']} {inventory.get('detail', '')}")
            for key in inventory["keys"]:
                usage = key.get("last_observed_use")
                lines.append(f"    line {key['line']}: {key.get('type', 'unknown')} {key.get('fingerprint', key.get('unknown', 'unknown'))}; last observed use=" + (usage['timestamp'] + ' from ' + usage['source'] if usage else 'unknown'))
    lines.append("Key usage evidence: " + json.dumps(check["key_usage"]))
    login = check["last_login"]
    lines.append("Account last-login evidence: " + login["status"])
    output = (login.get("output", "") + "\n" + login.get("detail", "")).strip().splitlines()
    lines.extend(output[:80])
    if len(output) > 80:
        lines.append("[Truncated; use --json for full evidence]")
    lines.extend("Limitation: " + limitation for limitation in check["limitations"])
    return "\n".join(lines)


def docker_text_report(check):
    lines = [f"Endpoint: {check['endpoint']} | Containers: {len(check['containers'])}"]
    for container in check["containers"]:
        lines.append(json.dumps(container, indent=2))
    lines.extend("Limitation: " + item for item in check["limitations"])
    return "\n".join(lines)


def env_text_report(check):
    lines = ["Roots: " + ", ".join(root["path"] + " (" + root["status"] + ")" for root in check["roots"])]
    coverage = application_coverage_text(check.get('applications', {}))
    if coverage:
        lines.append(coverage)
    for source in check.get("applications", {}).get("sources", []):
        lines.append(f"Application {source['kind']}:{source['name']} | {source['status']} | {len(source['files'])} referenced file(s)" + (f" | configured variable count: {source.get('configured_variable_count')}" if source['kind'] == 'docker' else ''))
    lines.extend(f"{item['path']} | {item['mode']} | {item['owner']}:{item['group']} | {item['status']} | ACL {item.get('extended_acl', 'not inspected')}" for item in check["files"])
    lines.append(f"Entries examined: {check['entries_examined']}; skipped paths: {len(check['skipped'])}. Full scope/evidence in JSON or HTML export.")
    lines.extend("Limitation: " + item for item in check["limitations"])
    return "\n".join(lines)


def git_text_report(check):
    return json.dumps(check, indent=2)


def render_text(report):
    output_lines = []
    def emit(value):
        output_lines.append(str(value))
    emit(f"Server audit: {report['host']} | {report['timestamp_utc']}")
    emit(f"Review: {report['summary']['REVIEW']} | Unknown: {report['summary']['UNKNOWN']} (not a security score)")
    for finding in report["findings"]:
        emit(f"[{finding['level']}] {finding['message']}")
    for name, check in report["checks"].items():
        emit(f"\n--- {name}: {check['status']} ---")
        if name == "ssh" and "configuration_source" in check:
            emit("SSH configuration source: " + str(check["configuration_source"]))
            if check.get("configuration_path") is not None:
                emit("SSH configuration argument: " + str(check["configuration_path"]))
            emit("SSH connection context: " + str(check.get("connection_context") or "Not supplied"))
        if name == "ports" and "listeners" in check:
            for item in check["listeners"]:
                emit(f"{item['protocol']} {item['address']} | {item['binding']} | {item['process']}")
        elif name == "accounts" and "accounts" in check:
            emit(account_text_report(check))
        elif name == "docker" and "containers" in check:
            emit(docker_text_report(check))
        elif name == "environment_files" and "files" in check:
            emit(env_text_report(check))
        elif name == "git_secrets":
            emit(git_text_report(check))
        elif name in ("scheduled_tasks", "external_verification"):
            emit(json.dumps(check, indent=2))
        else:
            lines = check.get("output", "").splitlines()
            emit("\n".join(lines[:80]))
            if len(lines) > 80:
                emit("[Truncated; use --json for full evidence]")
        if check.get("detail"):
            emit(check["detail"])
    emit("\nLimitations:")
    for limitation in report["limitations"]:
        emit("- " + limitation)
    return "\n".join(output_lines) + "\n"
