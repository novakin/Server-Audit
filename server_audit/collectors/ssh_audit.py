"""SSH configuration collection and policy review."""

import json


def _finding(message, config, connection):
    finding = {"level": "REVIEW", "message": message, "check": "ssh"}
    if config or connection:
        finding.update(resource_type="ssh_configuration",
                       resource_id=json.dumps([config, connection], separators=(",", ":")),
                       resource_name=(config or "sshd default configuration") + (" (" + connection + ")" if connection else ""))
    return finding


def ssh_findings(output, *, config=None, connection=None):
    settings = dict(line.split(None, 1) for line in output.splitlines() if len(line.split(None, 1)) == 2)
    findings = []
    forwarding_disabled = settings.get("disableforwarding") == "yes"
    for key, safe, advice in [
        ("permitrootlogin", {"no"}, "Prefer a named administrator with sudo; verify access before disabling root login."),
        ("passwordauthentication", {"no"}, "Prefer SSH keys; verify key access before disabling passwords."),
        ("permitemptypasswords", {"no"}, "Disable empty-password authentication."),
        ("x11forwarding", {"no"}, "Disable X11 forwarding if unused."),
        ("allowtcpforwarding", {"no"}, "Restrict forwarding if SSH tunnels are not required."),
    ]:
        if forwarding_disabled and key in {"x11forwarding", "allowtcpforwarding"}:
            continue
        value = settings.get(key)
        if value is not None and value not in safe:
            findings.append(_finding(f"SSH {key}={value}. {advice}", config, connection))
    if settings.get("kbdinteractiveauthentication") == "yes":
        findings.append(_finding("SSH keyboard-interactive authentication enabled; inspect PAM/MFA policy before changing it.", config, connection))
    selected = {key: value for key, value in settings.items() if key in {
        "port", "listenaddress", "permitrootlogin", "passwordauthentication",
        "pubkeyauthentication", "kbdinteractiveauthentication", "usepam",
        "permitemptypasswords", "authenticationmethods", "allowusers", "allowgroups",
        "denyusers", "denygroups", "maxauthtries", "x11forwarding", "allowtcpforwarding", "disableforwarding",
    }}
    return selected, findings


def collect(run, connection=None, config=None):
    command = ["sshd", "-T"]
    if config:
        command += ["-f", config]
    if connection:
        command += ["-C", connection]
    check = run(command)
    # Retain attempted scope even when sshd is missing or rejects the request.
    check.update(configuration_source="custom" if config else "default",
                 configuration_path=config or None, connection_context=connection or None)
    findings = []
    if check["status"] == "ok":
        settings, findings = ssh_findings(check["output"], config=config, connection=connection)
        check["selected_settings"] = settings
        # Keep legacy scalar values; this additive map preserves every occurrence.
        values = {}
        for line in check["output"].splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0] in settings:
                values.setdefault(parts[0], []).append(parts[1])
        check["selected_setting_values"] = values
    return check, findings
