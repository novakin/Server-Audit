"""SSH configuration collection and policy review."""


def ssh_findings(output):
    settings = dict(line.split(None, 1) for line in output.splitlines() if len(line.split(None, 1)) == 2)
    findings = []
    for key, safe, advice in [
        ("permitrootlogin", {"no"}, "Prefer a named administrator with sudo; verify access before disabling root login."),
        ("passwordauthentication", {"no"}, "Prefer SSH keys; verify key access before disabling passwords."),
        ("permitemptypasswords", {"no"}, "Disable empty-password authentication."),
        ("x11forwarding", {"no"}, "Disable X11 forwarding if unused."),
        ("allowtcpforwarding", {"no"}, "Restrict forwarding if SSH tunnels are not required."),
    ]:
        value = settings.get(key)
        if value is not None and value not in safe:
            findings.append({"level": "REVIEW", "message": f"SSH {key}={value}. {advice}"})
    if settings.get("kbdinteractiveauthentication") == "yes":
        findings.append({"level": "REVIEW", "message": "SSH keyboard-interactive authentication enabled; inspect PAM/MFA policy before changing it."})
    selected = {key: value for key, value in settings.items() if key in {
        "port", "listenaddress", "permitrootlogin", "passwordauthentication",
        "pubkeyauthentication", "kbdinteractiveauthentication", "usepam",
        "permitemptypasswords", "authenticationmethods", "allowusers", "allowgroups",
        "denyusers", "denygroups", "maxauthtries", "x11forwarding", "allowtcpforwarding",
    }}
    return selected, findings


def collect(run, connection=None, config=None):
    command = ["sshd", "-T"]
    if config:
        command += ["-f", config]
    if connection:
        command += ["-C", connection]
    check = run(command)
    findings = []
    if check["status"] == "ok":
        settings, findings = ssh_findings(check["output"])
        check["selected_settings"] = settings
    return check, findings
