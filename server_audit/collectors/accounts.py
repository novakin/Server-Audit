"""Account access evidence; never read private keys or password hashes."""

import datetime
import json
import os
import re
import shlex
import stat
from pathlib import Path


def permission_info(path, uid):
    try:
        info = path.lstat()
        return {"path": str(path), "mode": oct(stat.S_IMODE(info.st_mode)),
                "owner_uid": info.st_uid, "symlink": stat.S_ISLNK(info.st_mode),
                "unsafe": info.st_uid not in (0, uid) or bool(info.st_mode & 0o022)}
    except OSError as error:
        return {"path": str(path), "unknown": str(error)}


def key_inventory(path, run):
    """Use OpenSSH to validate and fingerprint public keys without retaining blobs."""
    result = {"path": str(path), "keys": []}
    try:
        if path.resolve() != path.absolute():
            raise ValueError("Symlink path skipped; inspect manually")
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("Not a regular file")
            data = source.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("File exceeds 1 MiB inspection limit")
        for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key = {"line": number, "last_observed_use": None}
            try:
                lexer = shlex.shlex(line, posix=True)
                lexer.whitespace_split = True
                lexer.commenters = ""
                first = next(lexer)
                tokens = [first, next(lexer)]
                if not first.startswith(("ssh-", "ecdsa-", "sk-")):
                    tokens.append(next(lexer))
                index = next(i for i, token in enumerate(tokens[:2]) if token.startswith(("ssh-", "ecdsa-", "sk-")))
                checked = run(["ssh-keygen", "-l", "-E", "sha256", "-f", "/dev/stdin"], input_text=tokens[index] + " " + tokens[index + 1] + "\n")
                if checked["status"] != "ok":
                    raise ValueError("Key validation unavailable or rejected by ssh-keygen")
                fields = checked["output"].split()
                key.update(bits=int(fields[0]), fingerprint=fields[1], type=tokens[index], options_present=index == 1)
            except (ValueError, StopIteration, IndexError) as error:
                key["unknown"] = str(error) or "Unrecognized authorized_keys entry"
            result["keys"].append(key)
    except FileNotFoundError:
        result["status"] = "absent"
    except (OSError, ValueError) as error:
        result.update(status="unknown", detail=str(error))
    else:
        result["status"] = "ok"
    return result


def login_events(output):
    events = []
    pattern = re.compile(r"Accepted publickey for (\S+) from (\S+) port \d+ ssh2: .*?(SHA256:[A-Za-z0-9+/]+)")
    for line in output.splitlines():
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                continue
            match = pattern.search(record.get("MESSAGE", ""))
            if match:
                stamp = datetime.datetime.fromtimestamp(int(record["__REALTIME_TIMESTAMP"]) / 1_000_000, datetime.timezone.utc).isoformat()
                events.append({"user": match[1], "source": match[2], "fingerprint": match[3], "timestamp": stamp})
        except (ValueError, KeyError, TypeError, OverflowError, OSError):
            continue
    return sorted(events, key=lambda event: event["timestamp"])


def collect(run, ssh_output=""):
    import pwd
    import grp

    findings = []
    accounts = []
    settings = dict(line.split(None, 1) for line in ssh_output.splitlines() if len(line.split(None, 1)) == 2)
    templates = settings.get("authorizedkeysfile", ".ssh/authorized_keys .ssh/authorized_keys2").split()
    journal = run(["journalctl", "-t", "sshd", "-t", "sshd-session", "--since", "30 days ago", "-n", "10000", "--no-pager", "-o", "json"])
    events = login_events(journal.get("output", "")) if journal["status"] == "ok" else []
    usage = {"status": journal["status"], "detail": journal.get("detail", ""), "window": "Last 30 days, at most 10000 journal entries", "matched_events": len(events)}
    if journal["status"] != "ok" or journal.get("detail") or os.geteuid() != 0:
        findings.append({"level": "UNKNOWN", "message": "SSH key usage history may be incomplete or unavailable; inspect account key_usage evidence and journal permissions."})
    groups = grp.getgrall()
    users = pwd.getpwall()
    fingerprints = {}
    for user in users:
        membership = sorted({group.gr_name for group in groups if user.pw_name in group.gr_mem or group.gr_gid == user.pw_gid})
        account = {"user": user.pw_name, "uid": user.pw_uid, "gid": user.pw_gid, "home": user.pw_dir,
                   "shell": user.pw_shell, "groups": membership, "key_files": [],
                   "password_state": run(["passwd", "-S", user.pw_name]),
                   "password_and_account_expiry": run(["chage", "-l", user.pw_name])}
        if os.geteuid() == 0:
            account["sudo_policy"] = run(["sudo", "-n", "-l", "-U", user.pw_name])
        else:
            account["sudo_policy"] = {"status": "unknown", "detail": "Root required to query another user's sudo policy"}
        sudo = account["sudo_policy"]
        if sudo["status"] == "ok" and "may run the following commands" in sudo.get("output", ""):
            findings.append({"level": "REVIEW", "message": f"Account {user.pw_name} has sudo command grants. Review sudo_policy for command scope, run-as users and NOPASSWD rules."})
        if user.pw_uid == 0 or set(membership) & {"sudo", "admin", "docker", "lxd", "disk"}:
            findings.append({"level": "REVIEW", "message": f"Account {user.pw_name}: UID {user.pw_uid}, privileged groups {membership}. Review intended administrative access."})
        state = account["password_state"].get("output", "").split()
        if len(state) > 1 and state[1] == "NP":
            findings.append({"level": "REVIEW", "message": f"Account {user.pw_name} has no password. Actual login depends on PAM and SSH policy."})
        account["permissions"] = [permission_info(Path(user.pw_dir), user.pw_uid)]
        for template in templates:
            if template == "none":
                continue
            expanded = re.sub(r"%[%huU]", lambda match: {"%%": "%", "%h": user.pw_dir, "%u": user.pw_name, "%U": str(user.pw_uid)}[match[0]], template)
            path = Path(expanded)
            if not path.is_absolute():
                path = Path(user.pw_dir) / path
            inventory = key_inventory(path, run)
            account["key_files"].append(inventory)
            if inventory["status"] == "unknown":
                findings.append({"level": "UNKNOWN", "message": f"{user.pw_name}: {path}: {inventory['detail']}"})
            if inventory["status"] != "absent":
                account["permissions"].extend(permission_info(parent, user.pw_uid) for parent in (path.parent, path))
            for key in inventory["keys"]:
                fingerprint = key.get("fingerprint")
                if fingerprint:
                    fingerprints.setdefault(fingerprint, set()).add(user.pw_name)
                    matches = [event for event in events if event["user"] == user.pw_name and event["fingerprint"] == fingerprint]
                    key["last_observed_use"] = matches[-1] if matches else None
                    if key["type"] == "ssh-dss" or (key["type"] == "ssh-rsa" and key["bits"] < 2048):
                        findings.append({"level": "REVIEW", "message": f"{user.pw_name}: weak/obsolete key {fingerprint} ({key['type']}, {key['bits']} bits)."})
                else:
                    findings.append({"level": "UNKNOWN", "message": f"{user.pw_name}: could not validate key at {path}:{key['line']}."})
        for permission in account["permissions"]:
            if permission.get("unsafe"):
                findings.append({"level": "REVIEW", "message": f"{user.pw_name}: unexpected owner or group/other write permission on {permission['path']} ({permission['mode']})."})
        accounts.append(account)
    for fingerprint, owners in fingerprints.items():
        if len(owners) > 1:
            findings.append({"level": "REVIEW", "message": f"SSH key {fingerprint} shared across accounts: {', '.join(sorted(owners))}."})
    last_login = run(["lastlog"])
    incomplete = [account["user"] for account in accounts if account["password_state"]["status"] != "ok"]
    if incomplete:
        findings.append({"level": "UNKNOWN", "message": "Password state unavailable for: " + ", ".join(incomplete)})
    incomplete_sudo = [account["user"] for account in accounts if account["sudo_policy"]["status"] != "ok" and "is not allowed to run sudo" not in (account["sudo_policy"].get("output", "") + account["sudo_policy"].get("detail", ""))]
    if incomplete_sudo:
        findings.append({"level": "UNKNOWN", "message": "Sudo policy could not be established for: " + ", ".join(incomplete_sudo)})
    incomplete_expiry = [account["user"] for account in accounts if account["password_and_account_expiry"]["status"] != "ok"]
    if incomplete_expiry:
        findings.append({"level": "UNKNOWN", "message": "Account/password expiry unavailable for: " + ", ".join(incomplete_expiry)})
    if last_login["status"] != "ok":
        findings.append({"level": "UNKNOWN", "message": "Account last-login history unavailable; inspect last_login evidence."})
    return {"status": "ok", "accounts": accounts, "key_usage": usage,
            "key_path_source": "selected sshd configuration/context" if "authorizedkeysfile" in settings else "conventional defaults; effective paths unknown",
            "last_login": last_login,
            "limitations": [
                "Accounts/groups are those enumerable through NSS; non-enumerable directory users may be absent.",
                "Password lock is not account disablement: SSH keys may still work. chage describes local shadow expiry; directory/PAM policies may differ.",
                "Sudo evidence comes from sudo -l; denied policies and lookup errors retain their native status. Group names alone do not prove all effective privileges.",
                "Key paths use the selected sshd output, or conventional defaults if unavailable. Per-user/address Match rules, AuthorizedKeysCommand, trusted CAs and certificates require separate review.",
                "Permissions cover home, key parent and key file mode/owner, not ACLs or all ancestor directories. Symlink key paths are skipped.",
                "Last observed key use comes only from visible retained journal entries. No match means unknown, never unused. lastlog may be missing or incomplete and is account-level, not key-level.",
            ]}, findings
