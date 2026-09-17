"""Bounded .env discovery using filesystem metadata only."""

import errno
import os
import re
import stat
import time
from pathlib import Path


DEFAULT_ROOTS = ("/etc", "/opt", "/srv", "/var/www", "/home", "/root")
EXCLUDED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
MAX_ENTRIES = 50000
MAX_FILES = 500
MAX_DEPTH = 12
SCAN_SECONDS = 15


def is_env_name(name):
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def metadata(path):
    info = path.lstat()
    result = {"path": str(path), "mode": format(stat.S_IMODE(info.st_mode), "04o"),
              "uid": info.st_uid, "gid": info.st_gid, "type": "file" if stat.S_ISREG(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "special",
              "sticky": bool(info.st_mode & stat.S_ISVTX)}
    try:
        import pwd
        import grp
        try:
            result["owner"] = pwd.getpwuid(info.st_uid).pw_name
        except KeyError:
            result["owner"] = str(info.st_uid)
        try:
            result["group"] = grp.getgrgid(info.st_gid).gr_name
        except KeyError:
            result["group"] = str(info.st_gid)
    except ImportError:
        result.update(owner=str(info.st_uid), group=str(info.st_gid))
    if result["type"] in ("file", "directory"):
        try:
            os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
            result["extended_acl"] = "present"
        except AttributeError:
            result["extended_acl"] = "unknown"
        except OSError as error:
            result["extended_acl"] = "absent" if error.errno == errno.ENODATA else "unknown"
    return result


def inspect_file(path, parent_cache):
    item = metadata(path)
    findings = []
    if item["type"] != "file" or any(parent.is_symlink() for parent in path.parents):
        item["status"] = "skipped"
        findings.append({"level": "UNKNOWN", "message": f"Environment file candidate {path}: special file or symlink path skipped; target/content not inspected."})
        return item, findings
    item["status"] = "inspected"
    mode = int(item["mode"], 8)
    reasons = []
    if mode & 0o004:
        reasons.append("world-readable")
    if mode & 0o002:
        reasons.append("world-writable")
    if mode & 0o020:
        reasons.append("group-writable")
    if mode & 0o040:
        reasons.append("group-readable; verify group membership is intended")
    if mode & 0o111:
        reasons.append("has executable permission bits")
    if mode & 0o7000:
        reasons.append("has special permission bits")
    if reasons:
        findings.append({"level": "REVIEW", "message": f"Environment file {path} ({item['mode']}): {'; '.join(reasons)}. Prefer 0600, or 0640 with an explicitly trusted service group."})
    if item["extended_acl"] == "present":
        findings.append({"level": "REVIEW", "message": f"Environment file {path} has an extended ACL. Inspect effective entries with getfacl; mode bits alone do not identify authorized users."})
    elif item["extended_acl"] == "unknown":
        findings.append({"level": "UNKNOWN", "message": f"Environment file {path}: extended ACL metadata could not be established."})
    item["parents"] = []
    for parent in path.parents:
        if parent not in parent_cache:
            try:
                parent_cache[parent] = metadata(parent)
            except OSError as error:
                parent_cache[parent] = {"path": str(parent), "unknown": str(error)}
        item["parents"].append(parent_cache[parent])
    return item, findings


def parse_environment_files(value):
    """Parse systemctl's path/ignore_errors pairs, rejecting ambiguous output."""
    if not value:
        return []
    matches = list(re.finditer(r"(.+?) \(ignore_errors=(yes|no)\)(?: |$)", value))
    if ''.join(match[0] for match in matches) != value:
        raise ValueError("Unrecognized EnvironmentFiles metadata")
    entries = []
    for match in matches:
        path = re.sub(r"\\x([0-9a-fA-F]{2})", lambda part: chr(int(part[1], 16)), match[1])
        if not path.startswith('/') or '\x00' in path:
            raise ValueError("EnvironmentFiles path is not an absolute file path")
        entries.append({"path": path, "optional": match[2] == "yes"})
    return entries


def application_sources(run, checks):
    sources, references = [], []
    services = checks.get("running_services", {})
    units = [line.split()[0] for line in services.get("output", "").splitlines() if line.split() and line.split()[0].endswith('.service')]
    partial = services.get("status") != "ok" or len(units) > 100
    for unit in units[:100]:
        evidence = run(["systemctl", "show", "--no-pager", "--property=EnvironmentFiles", "--property=MainPID", "--", unit])
        source = {"kind": "systemd", "name": unit, "status": evidence["status"], "files": []}
        if evidence["status"] == "ok":
            properties = dict(line.split('=', 1) for line in evidence.get("output", "").splitlines() if '=' in line)
            source["main_pid"] = properties.get("MainPID", "unknown")
            try:
                source["files"] = parse_environment_files(properties.get("EnvironmentFiles", ""))
                references.extend({**entry, "application": "systemd:" + unit} for entry in source["files"])
            except ValueError as error:
                source.update(status="unknown", detail=str(error))
                partial = True
        else:
            source["detail"] = evidence.get("detail", "EnvironmentFiles unavailable")
            partial = True
        sources.append(source)
    for container in checks.get("docker", {}).get("containers", []):
        source = {"kind": "docker", "name": container.get("name", container.get("id", "unknown")),
                  "status": container.get("inspection_status", "unknown"),
                  "configured_variable_count": container.get("environment_variable_count"), "files": []}
        for mount in container.get("mounts") or []:
            path = mount.get("source", "")
            if mount.get("type") == "bind" and path.startswith('/') and (is_env_name(Path(path).name) or is_env_name(Path(mount.get("destination", "")).name)):
                reference = {"path": path, "optional": False, "application": "docker:" + str(source["name"])}
                references.append(reference)
                source["files"].append({"path": path, "container_path": mount.get("destination"), "writable": mount.get("writable")})
        sources.append(source)
    return {"status": "partial" if partial else "ok", "sources": sources,
            "systemd_units_limit": 100, "systemd_units_observed": len(units),
            "docker_status": checks.get("docker", {}).get("status", "unavailable")}, references


def collect(roots=None, run=None, checks=None):
    explicit = roots is not None
    roots = list(roots if explicit else DEFAULT_ROOTS)
    result = {"status": "ok", "roots": [], "files": [], "skipped": [], "entries_examined": 0,
              "limits": {"entries": MAX_ENTRIES, "files": MAX_FILES, "depth": MAX_DEPTH, "seconds": SCAN_SECONDS},
              "excluded_directory_names": sorted(EXCLUDED_DIRS),
              "limitations": [
                  "Metadata only: no file contents, environment names/values, hashes or access-time based usage claims are collected.",
                  "Candidate names are .env, .env.* and *.env, including templates/backups. Names do not establish that a file contains secrets.",
                  "Traversal skips symlinks, excluded directories and different filesystems below each root. Bounds and errors can leave undiscovered candidates.",
                  "ACL presence is checked, not effective ACL entries, SELinux/AppArmor policy, directory group membership or application access. Ownership is recorded, not judged without an expected service identity.",
                  "Parent write bits are reviewed; sticky-directory restrictions are noted. Metadata is a point-in-time observation, not proof of web exposure or effective access.",
                  "Application evidence covers running systemd services (up to 100) and inspected Docker containers. Configured sources/counts do not prove what a running process loaded; /proc/*/environ is never read.",
                  "Docker does not retain original --env-file/Compose env_file source paths. Counts include image defaults and configured overrides, not variable names/values. Env-like bind mounts are candidates, not proof of loading.",
                  "Inline systemd Environment values, app-specific config loaders, shell-sourced files, Compose YAML, PM2 and Supervisor configuration are not read. Explicit scan roots replace discovery roots, not application references.",
              ]}
    findings, parents, visited = [], {}, set()
    if run is not None:
        result["applications"], references = application_sources(run, checks or {})
        if result["applications"]["status"] == "partial":
            result["status"] = "partial"
        for reference in references:
            path = Path(reference["path"])
            existing = next((item for item in result["files"] if item["path"] == str(path)), None)
            if existing is not None:
                existing["applications"].append(reference["application"])
                continue
            if len(result["files"]) >= MAX_FILES:
                result["status"] = "partial"
                result["skipped"].append({"path": str(path), "reason": "Referenced file limit reached"})
                break
            try:
                item, reviews = inspect_file(path, parents)
                item["applications"] = [reference["application"]]
                result["files"].append(item)
                findings.extend(reviews)
            except OSError as error:
                optional_absent = isinstance(error, FileNotFoundError) and reference["optional"]
                result["skipped"].append({"path": str(path), "reason": "Optional application file absent" if optional_absent else str(error), "application": reference["application"]})
                if not optional_absent:
                    result["status"] = "partial"
    started = time.monotonic()
    stopped = False
    def skip(path, reason, incomplete=False):
        result["skipped"].append({"path": str(path), "reason": reason})
        if incomplete:
            result["status"] = "partial"
    for raw in roots:
        path = Path(os.path.abspath(os.path.expanduser(raw)))
        scope = {"path": str(path), "status": "pending"}
        result["roots"].append(scope)
        if stopped:
            scope["status"] = "not_scanned"
            continue
        try:
            if any(part.is_symlink() for part in (path, *path.parents)):
                raise ValueError("Symlink root/ancestor not followed")
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("Scan root must be a directory")
        except FileNotFoundError:
            scope["status"] = "absent"
            if explicit:
                skip(path, "Requested root does not exist", True)
            continue
        except (OSError, ValueError) as error:
            scope["status"] = "skipped"
            skip(path, str(error), True)
            continue
        scope["status"] = "scanned"
        stack = [(path, 0)]
        while stack and not stopped:
            directory, depth = stack.pop()
            if directory in visited:
                continue
            visited.add(directory)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if result["entries_examined"] >= MAX_ENTRIES or len(result["files"]) >= MAX_FILES or time.monotonic() - started >= SCAN_SECONDS:
                            skip(directory, "Scan budget reached; remaining paths not inspected", True)
                            stopped = True
                            scope["status"] = "partial"
                            break
                        result["entries_examined"] += 1
                        candidate = Path(entry.path)
                        try:
                            if is_env_name(entry.name) and not entry.is_dir(follow_symlinks=False):
                                if not any(item["path"] == str(candidate) for item in result["files"]):
                                    item, reviews = inspect_file(candidate, parents)
                                    result["files"].append(item)
                                    findings.extend(reviews)
                            if entry.is_symlink():
                                skip(candidate, "Symlink not followed")
                            elif entry.is_dir(follow_symlinks=False):
                                if entry.name in EXCLUDED_DIRS:
                                    skip(candidate, "Excluded directory name")
                                elif entry.stat(follow_symlinks=False).st_dev != info.st_dev:
                                    skip(candidate, "Different filesystem")
                                elif depth >= MAX_DEPTH:
                                    skip(candidate, "Depth limit reached", True)
                                else:
                                    stack.append((candidate, depth + 1))
                        except OSError as error:
                            skip(candidate, str(error), True)
            except OSError as error:
                skip(directory, str(error), True)
                scope["status"] = "partial"
    for parent in parents.values():
        if "unknown" in parent:
            findings.append({"level": "UNKNOWN", "message": f"Environment file ancestor {parent['path']}: metadata unavailable."})
        elif int(parent["mode"], 8) & 0o022 and not parent["sticky"]:
            findings.append({"level": "REVIEW", "message": f"Environment file ancestor {parent['path']} ({parent['mode']}) is group/world-writable; files or path components may be replaceable."})
        if parent.get("extended_acl") == "present":
            findings.append({"level": "REVIEW", "message": f"Environment file ancestor {parent['path']} has an extended ACL; review effective directory access."})
        elif parent.get("extended_acl") == "unknown":
            findings.append({"level": "UNKNOWN", "message": f"Environment file ancestor {parent['path']}: extended ACL metadata unavailable."})
    if result["status"] == "partial":
        findings.append({"level": "UNKNOWN", "message": "Environment-file discovery incomplete. Review roots, scan limits and skipped paths; undiscovered files may remain."})
    result["files"].sort(key=lambda item: item["path"])
    return result, findings
