"""Built-in, metadata-only findings from explicitly selected local Git storage."""

import math
import os
from pathlib import Path
import re
import shutil
import stat
import time

from git_reader import (GitProcess, GitReadError, GitReadLimit, command, environment,
                        object_format, read_local_file, remaining, repository_view)


SCAN_SECONDS = 60
MAX_OBJECTS = 10000
MAX_OBJECT_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_DETECTIONS = 500
MAX_STORAGE_ENTRIES = 50000

# These are candidate detectors, not credential validation or a complete secret taxonomy.
RULES = (
    ('private-key', re.compile(rb'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----|-----BEGIN PGP PRIVATE KEY BLOCK-----')),
    ('github-token', re.compile(rb'(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,255})(?![A-Za-z0-9_])')),
    ('gitlab-token', re.compile(rb'(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_-]{20,255}(?![A-Za-z0-9_-])')),
    ('aws-access-key-id', re.compile(rb'(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])')),
    ('slack-token', re.compile(rb'(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{10,255}(?![A-Za-z0-9-])')),
    ('credential-in-url', re.compile(rb'(?i)[a-z][a-z0-9+.-]{1,20}://[^/\s:@]{1,128}:[^/\s@]{1,256}@')),
    ('authorization-header', re.compile(rb'(?i)\b(?:authorization|proxy-authorization)[ \t]{0,8}[:=][ \t]{0,8}(?:basic|bearer)[ \t]+[A-Za-z0-9._~+/=-]{8,512}')),
    ('credential-assignment', re.compile(
        rb'''(?im)(?<![\w])['"]?(?:[a-z0-9]+[_-]){0,3}(?:password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?(?:access[_-]?)?key|access[_-]?key|token|secret)['"]?\s{0,8}[:=][ \t]{0,8}(?:"([^"\r\n]{8,256})"|'([^'\r\n]{8,256})'|([a-z0-9+/_.~!@%&*:-]{12,256}))''')),
)
PLACEHOLDERS = {b'password', b'changeme', b'replace_me', b'your_password', b'your_api_key',
                b'your_token', b'example_password', b'example_token', b'placeholder'}
LIMITATIONS = [
    'Built-in candidate rules only; no credential validation, complete secret coverage or Gitleaks-equivalence claim. Rule IDs and ruleset version describe the detector.',
    'Only explicit local Git directories are inspected: config/config.worktree and stored blob, commit and tag objects, including unreachable objects still present. Current working files are not scanned.',
    'Git is a local storage reader only. No clone, fetch, remote search, hooks, filters or repository-configured commands are run. Included config, alternates, linked-worktree indirection and symlink/special-file storage are not followed.',
    'Object IDs identify stored content, not an original filename or every containing commit. Paths are not reconstructed. Pruned/missing objects, LFS payloads and submodule repositories require separate coverage.',
    'Time, object, byte, detection and storage-entry limits may leave incomplete coverage. Filesystem stalls and bounded reader shutdown can extend wall time beyond the scan budget.',
    'Only the named config files and stored object types are content-inspected; reflogs, index files, hooks and other administrative files are outside this check. Concurrent repository mutation is not an atomic snapshot.',
    'Raw bytes are inspected without executing content or decoding archives/embedded encodings. Secret values, matching lines, commit messages and author data are never exported.',
]


def scan_seconds_value(value):
    if isinstance(value, bool):
        raise ValueError('Git scan seconds must be numeric, not boolean.')
    seconds = float(value)
    if not math.isfinite(seconds) or not 0 < seconds <= 3600:
        raise ValueError('Git scan seconds must be greater than zero and at most 3600.')
    return seconds


def detections(data, location, kind, identifier, deadline):
    """Yield only fixed rule IDs and locations; never return matched text."""
    seen = set()
    for rule, pattern in RULES:
        remaining(deadline)
        for match in pattern.finditer(data):
            remaining(deadline)
            if rule == 'credential-assignment':
                value = next(group for group in match.groups() if group is not None).strip()
                if value.lower() in PLACEHOLDERS or value.startswith((b'$', b'${', b'{{', b'<', b'%(', b'os.environ', b'os.getenv', b'process.env.')):
                    continue
            line = data.count(b'\n', 0, match.start()) + 1
            if (rule, line) in seen:
                continue
            seen.add((rule, line))
            yield {'rule': rule, 'file': location, 'start_line': line, 'end_line': line,
                   'commit': identifier if kind == 'commit' else '',
                   'object_id': identifier, 'object_type': kind, 'byte_offset': match.start()}


def add_issue(repository, message):
    repository['status'] = 'partial'
    if message not in repository['issues']:
        repository['issues'].append(message)


def add_detections(repository, scan, data, location, kind, identifier, deadline):
    for detection in detections(data, location, kind, identifier, deadline):
        if repository['detections_found'] >= MAX_DETECTIONS:
            raise GitReadLimit('Repository detection limit reached.')
        scan['detections'].append(detection)
        repository['detections_found'] += 1


def git_directory(raw):
    root = Path(os.path.abspath(os.path.expanduser(raw)))
    for part in (root, *root.parents):
        if part.is_symlink():
            raise GitReadError('Symlink repository paths are not followed.')
    if (root / '.git').is_file():
        raise GitReadError('Git-file indirection is not followed; select the actual Git directory explicitly.')
    directory = root / '.git' if (root / '.git').is_dir() else root
    for path in (directory, directory / 'objects'):
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise GitReadError('Expected a local Git directory with an objects directory.')
    if not stat.S_ISREG((directory / 'HEAD').lstat().st_mode):
        raise GitReadError('Expected a regular Git HEAD file.')
    if (directory / 'commondir').exists() or (directory / 'commondir').is_symlink():
        raise GitReadError('Shared worktree storage is not followed; select the common Git directory explicitly.')
    return root, directory


def inspect_storage(directory, repository, deadline):
    objects = directory / 'objects'
    device = objects.stat().st_dev
    stack = [(objects, 0)]
    examined = 0
    while stack:
        remaining(deadline)
        current, depth = stack.pop()
        with os.scandir(current) as entries:
            for entry in entries:
                remaining(deadline)
                examined += 1
                if examined > MAX_STORAGE_ENTRIES:
                    raise GitReadLimit('Object-store entry limit reached before safe enumeration.')
                info = entry.stat(follow_symlinks=False)
                if info.st_dev != device:
                    raise GitReadError('Object storage crosses a filesystem boundary; scope unconfirmed.')
                if stat.S_ISDIR(info.st_mode):
                    if depth >= 4:
                        raise GitReadError('Unsupported object-store directory nesting.')
                    stack.append((Path(entry.path), depth + 1))
                elif not stat.S_ISREG(info.st_mode):
                    raise GitReadError('Symlink or special-file object storage is not followed.')
                if current == objects / 'info' and entry.name in ('alternates', 'http-alternates'):
                    raise GitReadError('Alternate object stores are not followed; select each standalone repository separately.')
                if entry.name.endswith('.promisor'):
                    add_issue(repository, 'Partial-clone storage observed; only objects already present are inspected.')
    repository['storage_entries_examined'] = examined


def object_header(line, expected_length):
    if line is None:
        raise GitReadError('Missing Git object header.')
    fields = line.split(b' ')
    if (len(fields) != 3 or not re.fullmatch(rb'[0-9a-f]{' + str(expected_length).encode('ascii') + rb'}', fields[0])
            or fields[1] not in (b'blob', b'commit', b'tag', b'tree') or not fields[2].isdigit()):
        raise GitReadError('Invalid Git object metadata; raw output withheld.')
    return fields[0].decode('ascii'), fields[1].decode('ascii'), int(fields[2])


def scan_objects(executable, view, directory, repository, deadline, algorithm):
    scan = {'mode': 'local_objects', 'status': 'ok', 'detections': [],
            'objects_seen': 0, 'objects_scanned': 0, 'oversized_objects': 0, 'bytes_read': 0}
    repository['scans'].append(scan)
    env = environment(view, directory / 'objects')
    enumeration = command(executable, view, 'cat-file', '--batch-all-objects', '--unordered', '--batch-check')
    contents = command(executable, view, 'cat-file', '--batch')
    length = 64 if algorithm == 'sha256' else 40
    try:
        with GitProcess(enumeration, env, view, deadline) as inventory:
            with GitProcess(contents, env, view, deadline) as reader:
                while True:
                    header = inventory.line()
                    if header is None:
                        break
                    identifier, kind, size = object_header(header, length)
                    if scan['objects_seen'] >= MAX_OBJECTS:
                        raise GitReadLimit('Repository object-count limit reached.')
                    scan['objects_seen'] += 1
                    if kind == 'tree':
                        continue
                    if size > MAX_OBJECT_BYTES:
                        scan['oversized_objects'] += 1
                        scan['status'] = 'partial'
                        add_issue(repository, 'Objects above the per-object byte limit were not inspected.')
                        continue
                    if scan['bytes_read'] + size > MAX_TOTAL_BYTES:
                        raise GitReadLimit('Repository content-byte limit reached.')
                    reader.write(identifier.encode('ascii') + b'\n')
                    actual = object_header(reader.line(), length)
                    if actual != (identifier, kind, size):
                        raise GitReadError('Git object metadata changed or is inconsistent.')
                    data = reader.exact(size)
                    if reader.exact(1) != b'\n':
                        raise GitReadError('Invalid Git object framing.')
                    scan['bytes_read'] += size
                    add_detections(repository, scan, data, 'git-object:' + identifier, kind, identifier, deadline)
                    scan['objects_scanned'] += 1
                inventory.finish()
                reader.finish()
    except (OSError, GitReadError):
        scan['status'] = 'partial'
        raise


def scan_repository(raw, executable, seconds):
    started = time.monotonic()
    deadline = started + seconds
    repository = {'path': str(raw), 'status': 'ok', 'scans': [], 'issues': [], 'detections_found': 0}
    try:
        remaining(deadline)
        root, directory = git_directory(raw)
        repository.update(path=str(root), git_directory=str(directory))
        config_scan = {'mode': 'git_configuration', 'status': 'ok', 'detections': [], 'files_scanned': []}
        repository['scans'].append(config_scan)
        config_present = False
        for name in ('config', 'config.worktree'):
            remaining(deadline)
            try:
                data = read_local_file(directory / name, MAX_CONFIG_BYTES)
            except FileNotFoundError:
                continue
            if name == 'config':
                config_present = True
            config_scan['files_scanned'].append(name)
            add_detections(repository, config_scan, data, name, 'configuration', None, deadline)
            if re.search(rb'(?im)^\s*\[include(?:if)?\b', data):
                add_issue(repository, 'Included configuration is not followed; only local config files are inspected.')
        inspect_storage(directory, repository, deadline)
        if (directory / 'shallow').exists():
            add_issue(repository, 'Shallow repository observed; earlier missing history cannot be inspected.')
        with repository_view() as view:
            algorithm, partial_clone = ('sha1', False)
            if config_present:
                algorithm, partial_clone = object_format(executable, view, directory / 'config', deadline)
            repository['object_format'] = algorithm
            if partial_clone:
                add_issue(repository, 'Partial-clone storage observed; only objects already present are inspected.')
            scan_objects(executable, view, directory, repository, deadline, algorithm)
    except GitReadError as error:
        add_issue(repository, str(error))
    except (OSError, ValueError):
        add_issue(repository, 'Local Git data could not be read; raw error withheld.')
    if repository['status'] != 'ok':
        if not repository['scans']:
            repository['status'] = 'error'
        for scan in repository['scans']:
            # Scope failures must not leave the configuration-only view looking complete.
            if scan['mode'] == 'git_configuration' and not any(item['mode'] == 'local_objects' for item in repository['scans']):
                scan['status'] = 'partial'
    repository['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return repository


def collect(roots=None, scan_seconds=SCAN_SECONDS):
    seconds = scan_seconds_value(scan_seconds)
    result = {'status': 'not_requested', 'repositories': [], 'detector': 'builtin', 'ruleset_version': 1,
              'rule_ids': [rule for rule, _ in RULES], 'limitations': list(LIMITATIONS),
              'limits': {'seconds_per_repository': seconds, 'objects': MAX_OBJECTS,
                         'bytes_per_object': MAX_OBJECT_BYTES, 'content_bytes_per_repository': MAX_TOTAL_BYTES,
                         'bytes_per_config_file': MAX_CONFIG_BYTES, 'detections_per_repository': MAX_DETECTIONS,
                         'storage_entries': MAX_STORAGE_ENTRIES}}
    if not roots:
        return result, []
    executable = shutil.which('git')
    if executable is None or os.name != 'posix':
        result.update(status='unavailable', requested_roots=list(roots),
                      detail='Local Git and POSIX pipe support are required for requested repository inspection. No installation performed.')
        return result, []
    result['status'] = 'ok'
    findings = []
    seen = set()
    for raw in roots:
        try:
            identity = str(git_directory(raw)[1])
        except (OSError, ValueError, GitReadError):
            identity = str(raw)
        if identity in seen:
            continue
        seen.add(identity)
        repository = scan_repository(raw, executable, seconds)
        result['repositories'].append(repository)
        if repository['status'] != 'ok':
            result['status'] = 'partial'
            findings.append({'level': 'UNKNOWN', 'message': f"Git {repository['path']}: incomplete local secret inspection. See repository issues and limits."})
        for scan in repository['scans']:
            for detection in scan['detections']:
                findings.append({'level': 'REVIEW', 'message':
                    f"Git {repository['path']}: possible secret ({detection['rule']}) in {detection['file']}:{detection['start_line']} [{scan['mode']}]. Verify locally; if genuine, revoke/rotate it and investigate exposure."})
    return result, findings
