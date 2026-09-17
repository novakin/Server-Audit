"""Read-only cron and system timer review. Never execute or export commands."""

import os
import re
import shlex
import stat
from pathlib import Path


MAX_FILES = 500
MAX_BYTES = 256 * 1024
MAX_TIMERS = 100
CRON_FILE = Path('/etc/crontab')
CRON_DIRECTORIES = (('/etc/cron.d', 'system'), ('/var/spool/cron/crontabs', 'user'),
                    ('/etc/cron.hourly', 'periodic'), ('/etc/cron.daily', 'periodic'),
                    ('/etc/cron.weekly', 'periodic'), ('/etc/cron.monthly', 'periodic'))
PATTERNS = (
    ("download-to-interpreter", r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[0-9.]*)\b"),
    ("network-download", r"\b(?:curl|wget)\b"),
    ("encoded-payload-decoding", r"\bbase64\b[^\n;|]*(?:--decode|-[A-Za-z]*d)\b|\bxxd\s+-r\b|\bopenssl\s+enc\b[^\n;|]*\s-d\b"),
    ("dynamic-evaluation", r"\beval\b"),
    ("inline-interpreter-code", r"\b(?:bash|sh|zsh|python[0-9.]*|perl|ruby|node)\s+-[A-Za-z]*[ce]\b"),
    ("temporary-path-reference", r"/(?:tmp|var/tmp|dev/shm)/"),
    ("long-encoded-looking-token", r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{160,}={0,2}(?![A-Za-z0-9+/])"),
)


def suspicious_patterns(text):
    return [name for name, pattern in PATTERNS if re.search(pattern, text)]


def read_definition(path, script=False):
    """Bound reads; reject links/special files before reading any bytes."""
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Symlink path skipped')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Not a regular file')
        data = source.read(min(512, MAX_BYTES + 1))
        binary = script and (data.startswith(b'\x7fELF') or b'\x00' in data)
        if not binary:
            data += source.read(max(0, MAX_BYTES + 1 - len(data)))
    if len(data) > MAX_BYTES:
        raise ValueError('Definition exceeds inspection size limit')
    metadata = {'path': str(path), 'mode': format(stat.S_IMODE(info.st_mode), '04o'), 'uid': info.st_uid, 'gid': info.st_gid}
    metadata['content_status'] = 'binary_metadata_only' if binary else 'text_inspected'
    return '' if binary else data.decode('utf-8', errors='replace'), metadata


def parse_crontab(text, system, owner):
    jobs, issues = [], []
    assignments = 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            assignments += 1
            continue
        schedule_fields = 1 if line.startswith('@') else 5
        pieces = line.split(None, schedule_fields + int(system))
        if len(pieces) != schedule_fields + int(system) + 1:
            issues.append({'line': number, 'reason': 'Unrecognized cron entry; raw text withheld'})
            continue
        schedule = pieces[:schedule_fields]
        if schedule_fields == 1:
            valid = schedule[0] in {'@reboot', '@yearly', '@annually', '@monthly', '@weekly', '@daily', '@midnight', '@hourly'}
        else:
            normalized = list(schedule)
            normalized[3] = re.sub(r'(?i)\b(?:JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)\b', '1', normalized[3])
            normalized[4] = re.sub(r'(?i)\b(?:SUN|MON|TUE|WED|THU|FRI|SAT)\b', '1', normalized[4])
            valid = all(re.fullmatch(r'[0-9*/,-]+', part) for part in normalized)
        user = pieces[schedule_fields] if system else owner
        if not valid or not re.fullmatch(r'[A-Za-z0-9_.-]+\$?', user):
            issues.append({'line': number, 'reason': 'Unsupported schedule/user syntax; raw text withheld'})
            continue
        jobs.append({'line': number, 'schedule': ' '.join(schedule), 'user': user,
                     'patterns': suspicious_patterns(pieces[-1]), 'referenced_scripts': script_paths(pieces[-1])})
    return jobs, assignments, issues


def script_paths(command):
    """Only literal absolute script paths; no expansion, resolution or execution."""
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    paths = []
    interpreters = {'sh', 'bash', 'dash', 'zsh', 'python', 'python3', 'perl', 'ruby', 'node'}
    for index, token in enumerate(tokens[:2]):
        if not token.startswith('/') or any(character in token for character in '$`\n\r'):
            continue
        # Only the executable or an immediate interpreter script argument.
        if index == 0 or (index == 1 and Path(tokens[0]).name in interpreters):
            paths.append(token)
    return list(dict.fromkeys(paths))[:4]


def timer_script_paths(value):
    """Accept only unescaped systemctl records; path= owns executable identity."""
    records = re.findall(r'\{ path=(.*?) ; argv\[\]=(.*?) ; (?:ignore_errors|flags|start_time)=', value)
    complete = bool(records) and len(records) == value.count('{ path=')
    targets = []
    for executable, arguments in records:
        if '\\' in executable or '\\' in arguments or not executable.startswith('/') or any(c in executable for c in '$`\n\r'):
            complete = False
            continue
        try:
            tokens = shlex.split(arguments)
        except ValueError:
            complete = False
            continue
        if not tokens:
            complete = False
            continue
        # systemd's @ prefix can replace argv[0] with an arbitrary name.
        tokens[0] = executable
        targets.extend(script_paths(shlex.join(tokens)))
    return list(dict.fromkeys(targets)), complete


def permission_findings(metadata, expected_uid=0, check_mode=True):
    findings = []
    if check_mode and int(metadata['mode'], 8) & 0o022:
        findings.append({'level': 'REVIEW', 'message': f"Scheduled definition {metadata['path']} ({metadata['mode']}) is group/world-writable."})
    if metadata['uid'] not in (0, expected_uid):
        findings.append({'level': 'REVIEW', 'message': f"Scheduled definition {metadata['path']} has unexpected owner UID {metadata['uid']} for run-as UID {expected_uid} (root ownership also accepted)."})
    return findings


def collect(run):
    result = {'status': 'ok', 'cron_files': [], 'timers': [], 'referenced_files': [], 'issues': [],
              'limits': {'files': MAX_FILES, 'bytes_per_file': MAX_BYTES, 'timers': MAX_TIMERS},
              'limitations': [
                  'Patterns are review signals, not malware verdicts. Legitimate maintenance can use encoding, downloads or inline shell code; malicious commands can look ordinary.',
                  'Raw commands, script contents, environment assignments, URLs and matched strings are withheld. Definitions are read locally but never executed, decoded or sourced.',
                  'Cron scope: /etc/crontab, /etc/cron.d, /etc/cron.hourly/daily/weekly/monthly and /var/spool/cron/crontabs. Presence does not establish enablement or execution.',
                  'Timer scope: up to 100 loaded system-manager timer units, including inactive ones. User-manager timers and unloaded/disabled unit files are not fully inventoried.',
                  'Literal absolute script references are inspected without following links. Dynamic/relative paths, include chains, shell expansion and arbitrary command arguments are not resolved.',
                  'Ownership/mode and immediate parent write bits are checked, not effective ACL/SELinux rights. Large/special/symlink files and exceeded limits leave unknown coverage.',
              ]}
    findings, files_seen, parents_seen = [], {}, set()
    ownership_seen, scripts_seen = set(), set()

    def issue(path, reason):
        result['status'] = 'partial'
        result['issues'].append({'path': str(path), 'reason': reason})

    def inspect(path, expected_uid=0, script=False):
        path = Path(path)
        key = str(path)
        if key in files_seen:
            inspected = files_seen[key]
            if inspected and (key, expected_uid) not in ownership_seen:
                ownership_seen.add((key, expected_uid))
                findings.extend(permission_findings(inspected[1], expected_uid, check_mode=False))
            return inspected
        if len(files_seen) >= MAX_FILES:
            issue(path, 'File inspection limit reached')
            return None
        files_seen[key] = None
        try:
            content, metadata = read_definition(path, script)
            findings.extend(permission_findings(metadata, expected_uid))
            ownership_seen.add((key, expected_uid))
            parent = path.parent
            if parent not in parents_seen:
                parents_seen.add(parent)
                info = parent.lstat()
                if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
                    findings.append({'level': 'REVIEW', 'message': f'Scheduled definition directory {parent} is group/world-writable; entries may be replaceable.'})
            files_seen[key] = content, metadata
            return files_seen[key]
        except (OSError, ValueError):
            issue(path, 'Definition unreadable, oversized, symlinked or not a regular file; content withheld')
            return None

    def patterns_at(path, line, patterns):
        if patterns:
            findings.append({'level': 'REVIEW', 'message': f"Scheduled task {path}" + (f':{line}' if line else '') + ': suspicious patterns [' + ', '.join(patterns) + ']. Review locally; this is not a malware verdict.'})

    def inspect_script(path, expected_uid=0):
        inspected = inspect(path, expected_uid, script=True)
        if inspected and str(path) not in scripts_seen:
            scripts_seen.add(str(path))
            content, metadata = inspected
            metadata['patterns'] = suspicious_patterns(content)
            result['referenced_files'].append(metadata)
            patterns_at(path, None, metadata['patterns'])

    definitions = [(CRON_FILE, 'system', 'root')]
    for location, kind in CRON_DIRECTORIES:
        directory = Path(location)
        try:
            if directory.is_symlink():
                raise ValueError('Symlink directory')
            for path in directory.iterdir():
                if len(definitions) >= MAX_FILES:
                    issue(directory, 'Cron discovery limit reached')
                    break
                if path.is_dir() and not path.is_symlink():
                    continue
                definitions.append((path, kind, path.name if kind == 'user' else 'root'))
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            issue(directory, 'Cron directory could not be enumerated')
    for path, kind, owner in definitions:
        if path == CRON_FILE and not path.exists():
            continue
        expected_uid = 0
        if kind == 'user':
            try:
                import pwd
                expected_uid = pwd.getpwnam(owner).pw_uid
            except (ImportError, KeyError):
                issue(path, 'Crontab owner could not be resolved')
        inspected = inspect(path, expected_uid, script=kind == 'periodic')
        if inspected is None:
            continue
        content, metadata = inspected
        metadata.update(kind=kind, owner=owner)
        if kind == 'periodic':
            metadata['patterns'] = suspicious_patterns(content)
            patterns_at(path, None, metadata['patterns'])
        else:
            metadata['jobs'], metadata['environment_assignment_count'], metadata['parse_issues'] = parse_crontab(content, kind == 'system', owner)
            if metadata['parse_issues']:
                issue(path, 'Some cron lines could not be parsed')
            for job in metadata['jobs']:
                patterns_at(path, job['line'], job['patterns'])
                for target in job['referenced_scripts']:
                    try:
                        import pwd
                        run_uid = pwd.getpwnam(job['user']).pw_uid
                    except (ImportError, KeyError):
                        issue(path, 'Referenced script run-as identity could not be resolved')
                        run_uid = expected_uid
                    inspect_script(target, run_uid)
        result['cron_files'].append(metadata)

    listing = run(['systemctl', 'list-units', '--all', '--type=timer', '--no-legend', '--plain', '--no-pager'])
    result['timer_collection_status'] = listing['status']
    if listing['status'] != 'ok':
        issue('systemd timers', 'Timer listing unavailable')
    else:
        units = [line.split()[0] for line in listing.get('output', '').splitlines() if line.split() and line.split()[0].endswith('.timer')]
        if len(units) > MAX_TIMERS:
            issue('systemd timers', 'Timer limit reached')
        for unit in units[:MAX_TIMERS]:
            timer = {'unit': unit, 'status': 'ok'}
            evidence = run(['systemctl', 'show', '--no-pager', '--property=Unit', '--property=ActiveState', '--property=LastTriggerUSec', '--property=NextElapseUSecRealtime', '--property=FragmentPath', '--property=DropInPaths', '--', unit])
            if evidence['status'] != 'ok':
                timer['status'] = 'unknown'
                issue(unit, 'Timer metadata unavailable')
            else:
                properties = dict(line.split('=', 1) for line in evidence.get('output', '').splitlines() if '=' in line)
                timer.update(active_state=properties.get('ActiveState'), last_trigger=properties.get('LastTriggerUSec'), next_trigger=properties.get('NextElapseUSecRealtime'), service=properties.get('Unit'))
                for fragment in [properties.get('FragmentPath', ''), *properties.get('DropInPaths', '').split()]:
                    if fragment.startswith('/'):
                        inspect_script(re.sub(r'\\x([0-9a-fA-F]{2})', lambda match: chr(int(match[1], 16)), fragment))
                service = properties.get('Unit', '')
                if service:
                    command = run(['systemctl', 'show', '--no-pager', '--property=ExecStart', '--property=User', '--property=FragmentPath', '--property=DropInPaths', '--', service])
                    if command['status'] != 'ok':
                        timer['status'] = 'unknown'
                        issue(service, 'Timer service metadata unavailable')
                    else:
                        values = dict(line.split('=', 1) for line in command.get('output', '').splitlines() if '=' in line)
                        timer['user'] = values.get('User') or 'root'
                        timer['patterns'] = suspicious_patterns(values.get('ExecStart', ''))
                        patterns_at(unit, None, timer['patterns'])
                        try:
                            import pwd
                            run_uid = int(timer['user']) if timer['user'].isdigit() else pwd.getpwnam(timer['user']).pw_uid
                        except (ImportError, KeyError):
                            run_uid = 0
                            issue(service, 'Timer service run-as identity could not be resolved')
                        targets, complete = timer_script_paths(values.get('ExecStart', ''))
                        timer['referenced_scripts'] = targets
                        if not complete:
                            timer['status'] = 'unknown'
                            issue(service, 'Timer executable reference syntax unsupported; target coverage incomplete')
                        for target in targets:
                            inspect_script(target, run_uid)
                        for fragment in [values.get('FragmentPath', ''), *values.get('DropInPaths', '').split()]:
                            if fragment.startswith('/'):
                                inspect_script(re.sub(r'\\x([0-9a-fA-F]{2})', lambda match: chr(int(match[1], 16)), fragment))
            result['timers'].append(timer)
    if result['status'] == 'partial':
        findings.append({'level': 'UNKNOWN', 'message': 'Scheduled-task coverage incomplete. Review issues and scope in scheduled task evidence.'})
    return result, findings
