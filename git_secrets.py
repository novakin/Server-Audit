"""Optional local Git secret scans with redacted, allowlisted evidence."""

import json
import os
import shutil
import signal
import subprocess
import tempfile
from pathlib import Path


class ScannerShutdownError(RuntimeError):
    """Scanner termination is unconfirmed; abort and retain private scratch."""


class ScannerShutdownInterrupted(KeyboardInterrupt):
    """Cancellation with unconfirmed scanner termination; retain scratch."""


def _stop_scanner(process):
    """Stop the private process group and reap the scanner before scratch cleanup."""
    try:
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass  # The scanner/group may have exited before the signal.
        process.wait()
    except OSError:
        raise ScannerShutdownError(
            f"Cannot confirm shutdown of scanner PID {process.pid}; audit aborted."
        ) from None
    except KeyboardInterrupt:
        raise ScannerShutdownInterrupted(
            f"Shutdown of scanner PID {process.pid} was interrupted; termination is unconfirmed."
        ) from None


def execute(command):
    """Discard scanner logs: they must never enter the audit report."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith(('GITLEAKS_', 'GIT_'))}
    environment.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    try:
        process = subprocess.Popen(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=environment, start_new_session=os.name == 'posix',
        )
    except OSError:
        return None

    # Manage the wait explicitly: Popen.__exit__ can wait indefinitely after a
    # failed stop, or replace the original interruption with a reaping error.
    try:
        process.wait(timeout=120)
    except KeyboardInterrupt:
        try:
            _stop_scanner(process)
        except (OSError, ScannerShutdownError):
            raise ScannerShutdownInterrupted(
                f"Cannot confirm shutdown of scanner PID {process.pid}; audit interrupted."
            ) from None
        raise
    except (subprocess.TimeoutExpired, OSError):
        _stop_scanner(process)
        return None
    return process.returncode


def scan_mode(executable, root, mode, scratch):
    report_path = scratch / (mode + '.json')
    command = [executable, mode, str(root), '--no-banner', '--no-color', '--redact=100',
               '--report-format=json', '--report-path', str(report_path), '--exit-code=10',
               '--timeout=110', '--log-level=error', '--ignore-gitleaks-allow',
               '--config', str(scratch / 'config.toml'), '--gitleaks-ignore-path', str(scratch / '.gitleaksignore')]
    if mode == 'git':
        command.append('--log-opts=--all --full-history --no-ext-diff --no-textconv')
    exit_code = execute(command)
    result = {"mode": "history" if mode == 'git' else "working_directory", "status": "ok", "detections": []}
    if exit_code not in (0, 10):
        result.update(status="error", detail="Scanner failed or timed out; raw logs withheld to avoid exposing secrets.", exit_code=exit_code)
        return result
    try:
        records = json.loads(report_path.read_text(encoding='utf-8'))
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise ValueError('Invalid scanner report')
        for record in records:
            # Never retain Secret, Match, Line, Message, Author, Email or arbitrary fields.
            result['detections'].append({
                'rule': str(record.get('RuleID', 'unknown')),
                'file': str(record.get('File', 'unknown')),
                'start_line': record.get('StartLine'),
                'end_line': record.get('EndLine'),
                'commit': str(record.get('Commit', '')),
            })
        if (exit_code == 10) != bool(records):
            raise ValueError('Scanner status/report mismatch')
    except (OSError, ValueError):
        result.update(status="error", detail="Missing, invalid or inconsistent scanner report; scan result unknown.")
    return result


def collect(roots=None):
    result = {"status": "not_requested", "repositories": [], "limitations": [
        "Only explicitly selected local repositories are scanned. No remote clone, fetch, GitHub search or credential validation is performed.",
        "Gitleaks reads repository content. History covers locally available reachable refs; shallow clones, deleted/unreachable objects, LFS content, submodules and remote-only branches require separate coverage.",
        "Working-directory scanning includes files supported by Gitleaks. Scanner defaults govern archives/encoding/symlinks. Ignored findings in custom repo config are not honored; built-in rule allowlists still apply.",
        "Findings are candidates, not verified live credentials. Raw secrets, matching text and commit messages are excluded; file paths and commit IDs remain operational metadata.",
        "Each mode has a 110-second scanner timeout and a 120-second process deadline. Failed scans are unknown, never clean. No automatic remediation or history rewriting occurs.",
    ]}
    if not roots:
        return result, []
    executable = shutil.which('gitleaks')
    if executable is None:
        result.update(status='unavailable', detail='Install current Gitleaks with git/dir subcommands (tested v8.30.1) to scan requested repositories. No automatic install performed.', requested_roots=list(roots))
        return result, []
    result['status'] = 'ok'
    findings = []
    seen = set()
    for raw in roots:
        try:
            root = Path(raw).expanduser().resolve()
        except (OSError, RuntimeError) as error:
            result['status'] = 'partial'
            result['repositories'].append({'path': str(raw), 'status': 'error', 'detail': str(error), 'scans': []})
            findings.append({'level': 'UNKNOWN', 'message': 'A requested Git root could not be resolved; see repository evidence.'})
            continue
        if root.name == '.git':
            root = root.parent
        if root in seen:
            continue
        seen.add(root)
        repository = {'path': str(root), 'scans': []}
        result['repositories'].append(repository)
        bare = (root / 'HEAD').is_file() and (root / 'objects').is_dir()
        if not root.is_dir() or not ((root / '.git').exists() or bare):
            repository.update(status='error', detail='Not a local Git repository root')
            result['status'] = 'partial'
            findings.append({'level': 'UNKNOWN', 'message': f'Git secret scan: {root} is not a repository root.'})
            continue
        scratch = None
        cleanup_safe = True
        try:
            # Explicit ownership lets a failed shutdown retain scratch without
            # a TemporaryDirectory finalizer deleting it during exception unwinding.
            scratch = Path(tempfile.mkdtemp(prefix='server-audit-gitleaks-'))
            (scratch / 'config.toml').write_text('[extend]\nuseDefault = true\n', encoding='utf-8')
            (scratch / '.gitleaksignore').write_text('', encoding='utf-8')
            for mode in (('git',) if bare else ('git', 'dir')):
                scan = scan_mode(executable, root, mode, scratch)
                repository['scans'].append(scan)
                if scan['status'] != 'ok':
                    result['status'] = 'partial'
                    findings.append({'level': 'UNKNOWN', 'message': f"Git {root}: {scan['mode']} secret scan incomplete. See scanner status."})
                for detection in scan['detections']:
                    findings.append({'level': 'REVIEW', 'message': f"Git {root}: possible secret ({detection['rule']}) in {detection['file']}:{detection['start_line']} [{scan['mode']}]. If real, revoke/rotate it and investigate exposure; deleting the file alone does not revoke a credential."})
        except (ScannerShutdownError, ScannerShutdownInterrupted) as error:
            cleanup_safe = False
            detail = f"{error} Private scratch retained at {scratch}; stop the scanner before removing it."
            if isinstance(error, KeyboardInterrupt):
                raise ScannerShutdownInterrupted(detail) from None
            raise ScannerShutdownError(detail) from None
        except OSError:
            repository.update(status='partial' if repository['scans'] else 'error',
                              detail='Private scanner scratch setup or access failed; scan incomplete. Raw error withheld.')
            findings.append({'level': 'UNKNOWN', 'message': f'Git {root}: scanner scratch setup or access failed; see repository evidence.'})
        finally:
            if scratch is not None and cleanup_safe:
                try:
                    shutil.rmtree(scratch)
                except OSError:
                    # Do not mask an active interruption or a programming error.
                    repository.update(status='partial' if repository['scans'] else 'error',
                                      cleanup_status='error', scratch_path=str(scratch))
                    findings.append({'level': 'UNKNOWN', 'message': f'Git {root}: private scanner scratch cleanup failed at {scratch}; restricted files may remain. Review locally.'})
        repository.setdefault('status', 'ok' if all(scan['status'] == 'ok' for scan in repository['scans']) else 'partial')
        if repository['status'] != 'ok':
            result['status'] = 'partial'
    return result, findings
