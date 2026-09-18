"""Shared synthetic host fixtures; no real host collection."""

import os
from unittest.mock import patch

from server_audit import audit_runner


class HostPath:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return self.value

    def stat(self):
        return os.stat_result((0,) * 10)

    def read_text(self):
        return 'ID=debian\nVERSION_ID=12\n'

    def iterdir(self):
        return iter([])


def fixture_report():
    calls = []
    def run(command, input_text=None):
        calls.append(command)
        if command[0] in ('ufw', 'ip6tables-save', 'docker'):
            return {'status': 'unavailable', 'detail': 'Command not installed: ' + command[0]}
        if command[0] == 'nft':
            return {'status': 'error', 'exit_code': 1, 'output': '', 'detail': 'Permission denied'}
        output = ''
        if command[0] == 'sshd':
            output = 'permitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication yes'
        elif command[0] == 'ss':
            output = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=20,fd=3))'
        elif command[0] == 'apt':
            output = 'Listing...\nopenssl/stable 3.0 amd64 [upgradable from: 2.0]'
        elif command[0] == 'systemctl':
            output = 'web.service loaded failed failed Web' if '--state=failed' in command else 'ssh.service loaded active running SSH'
        return {'status': 'ok', 'exit_code': 0, 'output': output, 'detail': ''}

    def environment(roots, runner, checks):
        assert roots == ['/srv/app']
        assert checks['ssh']['selected_settings']['permitrootlogin'] == 'yes'
        assert 'running_services' in checks and 'docker' in checks
        return {'status': 'partial', 'files': []}, [{'level': 'UNKNOWN', 'message': 'Fixture environment coverage incomplete.'}]

    with patch('server_audit.audit_runner.run', side_effect=run), patch('server_audit.collectors.system_audit.Path', HostPath), patch('server_audit.audit_runner.os.geteuid', return_value=1000, create=True), patch('server_audit.audit_runner.platform.node', return_value='fixture-host'), patch('server_audit.audit_runner.collect_accounts', side_effect=OSError('Fixture account access denied')), patch('server_audit.audit_runner.collect_env_files', side_effect=environment), patch('server_audit.audit_runner.collect_scheduled_tasks', return_value=({'status': 'ok', 'cron_files': []}, [])):
        report = audit_runner.audit('user=alice,addr=192.0.2.1', '/etc/ssh/custom.conf', ['/srv/app'])
    # The separately requested scheduled-task feature adds a check, not changes to existing checks.
    report['checks'].pop('scheduled_tasks')
    report['timestamp_utc'] = '2026-09-17T00:00:00+00:00'
    return report, calls
