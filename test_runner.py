"""Report contract captured before the orchestration refactor."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

import audit_runner
import reporting


class HostPath:
    def __init__(self, value):
        self.value = value

    def exists(self):
        return True

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

    with patch('audit_runner.run', side_effect=run), patch('system_audit.Path', HostPath), patch('audit_runner.os.geteuid', return_value=1000, create=True), patch('audit_runner.platform.node', return_value='fixture-host'), patch('audit_runner.collect_accounts', side_effect=OSError('Fixture account access denied')), patch('audit_runner.collect_env_files', side_effect=environment), patch('audit_runner.collect_scheduled_tasks', return_value=({'status': 'ok', 'cron_files': []}, [])):
        report = audit_runner.audit('user=alice,addr=192.0.2.1', '/etc/ssh/custom.conf', ['/srv/app'])
    # The separately requested scheduled-task feature adds a check, not changes to existing checks.
    report['checks'].pop('scheduled_tasks')
    report['timestamp_utc'] = '2026-09-17T00:00:00+00:00'
    return report, calls


class RunnerTests(unittest.TestCase):
    def test_report_and_command_order_match_pre_refactor_contract(self):
        report, calls = fixture_report()
        expected = json.loads(Path(__file__).with_name('fixtures').joinpath('audit-contract.json').read_text(encoding='utf-8'))
        # Intentional post-refactor change: missing optional tools are explicit skips.
        for name in ('ufw', 'iptables_ipv6'):
            expected['report']['checks'][name]['status'] = 'skipped'
        expected['report']['checks']['docker'] = {
            'status': 'skipped',
            'detail': 'Docker audit skipped: Docker CLI not found in the audit PATH. No container inspection attempted; daemon presence is unverified.',
        }
        # Intentional additive SSH evidence; the historical fixture remains unchanged.
        expected['report']['checks']['ssh'].update(
            configuration_source='custom', configuration_path='/etc/ssh/custom.conf',
            connection_context='user=alice,addr=192.0.2.1',
            selected_setting_values={'permitrootlogin': ['yes'], 'passwordauthentication': ['yes'],
                                     'kbdinteractiveauthentication': ['yes']})
        expected['report']['limitations'][1] = (
            'SSH settings describe the selected on-disk configuration (sshd default unless --ssh-config is supplied), '
            'not necessarily the running daemon or its command-line overrides. Match rules require --ssh-context.')
        self.assertEqual(report, expected['report'])
        self.assertEqual(list(report['checks']), list(expected['report']['checks']))
        self.assertEqual(calls, expected['commands'])


if __name__ == '__main__':
    unittest.main()
