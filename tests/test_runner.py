"""Report contract captured before the orchestration refactor."""

import json
import unittest
from pathlib import Path

from server_audit.collectors import git_secrets
from tests.helpers import fixture_report


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
        # Intentional replacement: built-in local-object scope, not Gitleaks scans.
        expected_git = expected['report']['checks']['git_secrets']
        expected_git.update(
            detector='builtin', ruleset_version=1,
            rule_ids=['private-key', 'github-token', 'gitlab-token', 'aws-access-key-id',
                      'slack-token', 'credential-in-url', 'authorization-header', 'credential-assignment'],
            limits={'seconds_per_repository': 60.0, 'objects': 10000,
                    'bytes_per_object': 2097152, 'content_bytes_per_repository': 67108864,
                    'bytes_per_config_file': 262144, 'detections_per_repository': 500,
                    'storage_entries': 50000},
            limitations=list(git_secrets.LIMITATIONS))
        self.assertIn('Current working files are not scanned.', expected_git['limitations'][1])
        self.assertEqual(report, expected['report'])
        self.assertEqual(list(report['checks']), list(expected['report']['checks']))
        self.assertEqual(calls, expected['commands'])


if __name__ == '__main__':
    unittest.main()
