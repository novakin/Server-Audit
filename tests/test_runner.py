"""Report contract captured before the orchestration refactor."""

import json
import unittest
from pathlib import Path

from server_audit import audit_runner
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
        # Parser coverage is the separately approved phase-one addition (#27).
        expected['report']['checks']['ports']['parser_coverage'] = {
            'status': 'ok', 'records_observed': 1, 'records_parsed': 1, 'records_unparsed': 0,
        }
        # Intentional replacement: built-in local-object scope, not Gitleaks scans.
        expected_git = expected['report']['checks']['git_secrets']
        expected_git.update(
            detector='builtin', ruleset_version=2,  # Narrowed reference exclusions; fixture unchanged.
            rule_ids=['private-key', 'github-token', 'gitlab-token', 'aws-access-key-id',
                      'slack-token', 'credential-in-url', 'authorization-header', 'credential-assignment'],
            limits={'seconds_per_repository': 60.0, 'objects': 10000,
                    'bytes_per_object': 2097152, 'content_bytes_per_repository': 67108864,
                    'bytes_per_config_file': 262144, 'detections_per_repository': 500,
                    'storage_entries': 50000},
            limitations=list(git_secrets.LIMITATIONS))
        self.assertIn('Current working files are not scanned.', expected_git['limitations'][1])
        # Metadata is additive; compare every historical field and ordered finding.
        metadata = {'check', 'resource_type', 'resource_id', 'resource_name'}
        compatible_report = {**report, 'findings': [
            {key: value for key, value in finding.items() if key not in metadata}
            for finding in report['findings']
        ]}
        self.assertEqual(compatible_report, expected['report'])
        self.assertEqual(list(report['checks']), list(expected['report']['checks']))
        self.assertEqual(calls, expected['commands'])
        self.assertEqual([finding.get('check') for finding in report['findings']], [
            None, 'ssh', 'ssh', 'ssh', 'ports', 'reboot_required', None,
            'nftables', 'apt_metadata', 'accounts', None, None,
            'available_updates', 'failed_services',
        ])
        for finding in report['findings']:
            if 'resource_type' in finding:
                for field in ('resource_type', 'resource_id', 'resource_name'):
                    self.assertIsInstance(finding[field], str)
                    self.assertTrue(finding[field])

    def test_common_failures_keep_check_identity_without_inventing_resource(self):
        findings = audit_runner.summarize({
            'accounts': {'status': 'error', 'detail': 'fixture denied'},
            'os': {'status': 'unavailable', 'detail': 'fixture missing'},
            'nftables': {'status': 'error', 'detail': 'fixture firewall denied'},
        })
        self.assertEqual(findings[:3], [
            {'level': 'UNKNOWN', 'message': 'accounts: fixture denied', 'check': 'accounts'},
            {'level': 'UNKNOWN', 'message': 'os: fixture missing', 'check': 'os'},
            {'level': 'UNKNOWN', 'message': 'nftables: fixture firewall denied', 'check': 'nftables'},
        ])

    def test_report_retains_audit_wide_and_injected_legacy_findings(self):
        report, _ = fixture_report()
        self.assertEqual(report['findings'][0], {
            'level': 'UNKNOWN',
            'message': 'Not running as root: SSH configuration, firewall and process ownership checks may be incomplete.',
        })
        self.assertIn({'level': 'UNKNOWN', 'message': 'Fixture environment coverage incomplete.'}, report['findings'])
        for finding in report['findings']:
            if 'check' in finding:
                self.assertIn(finding['check'], report['checks'])
        failures = [finding for finding in report['findings'] if finding.get('check') == 'accounts']
        self.assertEqual(failures, [{
            'level': 'UNKNOWN', 'message': 'accounts: Fixture account access denied', 'check': 'accounts',
        }])


if __name__ == '__main__':
    unittest.main()
