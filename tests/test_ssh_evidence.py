"""Additive SSH scope/multivalue evidence and legacy-format compatibility."""

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from server_audit import reporting
from server_audit.collectors import ssh_audit
from tests.helpers import fixture_report


class SSHEvidenceTests(unittest.TestCase):
    def test_disable_forwarding_override_preserves_subordinate_values_and_other_findings(self):
        output = ('permitrootlogin yes\npasswordauthentication yes\npermitemptypasswords yes\n'
                  'kbdinteractiveauthentication yes\nx11forwarding yes\nallowtcpforwarding yes\n')
        _, existing = ssh_audit.ssh_findings(output)
        unrelated = [item for item in existing if not item['message'].startswith(('SSH x11forwarding=', 'SSH allowtcpforwarding='))]
        self.assertEqual(len(existing), 6)
        self.assertEqual(len(unrelated), 4)
        for override in ('yes', 'no', None):
            with self.subTest(override=override):
                evidence = output + (f'disableforwarding {override}\n' if override is not None else '')
                check, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': evidence})
                expected = unrelated if override == 'yes' else existing
                self.assertEqual(findings, expected)
                self.assertEqual(check['output'], evidence)
                self.assertEqual(check['selected_settings']['x11forwarding'], 'yes')
                self.assertEqual(check['selected_settings']['allowtcpforwarding'], 'yes')
                if override is None:
                    self.assertNotIn('disableforwarding', check['selected_settings'])
                    self.assertNotIn('disableforwarding', check['selected_setting_values'])
                else:
                    self.assertEqual(check['selected_settings']['disableforwarding'], override)
                    self.assertEqual(check['selected_setting_values']['disableforwarding'], [override])

    def test_repeated_disable_forwarding_retains_values_and_legacy_last_value_policy(self):
        for values in (('no', 'yes'), ('yes', 'no')):
            with self.subTest(values=values):
                output = 'x11forwarding yes\nallowtcpforwarding yes\n' + ''.join(f'disableforwarding {value}\n' for value in values)
                check, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': output})
                self.assertEqual(check['selected_settings']['disableforwarding'], values[-1])
                self.assertEqual(check['selected_setting_values']['disableforwarding'], list(values))
                self.assertEqual(len(findings), 0 if values[-1] == 'yes' else 2)
                self.assertEqual(check['output'], output)

    def test_disable_forwarding_does_not_invent_missing_subordinate_settings(self):
        check, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': 'disableforwarding yes'})
        self.assertEqual(check['selected_settings'], {'disableforwarding': 'yes'})
        self.assertEqual(check['selected_setting_values'], {'disableforwarding': ['yes']})
        self.assertEqual(findings, [])

    def test_default_and_custom_scope_are_retained_on_success_and_failure(self):
        for status in ('ok', 'error', 'unavailable'):
            for config, context in ((None, None), ('relative config.conf', None),
                                    (None, 'user=alice'), ('/etc/ssh/custom.conf', 'user=bob,addr=192.0.2.1')):
                with self.subTest(status=status, config=config, context=context):
                    run = Mock(return_value={'status': status, 'output': 'permitrootlogin no', 'detail': ''})
                    check, _ = ssh_audit.collect(run, context, config)
                    command = ['sshd', '-T']
                    if config:
                        command += ['-f', config]
                    if context:
                        command += ['-C', context]
                    run.assert_called_once_with(command)
                    self.assertEqual(check['configuration_source'], 'custom' if config else 'default')
                    self.assertEqual(check['configuration_path'], config)
                    self.assertEqual(check['connection_context'], context)
                    self.assertEqual(check['status'], status)
                    if status != 'ok':
                        self.assertNotIn('selected_setting_values', check)
                        self.assertNotIn('selected_settings', check)

    def test_repeated_values_preserve_legacy_scalars_and_policy(self):
        output = ('port 22\nport 2222\nlistenaddress 0.0.0.0:22\nlistenaddress [::]:2222\n'
                  'allowusers alice bob\nallowusers carol\npermitrootlogin no\n'
                  'passwordauthentication yes\nhostkey /fixture/key\nignored-line\n')
        legacy, legacy_findings = ssh_audit.ssh_findings(output)
        run = Mock(return_value={'status': 'ok', 'output': output, 'detail': ''})
        check, findings = ssh_audit.collect(run)
        self.assertEqual(check['selected_settings'], legacy)
        self.assertEqual(check['selected_settings']['port'], '2222')
        self.assertEqual(check['selected_settings']['listenaddress'], '[::]:2222')
        self.assertEqual(check['selected_setting_values'], {
            'port': ['22', '2222'], 'listenaddress': ['0.0.0.0:22', '[::]:2222'],
            'allowusers': ['alice bob', 'carol'], 'permitrootlogin': ['no'],
            'passwordauthentication': ['yes'],
        })
        self.assertEqual(findings, legacy_findings)
        self.assertEqual(len(findings), 1)
        self.assertEqual(check['output'], output)

    def test_no_values_are_invented_for_absent_settings(self):
        check, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': '\nunknown value\nmalformed\n'})
        self.assertEqual(check['selected_settings'], {})
        self.assertEqual(check['selected_setting_values'], {})
        self.assertEqual(findings, [])

    def test_runner_uses_scope_neutral_limitation(self):
        report, _ = fixture_report()
        limitation = next(item for item in report['limitations'] if item.startswith('SSH settings'))
        self.assertIn('selected on-disk configuration', limitation)
        self.assertIn('--ssh-config', limitation)
        self.assertIn('command-line overrides', limitation)
        self.assertNotIn('installed default configuration', limitation)
        self.assertEqual(report['schema_version'], 1)

    def test_scope_survives_json_html_and_text_without_mutating_report(self):
        config, context = '/etc/ssh/<fixture>.conf', 'user=alice,host=<fixture>'
        output = 'port 22\nport 2222\ndisableforwarding yes\nx11forwarding yes\nallowtcpforwarding yes'
        check, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': output}, context, config)
        report = {'schema_version': 1, 'host': 'fixture', 'timestamp_utc': '2026-09-17T12:00:00+00:00',
                  'checks': {'ssh': check}, 'findings': findings, 'summary': {'REVIEW': 0, 'UNKNOWN': 0}, 'limitations': []}
        original = copy.deepcopy(report)
        with tempfile.TemporaryDirectory() as directory:
            folder = reporting.export_report(report, directory)
            exported = json.loads((folder / 'data/report.json').read_text())
            self.assertEqual(exported, original)
            self.assertEqual(exported['checks']['ssh']['selected_settings']['disableforwarding'], 'yes')
            self.assertEqual(exported['findings'], [])
            html = (folder / 'report.html').read_text()
            self.assertIn('configuration_source', html)
            self.assertIn('selected_setting_values', html)
            self.assertIn('disableforwarding', html)
            self.assertIn('&lt;fixture&gt;', html)
            self.assertNotIn(config, html)
            self.assertEqual(json.loads((folder / 'manifest.json').read_text())['status'], 'complete')
        text = reporting.render_text(report)
        self.assertIn('SSH configuration argument: ' + config, text)
        self.assertIn('SSH connection context: ' + context, text)
        self.assertIn('port 22\nport 2222', text)
        self.assertIn(output, text)
        self.assertEqual(report, original)

    def test_legacy_report_without_new_fields_still_renders(self):
        report = {'schema_version': 1, 'host': 'fixture', 'timestamp_utc': '2026-09-17T12:00:00+00:00',
                  'checks': {'ssh': {'status': 'ok', 'output': 'port 22', 'selected_settings': {'port': '22'}}},
                  'findings': [], 'summary': {'REVIEW': 0, 'UNKNOWN': 0}, 'limitations': []}
        text = reporting.render_text(report)
        self.assertIn('--- ssh: ok ---\nport 22', text)
        self.assertNotIn('SSH configuration source:', text)
        self.assertIn('port 22', reporting.render_html(report))


if __name__ == '__main__':
    unittest.main()
