"""System metadata failure-isolation regressions; Git lifecycle tests live in test_git_reader."""

import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit.collectors import system_audit
from tests.helpers import HostPath, fixture_report


class OSFailureTests(unittest.TestCase):
    def test_read_failure_is_evidence_not_platform_fallback(self):
        for error in (PermissionError('denied'), OSError('read failed'), UnicodeError('invalid text')):
            with self.subTest(error=type(error).__name__), patch('server_audit.collectors.system_audit.Path') as path, patch('server_audit.collectors.system_audit.platform.platform') as fallback:
                path.return_value.read_text.side_effect = error
                check = system_audit.collect_os()
                self.assertEqual(check['status'], 'error')
                self.assertIn(str(error), check['detail'])
                fallback.assert_not_called()

    def test_missing_os_release_preserves_existing_fallback(self):
        with patch('server_audit.collectors.system_audit.Path') as path, patch('server_audit.collectors.system_audit.platform.platform', return_value='platform fixture'):
            path.return_value.read_text.side_effect = FileNotFoundError()
            self.assertEqual(system_audit.collect_os(), {'status': 'ok', 'output': 'platform fixture'})

    def test_programming_errors_are_not_swallowed(self):
        with patch('server_audit.collectors.system_audit.Path') as path:
            path.return_value.read_text.side_effect = TypeError('programming defect')
            with self.assertRaises(TypeError):
                system_audit.collect_os()

    def test_failed_os_collection_preserves_later_checks_and_summary(self):
        with patch.object(HostPath, 'read_text', side_effect=PermissionError('fixture denied')):
            report, _ = fixture_report()
        self.assertEqual(report['checks']['os']['status'], 'error')
        self.assertIn('ports', report['checks'])
        self.assertIn('git_secrets', report['checks'])
        self.assertTrue(any(item['level'] == 'UNKNOWN' and item['message'].startswith('os:') for item in report['findings']))
        self.assertEqual(report['summary']['UNKNOWN'], sum(item['level'] == 'UNKNOWN' for item in report['findings']))


class RebootFailureTests(unittest.TestCase):
    def test_present_and_absent_marker_preserve_existing_results(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'reboot-required'
            for present in (False, True):
                if present:
                    marker.touch()
                with self.subTest(present=present):
                    with patch.object(system_audit, 'Path', return_value=marker) as path:
                        check, findings = system_audit.collect_reboot_state()
                    path.assert_called_once_with('/var/run/reboot-required')
                    self.assertEqual(check, {'status': 'ok', 'output': str(present)})
                    expected_findings = []
                    if present:
                        expected_findings.append({'level': 'REVIEW', 'message': 'System reports a reboot is required.'})
                    self.assertEqual(findings, expected_findings)

    def test_inspection_failures_are_errors_not_absence(self):
        errors = (
            PermissionError(errno.EACCES, 'fixture denied'),
            OSError(errno.EIO, 'fixture I/O failure'),
            NotADirectoryError(errno.ENOTDIR, 'fixture invalid parent'),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__):
                with patch.object(system_audit.Path, 'stat', side_effect=error):
                    check, findings = system_audit.collect_reboot_state()
                self.assertEqual(check, {'status': 'error', 'detail': str(error)})
                # The existing runner summary creates the Unknown finding from this error.
                self.assertEqual(findings, [])

    def test_failed_marker_inspection_preserves_other_evidence_and_summary(self):
        baseline, expected_commands = fixture_report()
        with patch.object(HostPath, 'stat', side_effect=PermissionError('fixture marker denied')):
            report, commands = fixture_report()
        self.assertEqual(report['checks']['reboot_required'],
                         {'status': 'error', 'detail': 'fixture marker denied'})
        self.assertEqual(list(report['checks']), list(baseline['checks']))
        for name, check in baseline['checks'].items():
            if name != 'reboot_required':
                with self.subTest(check=name):
                    self.assertEqual(report['checks'][name], check)
        self.assertEqual(commands, expected_commands)
        unknown = {'level': 'UNKNOWN', 'message': 'reboot_required: fixture marker denied'}
        self.assertEqual(report['findings'].count(unknown), 1)
        reboot_review = {'level': 'REVIEW', 'message': 'System reports a reboot is required.'}
        self.assertIn(reboot_review, baseline['findings'])
        self.assertEqual([item for item in report['findings'] if item != unknown],
                         [item for item in baseline['findings'] if item != reboot_review])
        self.assertEqual(report['summary'], {
            'REVIEW': baseline['summary']['REVIEW'] - 1,
            'UNKNOWN': baseline['summary']['UNKNOWN'] + 1,
        })
        self.assertEqual(report['schema_version'], baseline['schema_version'])
        self.assertEqual(report['limitations'], baseline['limitations'])

    def test_programming_errors_and_interruption_propagate_out_of_audit(self):
        for error in (TypeError('fixture programming defect'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), patch.object(HostPath, 'stat', side_effect=error):
                with self.assertRaises(type(error)):
                    fixture_report()


if __name__ == '__main__':
    unittest.main()
