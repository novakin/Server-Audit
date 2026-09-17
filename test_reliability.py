"""OS failure-isolation regressions; Git lifecycle tests live in test_git_reader."""

import unittest
from unittest.mock import patch

import system_audit
from test_runner import HostPath, fixture_report


class OSFailureTests(unittest.TestCase):
    def test_read_failure_is_evidence_not_platform_fallback(self):
        for error in (PermissionError('denied'), OSError('read failed'), UnicodeError('invalid text')):
            with self.subTest(error=type(error).__name__), patch('system_audit.Path') as path, patch('system_audit.platform.platform') as fallback:
                path.return_value.read_text.side_effect = error
                check = system_audit.collect_os()
                self.assertEqual(check['status'], 'error')
                self.assertIn(str(error), check['detail'])
                fallback.assert_not_called()

    def test_missing_os_release_preserves_existing_fallback(self):
        with patch('system_audit.Path') as path, patch('system_audit.platform.platform', return_value='platform fixture'):
            path.return_value.read_text.side_effect = FileNotFoundError()
            self.assertEqual(system_audit.collect_os(), {'status': 'ok', 'output': 'platform fixture'})

    def test_programming_errors_are_not_swallowed(self):
        with patch('system_audit.Path') as path:
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


if __name__ == '__main__':
    unittest.main()
