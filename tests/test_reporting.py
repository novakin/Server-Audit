import contextlib
import copy
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit import cli as audit
from server_audit import reporting


def sample_report():
    return {
        "schema_version": 1, "host": "edge-01", "timestamp_utc": "2026-09-17T12:00:00+00:00",
        "findings": [{"level": "REVIEW", "message": "SSH password authentication enabled."},
                     {"level": "UNKNOWN", "message": "Firewall evidence unavailable."}],
        "checks": {"ssh": {"status": "ok", "output": "passwordauthentication yes"},
                   "nftables": {"status": "unavailable", "detail": "Command not installed"},
                   "ports": {"status": "ok", "listeners": [{"address": "0.0.0.0:22", "protocol": "tcp", "binding": "non-loopback", "process": "sshd"}]},
                   "accounts": {"status": "ok", "accounts": [{"user": "alice", "uid": 1000, "groups": ["sudo"], "shell": "/bin/bash", "key_files": []}]},
                   "docker": {"status": "ok", "containers": []}},
        "limitations": ["External reachability not verified."],
    }


class ReportingTests(unittest.TestCase):
    def test_text_report_preserves_sections_before_and_after_raw_output(self):
        report = {'host': 'fixture', 'timestamp_utc': 'fixed', 'summary': {'REVIEW': 1, 'UNKNOWN': 0},
                  'findings': [{'level': 'REVIEW', 'message': 'Review fixture.'}],
                  'checks': {'first': {'status': 'ok', 'output': 'alpha\nbeta'}, 'second': {'status': 'error', 'detail': 'denied'}},
                  'limitations': ['Fixture scope.']}
        expected = ('Server audit: fixture | fixed\nReview: 1 | Unknown: 0 (not a security score)\n'
                    '[REVIEW] Review fixture.\n\n--- first: ok ---\nalpha\nbeta\n'
                    '\n--- second: error ---\n\ndenied\n\nLimitations:\n- Fixture scope.\n')
        self.assertEqual(reporting.render_text(report), expected)

    def test_new_collector_limitations_are_included_without_renderer_changes(self):
        report = sample_report()
        report['checks']['future_check'] = {'status': 'partial', 'limitations': ['Future collector scope.']}
        rendered = reporting.render_html(report)
        section = rendered.split('id="limitations"', 1)[1]
        self.assertIn('Future collector scope.', section)

    def test_export_is_unique_and_json_preserves_source(self):
        report = sample_report()
        original = copy.deepcopy(report)
        with tempfile.TemporaryDirectory() as temp:
            first = reporting.export_report(report, temp)
            second = reporting.export_report(report, temp)
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads((first / 'data/report.json').read_text()), report)
            manifest = json.loads((first / 'manifest.json').read_text())
            self.assertEqual(manifest['status'], 'complete')
            self.assertTrue(all((first / file).is_file() for file in manifest['files']))
            self.assertFalse((first / '.manifest.pending').exists())
        self.assertEqual(report, original)

    def test_all_host_data_is_escaped_in_html(self):
        report = sample_report()
        attack = '</pre><script>alert("injected")</script><img src=x onerror=alert(1)>'
        report['host'] = attack
        report['timestamp_utc'] = attack
        report['findings'][0]['message'] = attack
        report['checks']['ssh']['output'] = attack
        report['checks'][attack] = {'status': attack}
        report['limitations'] = [attack]
        output = reporting.render_html(report)
        self.assertNotIn(attack, output)
        self.assertIn('&lt;script&gt;', output)
        self.assertEqual(output.count('<script>'), 1)

    def test_host_cannot_escape_export_parent(self):
        report = sample_report()
        report['host'] = '../../bad/host\\path<script>'
        with tempfile.TemporaryDirectory() as temp:
            result = reporting.export_report(report, temp)
            self.assertEqual(result.parent, Path(temp).resolve())
            self.assertNotIn('<', result.name)

    @unittest.skipUnless(os.name == 'posix', 'POSIX permission checks')
    def test_private_linux_permissions(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = reporting.export_report(sample_report(), Path(temp) / 'audits')
            for path in (folder, folder / 'data'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for path in (folder / 'report.html', folder / 'data/report.json', folder / 'manifest.json'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_failed_write_retains_partial_folder_without_completion_manifest(self):
        native_write = reporting.private_write
        def failing_write(path, content):
            if path.name == 'report.html':
                raise OSError('simulated disk full')
            native_write(path, content)
        with tempfile.TemporaryDirectory() as temp, patch('server_audit.reporting.private_write', side_effect=failing_write):
            with self.assertRaisesRegex(OSError, 'Export incomplete'):
                reporting.export_report(sample_report(), temp)
            folders = list(Path(temp).iterdir())
            self.assertEqual(len(folders), 1)
            self.assertTrue((folders[0] / 'data/report.json').exists())
            self.assertFalse((folders[0] / 'manifest.json').exists())

    def test_empty_and_unavailable_inventory_remain_distinct(self):
        report = sample_report()
        self.assertIn('No containers found', reporting.render_html(report))
        report['checks']['docker'] = {'status': 'error', 'detail': 'Access denied'}
        output = reporting.render_html(report)
        self.assertIn('Docker inventory unavailable', output)
        self.assertNotIn('No containers found', output)
        report['findings'] = []
        self.assertIn('does not establish that the host is secure', reporting.render_html(report))

    def test_skipped_docker_reason_visible_in_html_and_text(self):
        report = sample_report()
        report['summary'] = {'REVIEW': 1, 'UNKNOWN': 1}
        report['checks']['docker'] = {'status': 'skipped', 'detail': 'Docker audit skipped: CLI not found.'}
        output = reporting.render_html(report)
        self.assertIn('>Skipped</span>', output)
        self.assertIn('Docker audit skipped: CLI not found.', output)
        self.assertNotIn('Docker inventory unavailable', output)
        self.assertNotIn('No containers found', output)
        report['checks'].pop('accounts')  # HTML fixture omits detailed text-only account fields.
        self.assertIn('Docker audit skipped: CLI not found.', reporting.render_text(report))

    def test_manifest_write_failure_does_not_publish_completion(self):
        native_write = reporting.private_write
        def failing_write(path, content):
            native_write(path, content)
            if path.name == '.manifest.pending':
                raise OSError('simulated flush failure')
        with tempfile.TemporaryDirectory() as temp, patch('server_audit.reporting.private_write', side_effect=failing_write):
            with self.assertRaises(OSError):
                reporting.export_report(sample_report(), temp)
            folder = next(Path(temp).iterdir())
            self.assertFalse((folder / 'manifest.json').exists())

    def test_export_failure_returns_nonzero_without_success_message(self):
        with patch('sys.argv', ['audit.py', '--export']), patch('server_audit.cli.platform.system', return_value='Linux'), patch('server_audit.cli.audit', return_value=sample_report()), patch('server_audit.cli.export_report', side_effect=OSError('disk full')), patch.dict(os.environ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = audit.main()
            self.assertEqual(result, 1)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn('Export failed:', stderr.getvalue())
            self.assertNotIn('Audit exported:', stderr.getvalue())

    def test_cli_export_does_not_pollute_json_stdout(self):
        with tempfile.TemporaryDirectory() as temp, patch('sys.argv', ['audit.py', '--json', '--export', temp]), patch('server_audit.cli.platform.system', return_value='Linux'), patch('server_audit.cli.audit', return_value=sample_report()), patch.dict(os.environ):
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = audit.main()
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(stdout.getvalue()), sample_report())
            self.assertIn('Audit exported:', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
