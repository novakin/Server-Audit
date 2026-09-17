"""Git CLI, orchestration and export boundaries; no production host inspection."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from server_audit import cli as audit
from server_audit import audit_runner
from server_audit.collectors import git_reader
from server_audit.collectors import git_secrets
from server_audit import reporting
from tests.helpers import fixture_report


class GitAuditTests(unittest.TestCase):
    def test_cli_uses_default_and_explicit_repository_budget(self):
        for arguments, expected in (([], 60), (['--git-scan-seconds', '12.5'], 12.5)):
            with self.subTest(arguments=arguments):
                with patch('sys.argv', ['audit.py', '--git-root', '/fixture/repo', '--json', *arguments]), \
                        patch('server_audit.cli.platform.system', return_value='Linux'), \
                        patch('server_audit.cli.audit', return_value={}) as collect, patch.dict(os.environ), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(audit.main(), 0)
                collect.assert_called_once_with(None, None, None, ['/fixture/repo'], expected)

    def test_invalid_cli_budget_is_rejected_before_collection(self):
        for value in ('0', '-1', 'nan', 'inf', '3601', 'invalid'):
            with self.subTest(value=value):
                with patch('sys.argv', ['audit.py', '--git-scan-seconds', value]), \
                        patch('server_audit.cli.audit') as collect, contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as failure:
                        audit.main()
                    self.assertEqual(failure.exception.code, 2)
                collect.assert_not_called()

    def test_runner_passes_budget_and_preserves_not_requested(self):
        with patch('server_audit.audit_runner.collect_git_secrets', wraps=git_secrets.collect) as collect:
            report, _ = fixture_report()
        collect.assert_called_once_with(None, scan_seconds=60)
        self.assertEqual(report['checks']['git_secrets']['status'], 'not_requested')

    def test_missing_git_is_unknown_in_the_full_report(self):
        def unavailable(roots, scan_seconds):
            with patch('server_audit.collectors.git_secrets.shutil.which', return_value=None):
                return git_secrets.collect(['/fixture/repo'], scan_seconds)
        with patch('server_audit.audit_runner.collect_git_secrets', side_effect=unavailable):
            report, _ = fixture_report()
        self.assertEqual(report['checks']['git_secrets']['status'], 'unavailable')
        self.assertTrue(any(item['message'].startswith('git_secrets:') and item['level'] == 'UNKNOWN'
                            for item in report['findings']))
        self.assertIn('ports', report['checks'])

    def test_partial_git_evidence_preserves_later_collection(self):
        partial = {'status': 'partial', 'repositories': [], 'issues': ['Fixture budget reached.']}
        findings = [{'level': 'UNKNOWN', 'message': 'Fixture Git coverage incomplete.'}]
        with patch('server_audit.audit_runner.collect_git_secrets', return_value=(partial, findings)):
            report, _ = fixture_report()
        self.assertEqual(report['checks']['git_secrets'], partial)
        self.assertIn(findings[0], report['findings'])
        self.assertEqual(report['summary']['UNKNOWN'], sum(row['level'] == 'UNKNOWN' for row in report['findings']))

    def test_shutdown_failure_aborts_before_summary_and_export(self):
        for error in (git_reader.GitShutdownError('Fixture reader shutdown unconfirmed.'),
                      git_reader.GitShutdownInterrupted('Fixture cancellation unconfirmed.'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                with patch('server_audit.audit_runner.collect_git_secrets', side_effect=error), \
                        patch('server_audit.audit_runner.summarize') as summarize, \
                        patch('server_audit.cli.audit', side_effect=lambda *args: fixture_report()[0]), \
                        patch('server_audit.cli.export_report') as export, patch('sys.argv', ['audit.py', '--export']), \
                        patch('server_audit.cli.platform.system', return_value='Linux'), patch.dict(os.environ):
                    with self.assertRaises(type(error)):
                        audit.main()
                summarize.assert_not_called()
                export.assert_not_called()

    def test_failed_reader_keeps_workspace_and_stops_repository_iteration(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'repo'
            (root / '.git' / 'objects').mkdir(parents=True)
            (root / '.git' / 'HEAD').write_text('ref: refs/heads/main\n')
            workspace = Path(folder) / 'reader'
            workspace.mkdir(mode=0o700)
            with patch('server_audit.collectors.git_secrets.shutil.which', return_value='fixture-git'), \
                    patch('server_audit.collectors.git_reader.tempfile.mkdtemp', return_value=str(workspace)), \
                    patch('server_audit.collectors.git_secrets.scan_objects', side_effect=git_reader.GitShutdownInterrupted('Fixture reader PID 123.')) as scan:
                with self.assertRaisesRegex(KeyboardInterrupt, 'workspace retained'):
                    git_secrets.collect([str(root), str(root / 'other')])
            scan.assert_called_once()
            self.assertTrue(workspace.is_dir())
            self.assertEqual(workspace.stat().st_mode & 0o777, 0o700)
            self.assertEqual((workspace / 'HEAD').read_text(), 'ref: refs/heads/audit-unused\n')

    def test_redacted_builtin_evidence_survives_json_html_and_text(self):
        sentinel = 'ghp_' + 'Ab12' * 9
        detection = list(git_secrets.detections(sentinel.encode(), 'git-object:' + 'a' * 40,
                                               'blob', 'a' * 40, time.monotonic() + 10))[0]
        check = {'status': 'ok', 'detector': 'builtin', 'ruleset_version': 1,
                 'repositories': [{'path': '/fixture/<repo>', 'status': 'ok',
                                   'scans': [{'mode': 'local_objects', 'status': 'ok', 'detections': [detection]}]}]}
        report = {'schema_version': 1, 'host': 'fixture', 'timestamp_utc': '2026-09-17T12:00:00+00:00',
                  'checks': {'git_secrets': check}, 'findings': [], 'limitations': [],
                  'summary': {'REVIEW': 0, 'UNKNOWN': 0}}
        original = copy.deepcopy(report)
        with tempfile.TemporaryDirectory() as folder:
            bundle = reporting.export_report(report, folder)
            self.assertEqual(json.loads((bundle / 'data/report.json').read_text()), original)
            self.assertEqual(json.loads((bundle / 'manifest.json').read_text())['status'], 'complete')
            html = (bundle / 'report.html').read_text()
            self.assertIn('&lt;repo&gt;', html)
            self.assertIn('local_objects', html)
            for rendered in (html, (bundle / 'data/report.json').read_text(), reporting.render_text(report)):
                self.assertNotIn(sentinel, rendered)
        self.assertEqual(report, original)

    def test_old_gitleaks_report_still_renders_without_new_fields(self):
        check = {'status': 'ok', 'repositories': [{'path': '/fixture/repo', 'status': 'ok', 'scans': [
            {'mode': 'history', 'status': 'ok', 'detections': []},
            {'mode': 'working_directory', 'status': 'ok', 'detections': []}]}]}
        report = {'schema_version': 1, 'host': 'fixture', 'timestamp_utc': '2026-09-17T12:00:00+00:00',
                  'checks': {'git_secrets': check}, 'findings': [], 'limitations': [],
                  'summary': {'REVIEW': 0, 'UNKNOWN': 0}}
        for rendered in (reporting.render_text(report), reporting.render_html(report)):
            self.assertIn('working_directory', rendered)
            self.assertIn('history', rendered)


if __name__ == '__main__':
    unittest.main()
