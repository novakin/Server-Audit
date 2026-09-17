import json
import os
import platform
import secrets
import string
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import git_secrets


class GitSecretTests(unittest.TestCase):
    def test_not_requested_and_missing_scanner(self):
        self.assertEqual(git_secrets.collect()[0]['status'], 'not_requested')
        with patch('git_secrets.shutil.which', return_value=None):
            self.assertEqual(git_secrets.collect(['/srv/app'])[0]['status'], 'unavailable')

    def test_only_location_fields_leave_scanner_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            def execute(command):
                path = Path(command[command.index('--report-path') + 1])
                path.write_text(json.dumps([{'RuleID': 'private-key', 'File': 'app.conf', 'StartLine': 7, 'EndLine': 9, 'Commit': 'abc', 'Secret': 'SECRET_SENTINEL', 'Match': 'SECRET_SENTINEL', 'Message': 'SECRET_SENTINEL'}]))
                self.assertIn('--redact=100', command)
                self.assertIn('--ignore-gitleaks-allow', command)
                self.assertIn('--log-opts=--all --full-history --no-ext-diff --no-textconv', command)
                return 10
            with patch('git_secrets.execute', side_effect=execute):
                result = git_secrets.scan_mode('gitleaks', scratch, 'git', scratch)
            self.assertEqual(result['status'], 'ok')
            self.assertNotIn('SECRET_SENTINEL', json.dumps(result))
            self.assertEqual(result['detections'][0]['start_line'], 7)

    def test_failure_and_missing_report_are_unknown(self):
        with tempfile.TemporaryDirectory() as temporary:
            for code in (None, 1, 0):
                with patch('git_secrets.execute', return_value=code):
                    result = git_secrets.scan_mode('gitleaks', Path(temporary), 'git', Path(temporary))
                self.assertEqual(result['status'], 'error')

    def test_invalid_repository_never_runs_scanner(self):
        with tempfile.TemporaryDirectory() as temporary, patch('git_secrets.shutil.which', return_value='/bin/gitleaks'), patch('git_secrets.execute') as execute:
            result, findings = git_secrets.collect([temporary])
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(findings[0]['level'], 'UNKNOWN')
            execute.assert_not_called()

    @unittest.skipUnless(platform.system() == 'Linux' and os.environ.get('AUDIT_TEST_GITLEAKS_PATH'), 'Opt-in real Gitleaks integration')
    def test_real_history_and_working_file_scan(self):
        executable = os.environ['AUDIT_TEST_GITLEAKS_PATH']
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def git(*args):
                subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True)
            git('init', '--quiet')
            git('config', 'user.name', 'Audit test')
            git('config', 'user.email', 'audit-test@example.invalid')
            fake = 'ghp_' + ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
            file = root / 'settings.py'
            file.write_text('github_token = "' + fake + '" # gitleaks:allow\n')
            git('add', 'settings.py')
            git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Fixture')
            git('rm', '--quiet', 'settings.py')
            git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Remove fixture')
            (root / '.env').write_text('GITHUB_TOKEN=' + fake + '\n')
            (root / '.gitignore').write_text('.env\n')
            (root / '.gitleaks.toml').write_text('[allowlist]\npaths = [".*"]\n')
            with patch('git_secrets.shutil.which', return_value=executable):
                report, findings = git_secrets.collect([str(root)])
            self.assertEqual(report['status'], 'ok', report)
            scans = report['repositories'][0]['scans']
            self.assertTrue(scans[0]['detections'], report)
            self.assertTrue(scans[1]['detections'], report)
            self.assertNotIn(fake, json.dumps(report))
            self.assertNotIn(fake, json.dumps(findings))


if __name__ == '__main__':
    unittest.main()
