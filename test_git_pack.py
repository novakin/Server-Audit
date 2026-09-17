"""Damaged packed storage must remain incomplete; disposable local fixtures only."""

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import git_reader
import git_secrets
import reporting


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Requires local Git and POSIX pipes')
class PackedStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='audit-pack-test-')
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'repository'
        self.root.mkdir()
        self.environment = git_reader.environment(self.parent)
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Synthetic audit test')
        self.git('config', 'user.email', 'audit@example.invalid')
        self.sentinel = 'ghp_' + 'Ab12' * 9  # Fabricated, never a usable credential.
        (self.root / 'settings.txt').write_text('api_key="' + self.sentinel + '"\n')
        self.git('add', '--', 'settings.txt')
        self.git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Synthetic fixture')
        self.object_id = self.git('rev-parse', 'HEAD:settings.txt').decode().strip()
        self.git('gc', '--prune=now', '--quiet')
        self.index = next((self.root / '.git/objects/pack').glob('*.idx'))
        self.pack = self.index.with_suffix('.pack')
        self.pack_digest = hashlib.sha256(self.pack.read_bytes()).hexdigest()

    def git(self, *arguments, data=None, root=None):
        completed = subprocess.run(
            ['git', '-C', str(root or self.root), *arguments],
            input=data, env=self.environment, capture_output=True, check=True, timeout=10,
        )
        return completed.stdout

    def scan(self, *roots):
        directory = self.root / '.git'
        before = {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            report, findings = git_secrets.collect(list(roots or [str(self.root)]), scan_seconds=10)
        after = {str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob('*') if p.is_file()}
        self.assertEqual(after, before, 'Inspection must not repair or alter damaged storage')
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn(self.sentinel, json.dumps([report, findings]))
        self.assertNotIn('PRIVATE_DIAGNOSTIC_SENTINEL', json.dumps([report, findings]))
        return report, findings

    def assert_incomplete(self, report, findings):
        repository = report['repositories'][0]
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(repository['status'], 'partial')
        self.assertTrue(repository['issues'])
        objects = next(scan for scan in repository['scans'] if scan['mode'] == 'local_objects')
        self.assertEqual(objects['status'], 'partial')
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))

    def assert_pack_unchanged(self):
        self.assertEqual(hashlib.sha256(self.pack.read_bytes()).hexdigest(), self.pack_digest)

    def test_healthy_pack_detects_secret_without_false_coverage_warning(self):
        report, findings = self.scan()
        self.assertEqual(report['status'], 'ok')
        repository = report['repositories'][0]
        self.assertEqual(repository['issues'], [])
        detections = [item for scan in repository['scans'] for item in scan['detections']]
        self.assertIn(self.object_id, {item['object_id'] for item in detections})
        self.assertFalse(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_missing_index_is_incomplete_not_successful_empty_scan(self):
        self.index.unlink()
        report, findings = self.scan()
        self.assert_incomplete(report, findings)
        self.assert_pack_unchanged()
        self.assertTrue(any('pairing' in issue for issue in report['repositories'][0]['issues']))

    def test_corrupt_index_is_incomplete_even_when_enumeration_does_not_fail(self):
        self.index.write_bytes(b'PRIVATE_DIAGNOSTIC_SENTINEL')
        report, findings = self.scan()
        self.assert_incomplete(report, findings)
        self.assert_pack_unchanged()
        self.assertTrue(any('diagnostics' in issue for issue in report['repositories'][0]['issues']))

    def test_truncated_index_is_incomplete(self):
        self.index.write_bytes(self.index.read_bytes()[:16])
        report, findings = self.scan()
        self.assert_incomplete(report, findings)
        self.assert_pack_unchanged()

    def test_index_without_its_pack_is_incomplete(self):
        self.pack.unlink()
        report, findings = self.scan()
        self.assert_incomplete(report, findings)
        self.assertTrue(any('pairing' in issue for issue in report['repositories'][0]['issues']))

    def test_equal_pack_and_index_counts_with_different_names_are_incomplete(self):
        self.index.rename(self.index.with_name('pack-' + '0' * 40 + '.idx'))
        report, findings = self.scan()
        self.assert_incomplete(report, findings)
        self.assert_pack_unchanged()
        self.assertTrue(any('pairing' in issue for issue in report['repositories'][0]['issues']))

    def test_corrupt_pack_content_remains_incomplete(self):
        self.pack.write_bytes(b'PRIVATE_DIAGNOSTIC_SENTINEL')
        report, findings = self.scan()
        self.assert_incomplete(report, findings)

    def test_config_loose_objects_and_later_repositories_survive_bad_indexes(self):
        loose_id = self.git('hash-object', '-w', '--stdin', data=(self.sentinel + '\n').encode()).decode().strip()
        self.git('config', 'remote.origin.url', 'https://alice:FixturePassword42@example.invalid/repo')
        healthy = self.parent / 'healthy'
        healthy.mkdir()
        self.git('init', '--quiet', root=healthy)
        healthy_id = self.git('hash-object', '-w', '--stdin', data=self.sentinel.encode(), root=healthy).decode().strip()
        for failure in ('missing', 'corrupt'):
            with self.subTest(failure=failure):
                if failure == 'missing':
                    self.index.unlink()
                else:
                    self.index.write_bytes(b'PRIVATE_DIAGNOSTIC_SENTINEL')
                report, findings = self.scan(str(self.root), str(healthy))
                self.assert_incomplete(report, findings)
                self.assertEqual([item['status'] for item in report['repositories']], ['partial', 'ok'])
                first = [item for scan in report['repositories'][0]['scans'] for item in scan['detections']]
                second = [item for scan in report['repositories'][1]['scans'] for item in scan['detections']]
                self.assertIn(loose_id, {item['object_id'] for item in first})
                self.assertIn('credential-in-url', {item['rule'] for item in first})
                self.assertIn(healthy_id, {item['object_id'] for item in second})
                self.assertNotIn('FixturePassword42', json.dumps([report, findings]))
                self.assert_pack_unchanged()

    def test_partial_status_and_redaction_survive_json_and_html_export(self):
        self.index.write_bytes(b'PRIVATE_DIAGNOSTIC_SENTINEL')
        check, findings = self.scan()
        report = {
            'schema_version': 1, 'host': 'synthetic', 'timestamp_utc': '2026-09-17T12:00:00+00:00',
            'checks': {'git_secrets': check}, 'findings': findings, 'limitations': [],
            'summary': {level: sum(item['level'] == level for item in findings) for level in ('REVIEW', 'UNKNOWN')},
        }
        folder = reporting.export_report(report, self.parent / 'exports')
        exported = json.loads((folder / 'data/report.json').read_text())
        self.assertEqual(exported, report)
        html = (folder / 'report.html').read_text()
        text = reporting.render_text(report)
        self.assertIn('Incomplete', html)
        self.assertIn('diagnostics', text)
        for output in (json.dumps(exported), html, text):
            self.assertNotIn(self.sentinel, output)
            self.assertNotIn('PRIVATE_DIAGNOSTIC_SENTINEL', output)


if __name__ == '__main__':
    unittest.main()
