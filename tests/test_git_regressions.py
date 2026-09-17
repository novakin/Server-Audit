"""Git scanner corrections: synthetic values and disposable repositories only."""

import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from server_audit import reporting
from server_audit.collectors import git_secrets
from tests.git_helpers import init_repository, run_git, snapshot


TOKEN = b'ghp_' + b'Ab12' * 9
LITERAL = '$uperSecret123!'


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Requires local Git and POSIX pipes')
class StorageRegressionTests(unittest.TestCase):

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='audit-git-regressions-')
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)

    def repository(self, name, algorithm='sha1', bare=False, data=TOKEN):
        root = self.parent / name
        directory = init_repository(root, algorithm, bare)
        identifier = run_git(root, 'hash-object', '-w', '--stdin', data=data).decode().strip()
        return root, directory, identifier

    def collect(self, *roots):
        before = [snapshot(root) for root in roots]
        report, findings = git_secrets.collect([str(root) for root in roots], scan_seconds=10)
        self.assertEqual(before, [snapshot(root) for root in roots])
        for value in (TOKEN.decode(), LITERAL, 'HardcodedSecret123', 'PRIVATE_DIAGNOSTIC'):
            self.assertNotIn(value, json.dumps([report, findings]))
        return report, findings

    def assert_unconfirmed(self, report, findings):
        self.assertEqual(report['status'], 'partial')
        repository = report['repositories'][0]
        self.assertEqual(repository['status'], 'partial')
        self.assertTrue(repository['issues'])
        self.assertNotIn('object_format', repository)
        self.assertFalse(any(scan['mode'] == 'local_objects' for scan in repository['scans']))
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_missing_config_never_claims_complete_sha1_or_sha256_coverage(self):
        for algorithm in ('sha1', 'sha256'):
            for bare in (False, True):
                with self.subTest(algorithm=algorithm, bare=bare):
                    root, directory, identifier = self.repository(algorithm + str(bare), algorithm, bare)
                    healthy, _ = self.collect(root)
                    self.assertEqual(healthy['status'], 'ok')
                    self.assertEqual(healthy['repositories'][0]['detections_found'], 1)
                    (directory / 'config').unlink()
                    self.assertTrue((directory / 'objects' / identifier[:2] / identifier[2:]).exists())
                    with patch.object(git_secrets, 'scan_objects') as objects:
                        report, findings = self.collect(root)
                    objects.assert_not_called()
                    self.assert_unconfirmed(report, findings)

    def test_missing_config_preserves_worktree_findings_and_later_repositories(self):
        root, directory, _ = self.repository('missing', 'sha256')
        (directory / 'config.worktree').write_bytes(b'[example]\n token="' + TOKEN + b'"\n')
        (directory / 'config').unlink()
        later, _, identifier = self.repository('healthy')
        report, findings = self.collect(root, later)
        self.assert_unconfirmed(report, findings)
        self.assertGreater(report['repositories'][0]['detections_found'], 0)
        self.assertEqual(report['repositories'][1]['status'], 'ok')
        found = [item for scan in report['repositories'][1]['scans'] for item in scan['detections']]
        self.assertIn(identifier, {item['object_id'] for item in found})

    def test_unreadable_config_is_unknown_and_does_not_stop_later_repositories(self):
        root, directory, _ = self.repository('denied')
        later, _, _ = self.repository('later')
        read = git_secrets.read_local_file
        def deny_selected(path, maximum):
            if path == directory / 'config':
                raise PermissionError('PRIVATE_DIAGNOSTIC')
            return read(path, maximum)
        with patch.object(git_secrets, 'read_local_file', side_effect=deny_selected):
            report, findings = self.collect(root, later)
        self.assert_unconfirmed(report, findings)
        self.assertEqual(report['repositories'][1]['status'], 'ok')
        self.assertGreater(report['repositories'][1]['detections_found'], 0)

    def test_literal_json_password_starting_with_dollar_is_detected(self):
        root, _, _ = self.repository('literal', data=json.dumps({'password': LITERAL}).encode())
        report, _ = self.collect(root)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['repositories'][0]['detections_found'], 1)

    def test_boolean_forms_preserve_sha1_and_sha256_collection(self):
        for algorithm in ('sha1', 'sha256'):
            root, directory, identifier = self.repository(algorithm, algorithm)
            original = (directory / 'config').read_text()
            for value in (None, '', 'true', 'false'):
                with self.subTest(algorithm=algorithm, value=value):
                    setting = 'worktreeConfig' if value is None else 'worktreeConfig = ' + value
                    (directory / 'config').write_text(original + '[extensions]\n' + setting + '\n')
                    report, findings = self.collect(root)
                    self.assertEqual(report['status'], 'ok', report)
                    self.assertEqual(report['repositories'][0]['object_format'], algorithm)
                    found = [item for scan in report['repositories'][0]['scans'] for item in scan['detections']]
                    self.assertEqual({item['object_id'] for item in found}, {identifier})
                    self.assertFalse(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_invalid_boolean_retains_config_findings_and_later_repositories(self):
        root, _, _ = self.repository('invalid')
        run_git(root, 'config', 'example.token', TOKEN.decode())
        run_git(root, 'config', 'extensions.worktreeConfig', 'PRIVATE_DIAGNOSTIC')
        later, _, _ = self.repository('later')
        report, findings = self.collect(root, later)
        self.assert_unconfirmed(report, findings)
        self.assertGreater(report['repositories'][0]['detections_found'], 0)
        self.assertEqual(report['repositories'][1]['status'], 'ok')

    def test_newline_in_value_cannot_inject_a_storage_format_key(self):
        root, _, _ = self.repository('multiline')
        run_git(root, 'config', 'extensions.partialClone', 'origin\nextensions.objectformat sha256')
        report, findings = self.collect(root)
        self.assertEqual(report['status'], 'partial')  # Partial-clone scope, not a read failure.
        repository = report['repositories'][0]
        self.assertEqual(repository['object_format'], 'sha1')
        self.assertEqual(repository['detections_found'], 1)
        self.assertTrue(all('Partial-clone' in issue for issue in repository['issues']))
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_readable_sha1_config_does_not_require_optional_format_settings(self):
        root, directory, _ = self.repository('ordinary')
        (directory / 'config').write_text('[core]\nbare = false\n')
        report, _ = self.collect(root)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['repositories'][0]['object_format'], 'sha1')
        self.assertEqual(report['repositories'][0]['detections_found'], 1)

    def test_invalid_or_valueless_nonboolean_storage_metadata_stays_unknown(self):
        cases = ['[core]\nrepositoryformatversion\n', '[core]\nrepositoryformatversion =\n',
                 '[extensions]\nobjectformat\n', '[extensions]\nobjectformat =\n',
                 '[extensions]\nobjectformat = "sha1\\nPRIVATE_DIAGNOSTIC"\n',
                 '[extensions]\npartialClone\n', '[extensions]\nrefStorage\n',
                 '[extensions]\nfutureStorage = PRIVATE_DIAGNOSTIC\n']
        for index, config in enumerate(cases):
            with self.subTest(config=config):
                root, directory, _ = self.repository('invalid-' + str(index))
                (directory / 'config').write_text(config)
                report, findings = self.collect(root)
                self.assert_unconfirmed(report, findings)

    def test_ruleset_two_and_partial_coverage_survive_export_without_secrets(self):
        root, directory, _ = self.repository('missing', 'sha256')
        (directory / 'config.worktree').write_bytes(b'[example]\n token="' + TOKEN + b'"\n')
        (directory / 'config').unlink()
        later, _, _ = self.repository('literal', data=json.dumps({'password': LITERAL}).encode())
        check, findings = self.collect(root, later)
        report = {'schema_version': 1, 'host': 'synthetic',
                  'timestamp_utc': '2026-09-17T12:00:00+00:00',
                  'checks': {'git_secrets': check}, 'findings': findings, 'limitations': [],
                  'summary': {level: sum(item['level'] == level for item in findings)
                              for level in ('REVIEW', 'UNKNOWN')}}
        bundle = reporting.export_report(report, self.parent / 'exports')
        exported = json.loads((bundle / 'data/report.json').read_text())
        self.assertEqual(exported, report)
        self.assertEqual(exported['schema_version'], 1)
        self.assertEqual(exported['checks']['git_secrets']['ruleset_version'], 2)
        self.assertEqual(exported['checks']['git_secrets']['status'], 'partial')
        self.assertEqual(json.loads((bundle / 'manifest.json').read_text())['status'], 'complete')
        html = (bundle / 'report.html').read_text()
        self.assertIn('Incomplete', html)
        for output in (json.dumps(exported), html, reporting.render_text(report)):
            self.assertIn('object format is unconfirmed', output)
            for sentinel in (TOKEN.decode(), LITERAL, 'PRIVATE_DIAGNOSTIC'):
                self.assertNotIn(sentinel, output)


if __name__ == '__main__':
    unittest.main()
