"""Git scanner corrections: synthetic values and disposable repositories only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from server_audit import reporting
from server_audit.collectors import git_reader, git_secrets


TOKEN = b'ghp_' + b'Ab12' * 9
LITERAL = '$uperSecret123!'


class ReferenceRegressionTests(unittest.TestCase):
    def matches(self, assignment):
        return list(git_secrets.detections(assignment.encode(), 'config', 'configuration',
                                          None, time.monotonic() + 5))

    def assert_candidate(self, assignment):
        found = self.matches(assignment)
        self.assertIn('credential-assignment', {item['rule'] for item in found})
        self.assertNotIn('HardcodedSecret123', json.dumps(found))
        self.assertNotIn(LITERAL, json.dumps(found))

    def test_literal_prefixes_and_quoted_code_are_candidates(self):
        for value in (LITERAL, '$UnbracedLiteral123', '<PrivateLiteral123>', '%(PrivateLiteral123)',
                      '{{unfinishedSecret123', 'os.environ.PrivateLiteral123',
                      'os.getenv.PrivateLiteral123', 'process.env.SECRET_KEY'):
            with self.subTest(value=value):
                self.assert_candidate(json.dumps({'password': value}))

    def test_complete_references_and_exact_placeholders_stay_excluded(self):
        cases = ['password="${PRIVATE_PASSWORD}"', 'password="{{ password }}"',
                 'password="changeme"', 'api_key="your_api_key"',
                 'secret=process.env.SECRET_KEY', 'password=os.environ.get("PASSWORD")',
                 "password=os.environ['PASSWORD']", 'password=os.environ.get("PASSWORD"); # comment',
                 'secret=process.env.SECRET_KEY; // comment', '{"password":"${PRIVATE_PASSWORD}"}']
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assertEqual(self.matches(assignment), [])

    def test_literal_fallbacks_and_concatenation_are_not_excluded(self):
        cases = ['password="${PASSWORD:-HardcodedSecret123!}"',
                 'password="${PASSWORD-HardcodedSecret123!}"',
                 'password="{{ password | default(123456789) }}"',
                 'password=os.environ.get("PASSWORD", "HardcodedSecret123!")',
                 'secret=process.env.SECRET_KEY || "HardcodedSecret123!"',
                 'secret=process.env.SECRET_KEY + "HardcodedSecret123!"',
                 'password="${PRIVATE_PASSWORD}" + "HardcodedSecret123!"',
                 'password="${PRIVATE_PASSWORD}"HardcodedSecret123!']
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assert_candidate(assignment)

    def test_truncated_and_ambiguous_expression_prefixes_remain_candidates(self):
        cases = ['password=os.environ.get', 'password=os.environ.getExtraSecret123',
                 'secret=process.env.', 'secret=process.env.' + 'A' * 300,
                 'secret=process.env.SECRET_KEY' + ' ' * 257 + '|| "HardcodedSecret123!"',
                 'password="${PRIVATE_PASSWORD}"' + ' ' * 257 + '+ "HardcodedSecret123!"']
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assert_candidate(assignment)

    def test_ruleset_version_changes_without_changing_rule_ids_or_limits(self):
        report, findings = git_secrets.collect()
        self.assertEqual(report['ruleset_version'], 2)
        self.assertEqual(report['status'], 'not_requested')
        self.assertEqual(findings, [])
        self.assertEqual(len(report['rule_ids']), 8)
        with patch.object(git_secrets.shutil, 'which', return_value=None):
            unavailable, _ = git_secrets.collect(['/fixture/repo'])
        self.assertEqual(unavailable['ruleset_version'], 2)
        self.assertEqual(unavailable['status'], 'unavailable')
        self.assertEqual(unavailable['limits'], report['limits'])
        self.assertEqual(unavailable['rule_ids'], report['rule_ids'])


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Requires local Git and POSIX pipes')
class StorageRegressionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='audit-git-regressions-')
        self.addCleanup(temporary.cleanup)
        self.parent = Path(temporary.name)
        self.executable = shutil.which('git')
        self.environment = git_reader.environment(self.parent)

    def git(self, root, *arguments, data=None):
        return subprocess.run([self.executable, '-C', str(root), *arguments], input=data,
                              env=self.environment, capture_output=True, check=True, timeout=10).stdout

    def repository(self, name, algorithm='sha1', bare=False, data=TOKEN):
        root = self.parent / name
        root.mkdir()
        args = ['init', '--quiet', '--object-format=' + algorithm]
        if bare:
            args.append('--bare')
        self.git(root, *args)
        identifier = self.git(root, 'hash-object', '-w', '--stdin', data=data).decode().strip()
        return root, root if bare else root / '.git', identifier

    def snapshot(self, root):
        return {str(path.relative_to(root)): path.read_bytes()
                for path in root.rglob('*') if path.is_file()}

    def collect(self, *roots):
        before = [self.snapshot(root) for root in roots]
        report, findings = git_secrets.collect([str(root) for root in roots], scan_seconds=10)
        self.assertEqual(before, [self.snapshot(root) for root in roots])
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

    def test_git_boolean_spellings_do_not_block_sha1_or_sha256_objects(self):
        spellings = [None, '', 'true', 'false', 'TRUE', 'yes', 'no', 'on', 'off', '0', '1', '2', '-1']
        for algorithm in ('sha1', 'sha256'):
            root, directory, identifier = self.repository(algorithm, algorithm)
            original = (directory / 'config').read_text()
            for value in spellings:
                with self.subTest(algorithm=algorithm, value=value):
                    setting = 'worktreeConfig' if value is None else 'worktreeConfig = ' + value
                    (directory / 'config').write_text(original + '[extensions]\n' + setting + '\n')
                    native = self.git(root, 'config', '--type=bool', '--get', 'extensions.worktreeconfig')
                    expected = b'false\n' if value in ('', 'false', 'no', 'off', '0') else b'true\n'
                    self.assertEqual(native, expected)
                    self.assertIn(identifier.encode(), self.git(root, 'cat-file', '--batch-all-objects', '--batch-check'))
                    report, findings = self.collect(root)
                    self.assertEqual(report['status'], 'ok', report)
                    self.assertEqual(report['repositories'][0]['object_format'], algorithm)
                    self.assertEqual(report['repositories'][0]['detections_found'], 1)
                    self.assertFalse(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_invalid_boolean_retains_config_findings_and_later_repositories(self):
        root, _, _ = self.repository('invalid')
        self.git(root, 'config', 'example.token', TOKEN.decode())
        self.git(root, 'config', 'extensions.worktreeConfig', 'PRIVATE_DIAGNOSTIC')
        later, _, _ = self.repository('later')
        report, findings = self.collect(root, later)
        self.assert_unconfirmed(report, findings)
        self.assertGreater(report['repositories'][0]['detections_found'], 0)
        self.assertEqual(report['repositories'][1]['status'], 'ok')

    def test_newline_in_value_cannot_inject_a_storage_format_key(self):
        root, _, _ = self.repository('multiline')
        self.git(root, 'config', 'extensions.partialClone', 'origin\nextensions.objectformat sha256')
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

    def test_truncated_protocol_or_empty_records_are_rejected_without_payloads(self):
        for data in (b'PRIVATE_DIAGNOSTIC', b'\0', b'core.repositoryformatversion\n0\0\0'):
            with self.subTest(data=data), git_reader.repository_view() as view:
                with patch.object(git_reader, 'GitProcess') as factory:
                    factory.return_value.__enter__.return_value.all.return_value = data
                    with self.assertRaises(git_reader.GitReadError) as caught:
                        git_reader.object_format(self.executable, view, view / 'config', time.monotonic() + 5)
                self.assertNotIn('PRIVATE_DIAGNOSTIC', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
