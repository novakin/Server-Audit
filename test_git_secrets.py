"""Built-in rules and real disposable Git stores; no external targets or live secrets."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import git_reader
import git_secrets


TOKEN = 'ghp_' + 'Ab3dEf7hIj9kLm2nOp4qRs6tUv8wXy0zABCD'
TOKEN = TOKEN[:4] + (TOKEN[4:] + 'EFGH')[:36]


class RuleTests(unittest.TestCase):
    def matches(self, value):
        return list(git_secrets.detections(value, 'config', 'configuration', None, time.monotonic() + 5))

    def test_supported_rule_families_and_redaction(self):
        fixtures = {
            'private-key': '-----BEGIN OPENSSH PRIVATE KEY-----',
            'github-token': TOKEN,
            'gitlab-token': 'glpat-' + 'Ab9_' * 6,
            'aws-access-key-id': 'AKIA' + 'A1B2' * 4,
            'slack-token': 'xoxb-1234567890-abcdef1234567890',
            'credential-in-url': 'https://alice:PrivateSentinel42@example.invalid/repo',
            'authorization-header': 'AUTHORIZATION: Basic UHJpdmF0ZVNlbnRpbmVsNDI=',
            'credential-assignment': 'AWS_SECRET_ACCESS_KEY="PrivateSentinel42"',
        }
        for expected, value in fixtures.items():
            with self.subTest(rule=expected):
                matches = self.matches(value.encode())
                self.assertIn(expected, {item['rule'] for item in matches})
                self.assertNotIn(value, json.dumps(matches))
                self.assertNotIn('PrivateSentinel42', json.dumps(matches))

    def test_placeholders_and_environment_references_are_not_literal_credentials(self):
        values = ['password="changeme"', 'password="${PRIVATE_PASSWORD}"',
                  'api_key="your_api_key"', 'secret=process.env.SECRET_KEY',
                  'password=os.environ.get("PASSWORD")', 'password="{{ password }}"']
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(self.matches(value.encode()), [])

    def test_line_and_byte_locations_without_content(self):
        data = b'# synthetic\npassword="PrivateSentinel42"\n'
        found = self.matches(data)
        self.assertEqual(found[0]['start_line'], 2)
        self.assertEqual(found[0]['byte_offset'], len(b'# synthetic\n'))
        self.assertNotIn('PrivateSentinel42', json.dumps(found))

    def test_known_tokens_do_not_honor_allow_comments(self):
        found = self.matches((TOKEN + ' # gitleaks:allow\n').encode())
        self.assertIn('github-token', {item['rule'] for item in found})

    def test_not_requested_never_looks_for_an_executable(self):
        with patch('git_secrets.shutil.which') as which:
            report, findings = git_secrets.collect()
        which.assert_not_called()
        self.assertEqual(report['status'], 'not_requested')
        self.assertEqual(report['detector'], 'builtin')
        self.assertEqual(findings, [])

    def test_missing_git_is_unavailable_not_a_clean_scan(self):
        with patch('git_secrets.shutil.which', return_value=None) as which:
            report, findings = git_secrets.collect(['/fixture/repository'])
        which.assert_called_once_with('git')
        self.assertEqual(report['status'], 'unavailable')
        self.assertEqual(report['requested_roots'], ['/fixture/repository'])
        self.assertEqual(findings, [])  # The runner supplies the common unavailable finding.

    def test_scan_budget_validation(self):
        for value in (0, -1, float('nan'), float('inf'), 3601, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                git_secrets.scan_seconds_value(value)
        self.assertEqual(git_secrets.scan_seconds_value('60'), 60)

    def test_malformed_protocol_headers_are_rejected_without_echo(self):
        for header in (None, b'PRIVATE_SENTINEL', b'f' * 40 + b' blob -2',
                       b'f' * 40 + b' surprise 5', b'f' * 39 + b' blob 5'):
            with self.subTest(header=header), self.assertRaises(git_reader.GitReadError) as caught:
                git_secrets.object_header(header, 40)
            self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Requires local Git and POSIX pipes')
class LocalGitTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name)
        self.root = self.parent / 'repository'
        self.root.mkdir()
        self.env = git_reader.environment(self.parent)
        self.git('init', '--quiet')
        self.git('config', 'user.name', 'Audit fixture')
        self.git('config', 'user.email', 'audit@example.invalid')

    def git(self, *args, data=None):
        result = subprocess.run(
            ['git', '-c', 'commit.gpgsign=false', '-C', str(self.root), *args],
            input=data, capture_output=True, env=self.env, check=True,
        )
        return result.stdout.decode().strip()

    def commit_file(self, name='settings.py', content=None):
        path = self.root / name
        path.write_text(content or 'API_KEY="' + TOKEN + '"\n')
        self.git('add', '--', name)
        self.git('commit', '--quiet', '-m', 'Synthetic fixture')
        return self.git('rev-parse', 'HEAD:' + name)

    def collect(self, *roots, **kwargs):
        return git_secrets.collect(list(roots) or [str(self.root)], **kwargs)

    def found(self, report):
        return [item for repo in report['repositories'] for scan in repo['scans'] for item in scan['detections']]

    def assert_private(self, report, findings, *values):
        rendered = json.dumps([report, findings])
        for value in (TOKEN, *values):
            self.assertNotIn(value, rendered)

    def test_deleted_historical_secret_remains_detectable(self):
        identifier = self.commit_file()
        self.git('rm', '--quiet', 'settings.py')
        self.git('commit', '--quiet', '-m', 'Remove synthetic file')
        report, findings = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertIn(identifier, {item['object_id'] for item in self.found(report)})
        self.assertFalse((self.root / 'settings.py').exists())
        self.assert_private(report, findings)

    def test_packed_delta_history_is_read(self):
        identifiers = []
        for number in range(6):
            content = ('benign line ' + 'x' * 80 + '\n') * 300
            content += 'API_KEY="' + TOKEN + '"\nrevision=' + str(number) + '\n'
            identifiers.append(self.commit_file(content=content))
        self.git('gc', '--prune=now', '--quiet')
        self.assertTrue(list((self.root / '.git/objects/pack').glob('*.pack')))
        indexes = list((self.root / '.git/objects/pack').glob('*.idx'))
        verified = self.git('verify-pack', '-v', str(indexes[0]))
        self.assertTrue(any(len(line.split()) == 7 for line in verified.splitlines()), 'Fixture must contain deltas')
        report, findings = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertTrue(set(identifiers) <= {item['object_id'] for item in self.found(report)})
        self.assert_private(report, findings)

    def test_unreachable_loose_object_is_inspected(self):
        identifier = self.git('hash-object', '-w', '--stdin', data=TOKEN.encode())
        report, findings = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertIn(identifier, {item['object_id'] for item in self.found(report)})
        self.assert_private(report, findings)

    def test_configuration_credentials_are_redacted(self):
        self.git('config', 'remote.origin.url', 'https://alice:PrivateSentinel42@example.invalid/repo')
        self.git('config', 'http.extraHeader', 'Authorization: Bearer PrivateSentinel42')
        report, findings = self.collect()
        rules = {item['rule'] for item in self.found(report)}
        self.assertTrue({'credential-in-url', 'authorization-header'} <= rules)
        self.assertTrue(all(item['file'] == 'config' for item in self.found(report)))
        self.assert_private(report, findings, 'PrivateSentinel42')

    def test_commit_and_tag_text_is_inspected_without_exporting_messages(self):
        self.commit_file(content='benign\n')
        self.git('commit', '--allow-empty', '--quiet', '-m', 'Fixture ' + TOKEN)
        self.git('tag', '-a', 'fixture-tag', '-m', 'Fixture ' + TOKEN)
        report, findings = self.collect()
        found = [item for item in self.found(report) if item['rule'] == 'github-token']
        self.assertEqual({item['object_type'] for item in found}, {'commit', 'tag'})
        for item in found:
            self.assertEqual(item['commit'], item['object_id'] if item['object_type'] == 'commit' else '')
        self.assert_private(report, findings)

    def test_working_files_are_outside_the_selected_git_storage_scope(self):
        (self.root / '.env').write_text('TOKEN=' + TOKEN)
        (self.root / 'untracked.py').write_text(TOKEN)
        report, findings = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertEqual(self.found(report), [])
        self.assertEqual(findings, [])

    def test_empty_repository_has_successful_empty_object_inventory(self):
        report, _ = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        scan = report['repositories'][0]['scans'][1]
        self.assertEqual(scan['objects_seen'], 0)
        self.assertEqual(scan['objects_scanned'], 0)

    def test_explicit_git_directory_and_duplicate_roots_scan_once(self):
        self.commit_file()
        with patch('git_secrets.scan_repository', wraps=git_secrets.scan_repository) as scan:
            report, _ = self.collect(str(self.root), str(self.root / '.git'), str(self.root))
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(len(report['repositories']), 1)

    def test_bare_repository_is_supported(self):
        self.root = self.parent / 'bare.git'
        self.root.mkdir()
        self.git('init', '--bare', '--quiet')
        identifier = self.git('hash-object', '-w', '--stdin', data=TOKEN.encode())
        report, _ = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertIn(identifier, {item['object_id'] for item in self.found(report)})

    def test_sha256_repository_is_supported(self):
        self.root = self.parent / 'sha256'
        self.root.mkdir()
        self.git('init', '--quiet', '--object-format=sha256')
        identifier = self.git('hash-object', '-w', '--stdin', data=TOKEN.encode())
        report, _ = self.collect()
        self.assertEqual(report['status'], 'ok', report)
        self.assertEqual(report['repositories'][0]['object_format'], 'sha256')
        self.assertEqual(len(identifier), 64)
        self.assertIn(identifier, {item['object_id'] for item in self.found(report)})

    def test_alternates_are_rejected_without_reader_execution(self):
        (self.root / '.git/objects/info/alternates').write_text(str(self.parent / 'outside'))
        with patch('git_secrets.GitProcess') as reader:
            report, findings = self.collect()
        reader.assert_not_called()
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_symlink_and_special_object_storage_are_rejected(self):
        target = self.parent / 'outside'
        target.write_text(TOKEN)
        link = self.root / '.git/objects/linked'
        link.symlink_to(target)
        report, _ = self.collect()
        self.assertEqual(report['status'], 'partial')
        link.unlink()
        os.mkfifo(link)
        report, _ = self.collect()
        self.assertEqual(report['status'], 'partial')

    def test_repository_symlink_gitfile_and_commondir_are_rejected(self):
        link = self.parent / 'linked'
        link.symlink_to(self.root, target_is_directory=True)
        report, _ = self.collect(str(link))
        self.assertEqual(report['status'], 'partial')
        worktree = self.parent / 'worktree'
        worktree.mkdir()
        (worktree / '.git').write_text('gitdir: ' + str(self.root / '.git'))
        report, _ = self.collect(str(worktree))
        self.assertEqual(report['status'], 'partial')
        (self.root / '.git/commondir').write_text(str(self.parent / 'outside'))
        report, _ = self.collect()
        self.assertEqual(report['status'], 'partial')

    def test_config_includes_and_inherited_execution_settings_are_not_used(self):
        outside = self.parent / 'outside.conf'
        outside.write_text('[remote "private"]\nurl=https://alice:OutsideSentinel42@example.invalid\n')
        marker = self.parent / 'executed'
        self.commit_file()
        self.git('config', 'include.path', str(outside))
        self.git('config', 'core.fsmonitor', 'touch ' + str(marker))
        self.git('config', 'core.sshCommand', 'touch ' + str(marker))
        self.assertFalse(marker.exists())
        with patch.dict(os.environ, {'GIT_TRACE': str(marker), 'GIT_CONFIG_COUNT': '1',
                                    'GIT_CONFIG_KEY_0': 'core.fsmonitor', 'GIT_CONFIG_VALUE_0': 'touch ' + str(marker)}):
            report, findings = self.collect()
        self.assertFalse(marker.exists())
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(self.found(report))
        self.assert_private(report, findings, 'OutsideSentinel42')

    def test_partial_clone_remotes_are_not_invoked(self):
        self.commit_file()
        marker = self.parent / 'remote-executed'
        helper = self.parent / 'git-remote-auditfixture'
        helper.write_text('#!/bin/sh\ntouch ' + str(marker) + '\nexit 1\n')
        helper.chmod(0o700)
        self.git('config', 'core.repositoryformatversion', '1')
        self.git('config', 'extensions.partialClone', 'origin')
        self.git('config', 'remote.origin.promisor', 'true')
        self.git('config', 'remote.origin.url', 'auditfixture::never-contact')
        with patch.dict(os.environ, {'PATH': str(self.parent) + os.pathsep + os.environ['PATH']}):
            report, findings = self.collect()
        self.assertFalse(marker.exists())
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(self.found(report))
        self.assert_private(report, findings)

    def test_oversized_objects_are_skipped_before_content_requests(self):
        identifier = self.git('hash-object', '-w', '--stdin', data=b'x' * 1024 + TOKEN.encode())
        with patch('git_secrets.MAX_OBJECT_BYTES', 100):
            report, _ = self.collect()
        scan = report['repositories'][0]['scans'][1]
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(scan['oversized_objects'], 1)
        self.assertEqual(scan['bytes_read'], 0)
        self.assertNotIn(identifier, {item['object_id'] for item in self.found(report)})

    def test_count_and_total_byte_limits_preserve_config_findings(self):
        self.commit_file()
        self.git('config', 'remote.origin.url', 'https://alice:PrivateSentinel42@example.invalid/repo')
        for constant in ('MAX_OBJECTS', 'MAX_TOTAL_BYTES', 'MAX_STORAGE_ENTRIES'):
            with self.subTest(limit=constant), patch.object(git_secrets, constant, 0):
                report, findings = self.collect()
                self.assertEqual(report['status'], 'partial')
                self.assertIn('credential-in-url', {item['rule'] for item in self.found(report)})
                self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
                self.assert_private(report, findings, 'PrivateSentinel42')

    def test_detection_limit_retains_only_bounded_findings(self):
        self.git('config', 'remote.origin.url', 'https://alice:PrivateSentinel42@example.invalid/repo')
        self.git('config', 'http.extraHeader', 'Authorization: Bearer PrivateSentinel42')
        with patch('git_secrets.MAX_DETECTIONS', 1):
            report, findings = self.collect()
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(len(self.found(report)), 1)
        self.assert_private(report, findings, 'PrivateSentinel42')

    def test_metadata_limit_and_access_error_are_not_clean(self):
        with patch('git_secrets.MAX_CONFIG_BYTES', 1):
            report, _ = self.collect()
        self.assertEqual(report['status'], 'partial')
        with patch('git_secrets.read_local_file', side_effect=PermissionError('PRIVATE_SENTINEL')):
            report, findings = self.collect()
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_expired_budget_stops_without_starting_git(self):
        with patch('git_secrets.GitProcess') as reader:
            report, findings = self.collect(scan_seconds=1e-12)
        reader.assert_not_called()
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(findings)

    def test_bad_repository_does_not_prevent_next_repository(self):
        self.commit_file()
        report, findings = self.collect(str(self.parent / 'missing'), str(self.root))
        self.assertEqual([item['status'] for item in report['repositories']], ['error', 'ok'])
        self.assertTrue(self.found(report))
        self.assert_private(report, findings)

    def test_corrupt_loose_object_is_unknown_without_raw_diagnostics(self):
        identifier = self.git('hash-object', '-w', '--stdin', data=TOKEN.encode())
        (self.root / '.git/objects' / identifier[:2] / identifier[2:]).write_bytes(b'PRIVATE_SENTINEL')
        report, findings = self.collect()
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_unknown_storage_extension_is_not_assumed_supported(self):
        self.git('config', 'core.repositoryformatversion', '1')
        self.git('config', 'extensions.futureStorage', 'PRIVATE_SENTINEL')
        report, findings = self.collect()
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_read_only_source_and_no_payload_workspace(self):
        self.commit_file()
        directory = self.root / '.git'
        before = {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob('*') if path.is_file()}
        report, findings = self.collect()
        after = {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assert_private(report, findings)

    def test_programming_errors_are_not_silently_converted_to_scan_results(self):
        with patch('git_secrets.inspect_storage', side_effect=TypeError('programming defect')):
            with self.assertRaises(TypeError):
                self.collect()


if __name__ == '__main__':
    unittest.main()
