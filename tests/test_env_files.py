import errno
import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit.collectors import env_files


class SourceTests(unittest.TestCase):
    def test_candidate_names(self):
        for name in ('.env', '.env.production', '.env.example', 'app.env'):
            self.assertTrue(env_files.is_env_name(name))
        self.assertFalse(env_files.is_env_name('environment.py'))

    def test_systemd_metadata_paths_and_optional_flags(self):
        entries = env_files.parse_environment_files('/etc/default/app (ignore_errors=yes) /srv/my\\x20app/config (ignore_errors=no)')
        self.assertEqual(entries, [{'path': '/etc/default/app', 'optional': True}, {'path': '/srv/my app/config', 'optional': False}])
        with self.assertRaises(ValueError):
            env_files.parse_environment_files('unexpected metadata')

    def test_sources_do_not_request_environment_values(self):
        calls = []
        def run(command):
            calls.append(command)
            return {'status': 'ok', 'output': 'MainPID=123\nEnvironmentFiles=/etc/default/app (ignore_errors=yes)'}
        checks = {'running_services': {'status': 'ok', 'output': 'app.service loaded active running App'},
                  'docker': {'status': 'ok', 'containers': [{'name': '/web', 'inspection_status': 'ok', 'environment_variable_count': 4, 'mounts': [{'type': 'bind', 'source': '/srv/config/secret', 'destination': '/app/.env', 'writable': False}]}]}}
        result, references = env_files.application_sources(run, checks)
        self.assertEqual(len(references), 2)
        self.assertEqual(result['sources'][1]['configured_variable_count'], 4)
        self.assertIn('--property=EnvironmentFiles', calls[0])
        self.assertNotIn('--property=Environment', calls[0])


@unittest.skipUnless(platform.system() == 'Linux', 'Linux permissions and xattrs')
class MetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def file(self, name='.env', mode=0o600):
        path = self.root / name
        path.write_text('DO_NOT_READ=secret-test-sentinel')
        path.chmod(mode)
        return path

    def test_contents_never_opened_and_private_file_not_flagged(self):
        self.file()
        with patch('builtins.open', side_effect=AssertionError('Content read')), patch.object(Path, 'open', side_effect=AssertionError('Content read')):
            result, findings = env_files.collect([str(self.root)])
        self.assertEqual(result['files'][0]['mode'], '0600')
        self.assertNotIn('secret-test-sentinel', json.dumps(result))
        self.assertFalse(any(item['level'] == 'REVIEW' for item in findings))

    def test_modes_and_parent_write_access(self):
        self.file(mode=0o777)
        self.root.chmod(0o770)
        result, findings = env_files.collect([str(self.root)])
        messages = '\n'.join(item['message'] for item in findings)
        for phrase in ('world-readable', 'world-writable', 'group-writable', 'executable', 'ancestor'):
            self.assertIn(phrase, messages)
        self.assertEqual(result['status'], 'ok')

    def test_symlinks_and_fifos_not_followed(self):
        self.file('private')
        (self.root / '.env').symlink_to(self.root / 'private')
        os.mkfifo(self.root / 'pipe.env')
        result, findings = env_files.collect([str(self.root)])
        self.assertEqual(len(result['files']), 2)
        self.assertTrue(all(item['status'] == 'skipped' for item in result['files']))
        self.assertEqual(len([item for item in findings if item['level'] == 'UNKNOWN']), 2)

    def test_acl_presence_and_denial_are_not_clean_results(self):
        path = self.file()
        with patch('server_audit.collectors.env_files.os.getxattr', return_value=b'ACL metadata'):
            item, findings = env_files.inspect_file(path, {})
            self.assertEqual(item['extended_acl'], 'present')
            self.assertTrue(any('extended ACL' in finding['message'] for finding in findings))
        with patch('server_audit.collectors.env_files.os.getxattr', side_effect=OSError(errno.EACCES, 'denied')):
            item, findings = env_files.inspect_file(path, {})
            self.assertEqual(item['extended_acl'], 'unknown')
            self.assertTrue(any(finding['level'] == 'UNKNOWN' for finding in findings))

    def test_budget_and_missing_root_are_explicit(self):
        self.file()
        with patch('server_audit.collectors.env_files.MAX_ENTRIES', 0):
            result, findings = env_files.collect([str(self.root)])
            self.assertEqual(result['status'], 'partial')
            self.assertTrue(findings)
        result, findings = env_files.collect([str(self.root / 'missing')])
        self.assertEqual(result['status'], 'partial')

    def test_application_file_without_env_suffix_is_inspected_once(self):
        path = self.file('settings')
        def run(command):
            return {'status': 'ok', 'output': f'EnvironmentFiles={path} (ignore_errors=no)\nMainPID=3'}
        checks = {'running_services': {'status': 'ok', 'output': 'app.service loaded active running'}}
        report, findings = env_files.collect([str(self.root)], run, checks)
        self.assertEqual(len(report['files']), 1)
        self.assertEqual(report['files'][0]['applications'], ['systemd:app.service'])


if __name__ == '__main__':
    unittest.main()
