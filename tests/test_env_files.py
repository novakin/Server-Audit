import errno
import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit.collectors import env_files
from server_audit import reporting


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

    def test_docker_coverage_distinguishes_absence_failure_and_success_without_relabeling_aggregate(self):
        inspected = {'name': '/web', 'inspection_status': 'ok', 'environment_variable_count': 4,
                     'mounts': [{'type': 'bind', 'source': '/srv/app.env', 'destination': '/app/.env'}]}
        failed = {'id': 'a' * 64, 'inspection_status': 'error', 'detail': 'DO_NOT_COPY_CONTAINER_DETAIL'}
        cases = [
            ({}, 'unavailable', 0, 0, 'presence are unverified'),
            ({'status': 'skipped', 'detail': 'DO_NOT_COPY_DOCKER_DETAIL'}, 'skipped', 0, 0, 'CLI unavailable'),
            ({'status': 'unavailable'}, 'unavailable', 0, 0, 'could not be collected'),
            ({'status': 'error', 'detail': 'DO_NOT_COPY_DOCKER_DETAIL'}, 'partial', 0, 0, 'inventory failed'),
            ({'status': 'error', 'containers': [inspected, failed]}, 'partial', 2, 1, 'lower bound'),
            ({'status': 'ok', 'containers': [inspected, failed]}, 'partial', 2, 1, 'could not be inspected'),
            ({'status': 'ok', 'containers': [inspected]}, 'ok', 1, 1, 'all retained containers'),
            ({'status': 'ok', 'containers': []}, 'ok', 0, 0, 'succeeded with no containers'),
        ]
        for docker, expected_status, retained, successful, explanation in cases:
            with self.subTest(docker=docker):
                checks = {'running_services': {'status': 'ok', 'output': ''}, 'docker': docker}
                result, references = env_files.application_sources(lambda command: self.fail('No systemd units'), checks)
                coverage = result['docker_coverage']
                self.assertEqual(result['status'], 'ok')  # Existing aggregate semantics preserved.
                self.assertEqual(result['docker_status'], docker.get('status', 'unavailable'))
                self.assertEqual(coverage['status'], expected_status)
                self.assertEqual(coverage['containers_retained'], retained)
                self.assertEqual(coverage['containers_inspected'], successful)
                self.assertIn(explanation, coverage['detail'])
                self.assertNotIn('DO_NOT_COPY', json.dumps(result))
                self.assertEqual(len(result['sources']), retained)
                if retained:
                    self.assertEqual(result['sources'][0]['configured_variable_count'], 4)
                    self.assertEqual(references, [{'path': '/srv/app.env', 'optional': False, 'application': 'docker:/web'}])
                if retained > successful:
                    self.assertEqual(result['sources'][-1]['status'], 'error')

    def test_docker_uncertainty_does_not_add_duplicate_findings_to_independent_collection(self):
        for docker in ({'status': 'skipped'}, {'status': 'error'},
                       {'status': 'ok', 'containers': [{'id': 'a' * 64, 'inspection_status': 'error'}]}):
            with self.subTest(docker=docker):
                checks = {'running_services': {'status': 'ok', 'output': ''}, 'docker': docker}
                result, findings = env_files.collect([], lambda command: self.fail('No systemd units'), checks)
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['applications']['status'], 'ok')
                self.assertEqual(findings, [])


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
        for phrase in ('other read bit set', 'world-writable', 'group-writable', 'executable', 'ancestor'):
            self.assertIn(phrase, messages)
        self.assertEqual(result['status'], 'ok')
        file_findings = [item for item in findings if item.get('resource_type') == 'file']
        self.assertEqual([item['resource_id'] for item in file_findings], [str(self.root / '.env')])
        ancestor_findings = [item for item in findings if item.get('resource_type') == 'directory']
        self.assertEqual([item['resource_id'] for item in ancestor_findings], [str(self.root)])
        self.assertTrue(all(item['check'] == 'environment_files' for item in findings))

    def test_read_bits_receive_conditional_advice_without_changing_metadata_or_reading_contents(self):
        for mode in (0o600, 0o640, 0o644):
            with self.subTest(mode=oct(mode)):
                path = self.file(mode=mode)
                expected = env_files.metadata(path)
                with patch('builtins.open', side_effect=AssertionError('Content read')), \
                     patch.object(Path, 'open', side_effect=AssertionError('Content read')):
                    item, findings = env_files.inspect_file(path, {})
                self.assertEqual({key: item[key] for key in expected}, expected)
                self.assertEqual(item['status'], 'inspected')
                messages = '\n'.join(finding['message'] for finding in findings)
                self.assertEqual(len([finding for finding in findings if finding['level'] == 'REVIEW']), 0 if mode == 0o600 else 1)
                if mode != 0o600:
                    self.assertIn('group read bit set', messages)
                    self.assertIn('If confidential values are stored here', messages)
                    self.assertIn('preserving required service access', messages)
                    self.assertIn('Contents were not inspected', messages)
                self.assertEqual('other read bit set' in messages, mode == 0o644)
                self.assertNotIn('world-readable', messages)
                self.assertNotIn('Prefer 0600', messages)

    def test_mixed_modes_preserve_integrity_and_parent_warnings_independent_of_confidentiality(self):
        self.root.chmod(0o770)
        for mode in (0o664, 0o666, 0o620, 0o700, 0o4700):
            with self.subTest(mode=oct(mode)):
                self.file(mode=mode)
                with patch('builtins.open', side_effect=AssertionError('Content read')), \
                     patch.object(Path, 'open', side_effect=AssertionError('Content read')):
                    check, findings = env_files.collect([str(self.root)])
                messages = '\n'.join(finding['message'] for finding in findings)
                self.assertIn('ancestor', messages)
                self.assertEqual(check['files'][0]['mode'], format(mode, '04o'))
                self.assertEqual('If confidential values are stored here' in messages, bool(mode & 0o044))
                if mode & 0o022:
                    self.assertIn('group-writable', messages)
                    self.assertIn('protect file integrity', messages)
                    self.assertIn('trusted writers', messages)
                if mode & 0o002:
                    self.assertIn('world-writable', messages)
                if mode & 0o111:
                    self.assertIn('executable', messages)
                if mode & 0o7000:
                    self.assertIn('special permission bits', messages)
                self.assertNotIn('Prefer 0600', messages)

    def test_root_owned_service_and_template_references_are_not_assumed_non_sensitive(self):
        for name in ('/etc/default/cron', '/etc/default/ssh', '/srv/app/.env.example'):
            with self.subTest(path=name):
                candidate = Path(name)
                def metadata(path):
                    return {'path': str(path), 'mode': '0644' if path == candidate else '0700',
                            'uid': 0, 'gid': 0, 'owner': 'root', 'group': 'root', 'sticky': False,
                            'type': 'file' if path == candidate else 'directory', 'extended_acl': 'absent'}
                with patch.object(env_files, 'metadata', side_effect=metadata), \
                     patch.object(Path, 'is_symlink', return_value=False), \
                     patch('builtins.open', side_effect=AssertionError('Content read')), \
                     patch.object(Path, 'open', side_effect=AssertionError('Content read')):
                    check, findings = self.collect_references(f'{name} (ignore_errors=no)')
                item = check['files'][0]
                self.assertEqual((item['path'], item['owner'], item['mode']), (name, 'root', '0644'))
                self.assertEqual(item['applications'], ['systemd:app.service'])
                self.assertEqual(len(findings), 1)
                self.assertIn('If confidential values are stored here', findings[0]['message'])

    def test_conditional_advice_and_unchanged_inventory_survive_all_report_formats(self):
        self.file('config<fixture>.env', 0o644)
        check, findings = env_files.collect([str(self.root)])
        summary = {level: sum(item['level'] == level for item in findings) for level in ('REVIEW', 'UNKNOWN')}
        self.assertEqual(summary, {'REVIEW': 1, 'UNKNOWN': 0})
        report = {'schema_version': 1, 'host': 'synthetic', 'timestamp_utc': '2026-01-01T12:00:00+00:00',
                  'checks': {'environment_files': check}, 'findings': findings, 'summary': summary, 'limitations': []}
        with tempfile.TemporaryDirectory() as directory:
            folder = reporting.export_report(report, directory)
            self.assertEqual(json.loads((folder / 'data/report.json').read_text()), report)
            html = (folder / 'report.html').read_text()
            self.assertIn('config&lt;fixture&gt;.env', html)
            self.assertIn('If confidential values require restricted readership', html)
            self.assertNotIn('0600 is a common default', html)
        self.assertIn('If confidential values are stored here', reporting.render_text(report))
        self.assertNotIn('secret-test-sentinel', json.dumps(report))

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

    def collect_references(self, value, roots=()):
        checks = {'running_services': {'status': 'ok', 'output': 'app.service loaded active running'},
                  'docker': {'status': 'ok', 'containers': []}}
        return env_files.collect(list(roots),
                                 lambda command: {'status': 'ok', 'output': f'EnvironmentFiles={value}\nMainPID=3'},
                                 checks)

    def test_optional_and_mandatory_wildcards_are_unknown_without_literal_inspection(self):
        self.file('production.env')
        for pattern in ('*.env', 'production.???', '[ap]*.env', 'settings[ab].conf', 'settings[]].conf', 'settings[!]].conf', 'settings[^a].conf'):
            for optional in ('yes', 'no'):
                with self.subTest(pattern=pattern, optional=optional):
                    path = self.root / pattern
                    with patch.object(env_files, 'inspect_file', side_effect=AssertionError('Pattern inspected literally')):
                        report, findings = self.collect_references(f'{path} (ignore_errors={optional})')
                    self.assertEqual(report['status'], 'partial')
                    self.assertEqual(report['applications']['status'], 'partial')
                    source = report['applications']['sources'][0]
                    self.assertEqual(source['status'], 'partial')
                    reference = source['files'][0]
                    self.assertEqual(reference['path'], str(path))
                    self.assertEqual(reference['optional'], optional == 'yes')
                    self.assertEqual(reference['status'], 'unknown')
                    self.assertEqual(report['files'], [])
                    self.assertEqual(report['skipped'][0]['application'], 'systemd:app.service')
                    self.assertEqual(report['skipped'][0]['optional'], optional == 'yes')
                    self.assertIn('not evaluated', report['skipped'][0]['reason'])
                    self.assertTrue(any(item['level'] == 'UNKNOWN' and 'EnvironmentFile reference' in item['message']
                                        and str(path) in item['message'] for item in findings))
                    self.assertTrue(all(item['check'] == 'environment_files' and 'resource_id' not in item
                                        for item in findings))
                    self.assertNotIn('Optional application file absent', json.dumps(report))

    def test_repeated_environment_files_properties_preserve_all_reference_evidence(self):
        literal = self.file('literal.conf')
        values = [f'{self.root}/*.env (ignore_errors=yes)',
                  f'{self.root}/missing-?.env (ignore_errors=no)',
                  f'{literal} (ignore_errors=no)',
                  f'{self.root}/absent-literal (ignore_errors=yes)']
        with patch('builtins.open', side_effect=AssertionError('Content read')), \
             patch.object(Path, 'open', side_effect=AssertionError('Content read')):
            report, findings = self.collect_references('\nEnvironmentFiles='.join(values))
        source = report['applications']['sources'][0]
        self.assertEqual(len(source['files']), 4)
        self.assertEqual(source['status'], 'partial')
        self.assertEqual(report['status'], 'partial')
        self.assertEqual([item['optional'] for item in source['files']], [True, False, False, True])
        self.assertEqual([item['status'] for item in source['files'][:2]], ['unknown', 'unknown'])
        self.assertEqual(report['files'][0]['path'], str(literal))
        self.assertEqual(report['files'][0]['applications'], ['systemd:app.service'])
        absent = next(item for item in report['skipped'] if item['path'].endswith('/absent-literal'))
        self.assertEqual(absent['reason'], 'Optional application file absent')
        self.assertEqual(len([item for item in findings if item['level'] == 'UNKNOWN'
                              and item['message'].startswith('EnvironmentFile reference')]), 2)

    def test_literal_bracket_sequences_retain_metadata_and_application_attribution(self):
        for name in ('settings[.conf', 'settings].conf', 'settings[].conf', 'settings[!].conf', 'settings[^].conf'):
            path = self.file(name)
            for optional in ('yes', 'no'):
                with self.subTest(name=name, optional=optional), \
                     patch('builtins.open', side_effect=AssertionError('Content read')), \
                     patch.object(Path, 'open', side_effect=AssertionError('Content read')):
                    report, findings = self.collect_references(f'{path} (ignore_errors={optional})')
                    self.assertEqual(report['status'], 'ok')
                    self.assertEqual(report['applications']['status'], 'ok')
                    self.assertEqual(report['files'][0]['path'], str(path))
                    self.assertEqual(report['files'][0]['applications'], ['systemd:app.service'])
                    self.assertEqual(report['files'][0]['status'], 'inspected')
                    self.assertEqual(report['skipped'], [])
                    self.assertEqual(findings, [])

    def test_escaped_glob_references_remain_unknown_instead_of_claiming_absence(self):
        path = str(self.root / 'literal\\*.conf')
        with patch.object(env_files, 'inspect_file', side_effect=AssertionError('Unevaluated reference inspected')):
            report, findings = self.collect_references(f'{path} (ignore_errors=yes)')
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['files'], [])
        self.assertIn('Escaped EnvironmentFile reference not evaluated', report['skipped'][0]['reason'])
        self.assertNotIn('Optional application file absent', json.dumps(report))
        self.assertTrue(any(item['level'] == 'UNKNOWN' and 'Escaped EnvironmentFile' in item['message']
                            for item in findings))

    def test_bracket_classes_cannot_span_directory_and_file_components(self):
        directory = self.root / 'dir['
        directory.mkdir(mode=0o700)
        path = self.file('dir[/settings].conf')
        report, findings = self.collect_references(f'{path} (ignore_errors=no)')
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['files'][0]['path'], str(path))
        self.assertEqual(report['files'][0]['applications'], ['systemd:app.service'])
        self.assertEqual(report['skipped'], [])
        self.assertEqual(findings, [])

    def test_independent_discovery_and_literal_references_survive_wildcard_uncertainty(self):
        discovered = self.file('production.env')
        literal = self.file('settings')
        value = f'{self.root}/*.env (ignore_errors=yes) {literal} (ignore_errors=no)'
        with patch('builtins.open', side_effect=AssertionError('Content read')), \
             patch.object(Path, 'open', side_effect=AssertionError('Content read')):
            report, findings = self.collect_references(value, [str(self.root)])
        files = {item['path']: item for item in report['files']}
        self.assertEqual(set(files), {str(discovered), str(literal)})
        self.assertEqual(files[str(literal)]['applications'], ['systemd:app.service'])
        self.assertNotIn('applications', files[str(discovered)])  # No guessed glob/source association.
        self.assertEqual(report['status'], 'partial')
        self.assertNotIn('secret-test-sentinel', json.dumps((report, findings)))

    def test_literal_optional_absence_and_mandatory_failure_stay_distinct(self):
        path = self.root / 'absent.env'
        optional, optional_findings = self.collect_references(f'{path} (ignore_errors=yes)')
        self.assertEqual(optional['status'], 'ok')
        self.assertEqual(optional['skipped'][0]['reason'], 'Optional application file absent')
        self.assertEqual(optional_findings, [])
        mandatory, mandatory_findings = self.collect_references(f'{path} (ignore_errors=no)')
        self.assertEqual(mandatory['status'], 'partial')
        self.assertNotEqual(mandatory['skipped'][0]['reason'], 'Optional application file absent')
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in mandatory_findings))

    def test_docker_bind_path_with_glob_characters_is_still_a_literal_file(self):
        path = self.file('literal*.env')
        checks = {'running_services': {'status': 'ok', 'output': ''},
                  'docker': {'status': 'ok', 'containers': [
                      {'name': '/app', 'inspection_status': 'ok', 'mounts': [
                          {'type': 'bind', 'source': str(path), 'destination': '/app/.env'}]}]}}
        report, findings = env_files.collect([], lambda command: {'status': 'ok', 'output': ''}, checks)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['files'][0]['path'], str(path))
        self.assertEqual(report['files'][0]['applications'], ['docker:/app'])
        self.assertFalse(any('Wildcard' in item['message'] for item in findings))

    def test_independent_discovery_survives_incomplete_docker_references(self):
        path = self.file()
        for docker in ({'status': 'skipped'}, {'status': 'error', 'detail': 'DO_NOT_COPY_DAEMON_DETAIL'},
                       {'status': 'ok', 'containers': [{'id': 'a' * 64, 'inspection_status': 'error',
                                                       'detail': 'DO_NOT_COPY_INSPECT_DETAIL'}]}):
            with self.subTest(docker=docker), \
                 patch('builtins.open', side_effect=AssertionError('Content read')), \
                 patch.object(Path, 'open', side_effect=AssertionError('Content read')):
                checks = {'running_services': {'status': 'ok', 'output': ''}, 'docker': docker}
                result, findings = env_files.collect([str(self.root)], lambda command: self.fail('No systemd units'), checks)
                self.assertEqual(result['status'], 'ok')
                self.assertEqual(result['applications']['status'], 'ok')
                self.assertEqual(result['files'][0]['path'], str(path))
                self.assertNotIn('applications', result['files'][0])
                self.assertEqual(findings, [])
                self.assertNotIn('DO_NOT_COPY', json.dumps(result))
                self.assertNotIn('secret-test-sentinel', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
