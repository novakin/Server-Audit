import json
import os
import platform
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server_audit.collectors import accounts
from server_audit.command_runner import run
from server_audit.reporting import account_text_report


class UsageTests(unittest.TestCase):
    def test_only_successful_publickey_events_are_matched(self):
        messages = [
            'Accepted publickey for alice from 192.0.2.1 port 4000 ssh2: ED25519 SHA256:abcd',
            'Failed publickey for alice from 192.0.2.1 port 4000 ssh2: ED25519 SHA256:abcd',
            'Accepted password for bob from 192.0.2.2 port 4000 ssh2',
        ]
        output = '\n'.join(json.dumps({'MESSAGE': message, '__REALTIME_TIMESTAMP': '1700000000000000'}) for message in messages)
        events = accounts.login_events(output + '\ninvalid JSON\n[]')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['fingerprint'], 'SHA256:abcd')
        self.assertEqual(events[0]['user'], 'alice')
        self.assertEqual(events[0]['timestamp'], '2023-11-14T22:13:20+00:00')

    def test_missing_history_does_not_invent_usage(self):
        self.assertEqual(accounts.login_events(''), [])


@unittest.skipUnless(platform.system() == 'Linux', 'Linux ownership and OpenSSH integration')
class KeyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.home = Path(self.directory.name)

    def test_permissions(self):
        self.home.chmod(0o777)
        self.assertTrue(accounts.permission_info(self.home, os.getuid())['unsafe'])
        self.home.chmod(0o700)
        self.assertFalse(accounts.permission_info(self.home, os.getuid())['unsafe'])

    def test_symlinks_and_special_files_are_not_read(self):
        target = self.home / 'target'
        target.write_text('sensitive content')
        link = self.home / 'authorized_keys'
        link.symlink_to(target)
        self.assertEqual(accounts.key_inventory(link, run)['status'], 'unknown')
        fifo = self.home / 'fifo'
        os.mkfifo(fifo)
        self.assertEqual(accounts.key_inventory(fifo, run)['status'], 'unknown')

    def test_absent_file_and_invalid_key(self):
        path = self.home / 'authorized_keys'
        self.assertEqual(accounts.key_inventory(path, run)['status'], 'absent')
        path.write_text('# ignored\nssh-ed25519 invalid\n')
        inventory = accounts.key_inventory(path, run)
        self.assertEqual(inventory['keys'][0]['line'], 2)
        self.assertIn('unknown', inventory['keys'][0])

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'Requires installed OpenSSH client')
    def test_real_openssh_key_options_comments_and_usage(self):
        private = self.home / 'test-key'
        generated = run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(private)])
        self.assertEqual(generated['status'], 'ok', generated)
        public = private.with_suffix('.pub').read_text().split()
        key_directory = self.home / '.ssh'
        key_directory.mkdir(mode=0o700)
        path = key_directory / 'authorized_keys'
        path.write_text('command="echo hello, world",no-pty ' + ' '.join(public[:2]) + ' comment with unmatched " quote\n')
        inventory = accounts.key_inventory(path, run)
        key = inventory['keys'][0]
        self.assertNotIn('unknown', key, inventory)
        self.assertTrue(key['options_present'])
        self.assertIsNone(key['last_observed_use'])
        self.assertNotIn(public[1], json.dumps(inventory))
        native = run(['ssh-keygen', '-l', '-E', 'sha256', '-f', str(private.with_suffix('.pub'))])
        self.assertIn(key['fingerprint'], native['output'])

        def fake_run(command, input_text=None):
            if command[0] == 'ssh-keygen':
                return run(command, input_text)
            output = ''
            if command[0] == 'journalctl':
                output = json.dumps({'MESSAGE': f"Accepted publickey for alice from 192.0.2.1 port 42 ssh2: ED25519 {key['fingerprint']}", '__REALTIME_TIMESTAMP': '1700000000000000'})
            if command[0] == 'passwd':
                output = command[-1] + ' L 2024-01-01 0 99999 7 -1'
            return {'status': 'ok', 'output': output, 'detail': ''}

        users = [SimpleNamespace(pw_name=name, pw_uid=os.getuid(), pw_gid=os.getgid(), pw_dir=str(self.home), pw_shell='/bin/bash') for name in ('alice', 'bob')]
        with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=[]):
            report, findings = accounts.collect(fake_run, 'authorizedkeysfile .ssh/authorized_keys')
        alice, bob = report['accounts']
        self.assertIsNotNone(alice['key_files'][0]['keys'][0]['last_observed_use'])
        self.assertIsNone(bob['key_files'][0]['keys'][0]['last_observed_use'])
        self.assertTrue(any('shared across accounts' in item['message'] for item in findings))
        self.assertEqual(alice['password_state']['output'].split()[1], 'L')
        text = account_text_report(report)
        self.assertIn('last observed use=unknown', text)
        self.assertNotIn(public[1], text)


if __name__ == '__main__':
    unittest.main()
