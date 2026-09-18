import json
import os
import platform
import shutil
import stat
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
        ordinary_file = self.home / 'ordinary-file'
        ordinary_file.touch()
        for path in (self.home, ordinary_file):
            for mode, unsafe in ((0o700, False), (0o720, True), (0o702, True)):
                with self.subTest(path=path.name, mode=oct(mode)):
                    path.chmod(mode)
                    permission = accounts.permission_info(path, os.getuid())
                    self.assertEqual(permission['unsafe'], unsafe)
                    self.assertFalse(permission['symlink'])
                    self.assertNotIn('unknown', permission)

    def test_link_metadata_does_not_assess_private_writable_or_missing_targets(self):
        target = self.home / 'target-directory'
        link = self.home / 'home-link'
        link.symlink_to(target, target_is_directory=True)
        for mode in (None, 0o700, 0o777):
            with self.subTest(target_mode=mode):
                if mode is not None:
                    target.mkdir(exist_ok=True)
                    target.chmod(mode)
                permission = accounts.permission_info(link, os.getuid())
                self.assertEqual(permission['mode'], '0o777')
                self.assertEqual(permission['owner_uid'], os.getuid())
                self.assertTrue(permission['symlink'])
                self.assertFalse(permission['unsafe'])
                self.assertIn('target permissions not inspected', permission['unknown'])

    def test_ownership_checks_still_apply_to_links_and_ordinary_paths(self):
        path = self.home / 'metadata-fixture'
        for kind in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK):
            mode = kind | (0o777 if kind == stat.S_IFLNK else 0o700)
            for owner, unsafe in ((0, False), (1001, False), (1002, True)):
                with self.subTest(kind=kind, owner=owner):
                    info = SimpleNamespace(st_mode=mode, st_uid=owner)
                    with patch.object(Path, 'lstat', return_value=info):
                        permission = accounts.permission_info(path, 1001)
                    self.assertEqual(permission['owner_uid'], owner)
                    self.assertEqual(permission['unsafe'], unsafe)
                    self.assertEqual('unknown' in permission, kind == stat.S_IFLNK)

    def test_missing_and_unreadable_permissions_remain_unknown(self):
        path = self.home / 'missing'
        permission = accounts.permission_info(path, os.getuid())
        self.assertEqual(permission['path'], str(path))
        self.assertIn('unknown', permission)
        self.assertNotIn('unsafe', permission)
        with patch.object(Path, 'lstat', side_effect=PermissionError('fixture denied')):
            self.assertEqual(accounts.permission_info(path, os.getuid()),
                             {'path': str(path), 'unknown': 'fixture denied'})
        with patch.object(Path, 'lstat', side_effect=TypeError('fixture defect')):
            with self.assertRaises(TypeError):
                accounts.permission_info(path, os.getuid())

    def test_collector_reports_link_uncertainty_and_owner_without_write_claim(self):
        target = self.home / 'private-target'
        target.mkdir(mode=0o700)
        link = self.home / 'home-link'
        link.symlink_to(target, target_is_directory=True)
        ordinary = self.home / 'ordinary-home'
        ordinary.mkdir(mode=0o777)
        ordinary.chmod(0o777)
        fixture_uid = os.getuid() or 1001
        users = [SimpleNamespace(pw_name=name, pw_uid=fixture_uid, pw_gid=os.getgid(),
                                 pw_dir=str(home), pw_shell='/bin/bash')
                 for name, home in (('alice', link), ('bob', ordinary))]
        native_lstat = Path.lstat

        for owner in (0, fixture_uid + 1):
            with self.subTest(link_owner=owner):
                def metadata(path):
                    if path == link:
                        return SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=owner)
                    return native_lstat(path)

                with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=[]), \
                     patch.object(accounts.os, 'geteuid', return_value=0), \
                     patch.object(Path, 'lstat', metadata):
                    check, findings = accounts.collect(
                        lambda command: {'status': 'ok', 'output': '', 'detail': ''},
                        'authorizedkeysfile none',
                    )
                permission = check['accounts'][0]['permissions'][0]
                unknown = {'level': 'UNKNOWN',
                           'message': f"alice: {link}: {permission['unknown']}"}
                self.assertEqual(findings.count(unknown), 1)
                alice_reviews = [item['message'] for item in findings
                                 if item['level'] == 'REVIEW' and item['message'].startswith('alice:')]
                if owner == 0:
                    self.assertEqual(alice_reviews, [])
                else:
                    self.assertEqual(alice_reviews,
                                     [f'alice: unexpected owner UID {owner} on symbolic link {link}.'])
                self.assertIn({'level': 'REVIEW', 'message':
                               f'bob: unexpected owner or group/other write permission on {ordinary} (0o777).'},
                              findings)
                self.assertIn('target permissions not inspected', account_text_report(check))
                self.assertEqual(json.loads(json.dumps(check)), check)

    def test_shared_symlink_key_parent_is_reported_once_and_contents_stay_unread(self):
        target = self.home / 'key-target'
        target.mkdir(mode=0o700)
        for name in ('authorized_keys', 'authorized_keys2'):
            (target / name).write_text('PRIVATE_SYNTHETIC_SENTINEL')
        link = self.home / '.ssh'
        link.symlink_to(target, target_is_directory=True)
        user = SimpleNamespace(pw_name='alice', pw_uid=os.getuid() or 1001, pw_gid=os.getgid(),
                               pw_dir=str(self.home), pw_shell='/bin/bash')
        with patch('pwd.getpwall', return_value=[user]), patch('grp.getgrall', return_value=[]), \
             patch.object(accounts.os, 'geteuid', return_value=0), \
             patch.object(accounts.os, 'open', side_effect=AssertionError('Key contents must not be opened')):
            check, findings = accounts.collect(
                lambda command: {'status': 'ok', 'output': '', 'detail': ''},
            )
        inventories = check['accounts'][0]['key_files']
        self.assertEqual([item['status'] for item in inventories], ['unknown', 'unknown'])
        self.assertTrue(all(item['keys'] == [] for item in inventories))
        link_permissions = [item for item in check['accounts'][0]['permissions'] if item.get('symlink')]
        self.assertEqual(len(link_permissions), 2)  # Each configured key retains its parent evidence.
        unknown = {'level': 'UNKNOWN', 'message': f"alice: {link}: {link_permissions[0]['unknown']}"}
        self.assertEqual(findings.count(unknown), 1)
        self.assertFalse(any(item['level'] == 'REVIEW' for item in findings))
        self.assertNotIn('PRIVATE_SYNTHETIC_SENTINEL', json.dumps((check, findings)))

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
