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
from server_audit.reporting import render_html
from server_audit.reporting import render_text
from server_audit import reporting
from server_audit.collectors import ssh_audit


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


@unittest.skipUnless(platform.system() == 'Linux', 'Linux account database')
class ScopeTests(unittest.TestCase):
    def collect(self, context=None, output='authorizedkeysfile /synthetic/alice-only.keys', status='ok', fallback_keys=True):
        users = [SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=uid,
                                 pw_dir=f'/synthetic/{name}', pw_shell='/bin/bash')
                 for name, uid in (('alice', 1001), ('bob', 1002))]
        def inventory(path, run):
            if not fallback_keys and str(path) != '/synthetic/alice-only.keys':
                return {'path': str(path), 'status': 'absent', 'keys': []}
            return {'path': str(path), 'status': 'ok', 'keys': [
                {'line': 1, 'type': 'ssh-rsa', 'bits': 1024,
                 'fingerprint': 'SHA256:SyntheticKey', 'last_observed_use': None}]}
        scope = {'status': status, 'output': output, 'configuration_source': 'custom',
                 'configuration_path': '/synthetic/<fixture>.conf', 'connection_context': context}
        with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=[]), \
             patch.object(accounts.os, 'geteuid', return_value=0), \
             patch.object(accounts, 'key_inventory', side_effect=inventory) as inspect, \
             patch.object(accounts, 'permission_info', side_effect=lambda path, uid: {'path': str(path)}):
            check, findings = accounts.collect(
                lambda command: {'status': 'ok', 'output': '', 'detail': ''}, ssh_check=scope)
        return check, findings, [str(call.args[0]) for call in inspect.call_args_list]

    def test_user_context_is_not_attributed_to_other_accounts_and_fallback_observations_survive(self):
        check, findings, paths = self.collect('user=alice,addr=192.0.2.1')
        alice, bob = check['accounts']
        self.assertEqual([item['path'] for item in alice['key_files']], ['/synthetic/alice-only.keys'])
        self.assertEqual([item['path'] for item in bob['key_files']],
                         ['/synthetic/bob/.ssh/authorized_keys', '/synthetic/bob/.ssh/authorized_keys2'])
        self.assertEqual(paths.count('/synthetic/alice-only.keys'), 1)
        self.assertEqual(alice['key_path_scope']['applicability'], 'selected_context')
        self.assertEqual(bob['key_path_scope']['applicability'], 'unknown')
        self.assertEqual(bob['key_path_scope']['source'], 'conventional defaults')
        self.assertTrue(any('bob: weak/obsolete key' in item['message'] for item in findings))
        shared = [item['message'] for item in findings if 'candidate key files for accounts:' in item['message']]
        self.assertEqual(len(shared), 1)  # Same key was independently observed in Bob's fallback files.
        self.assertIn('Effective authorization across these accounts is unverified', shared[0])
        self.assertTrue(any(item['level'] == 'UNKNOWN' and 'applicability unverified for: bob.' in item['message']
                            for item in findings))
        self.assertEqual(check['ssh_scope']['connection_context'], 'user=alice,addr=192.0.2.1')
        self.assertEqual(check['ssh_scope']['configuration_path'], '/synthetic/<fixture>.conf')

    def test_alice_only_file_cannot_create_a_shared_key_finding_for_bob(self):
        check, findings, _ = self.collect('user=alice', fallback_keys=False)
        self.assertEqual(len(check['accounts'][0]['key_files'][0]['keys']), 1)
        self.assertTrue(all(not item['keys'] for item in check['accounts'][1]['key_files']))
        self.assertFalse(any('candidate key files for accounts:' in item['message'] for item in findings))

    def test_context_without_user_and_no_context_keep_qualified_candidate_inventory(self):
        for context in (None, 'addr=192.0.2.1,host=client.example', 'user=alice,user=bob'):
            with self.subTest(context=context):
                check, findings, paths = self.collect(context)
                self.assertEqual(paths, ['/synthetic/alice-only.keys'] * 2)
                self.assertTrue(all(account['key_path_scope']['applicability'] == 'unknown'
                                    for account in check['accounts']))
                self.assertTrue(any(item['level'] == 'UNKNOWN' and 'applicability unverified for: alice, bob.' in item['message']
                                    for item in findings))
                self.assertFalse(any('shared across accounts:' in item['message'] for item in findings))

    def test_missing_and_failed_settings_keep_attempted_scope_and_conventional_inventory(self):
        for status, output in (('error', 'authorizedkeysfile /synthetic/alice-only.keys'),
                               ('unavailable', ''), ('ok', 'port 22')):
            with self.subTest(status=status):
                check, findings, paths = self.collect('user=alice', output, status)
                self.assertNotIn('/synthetic/alice-only.keys', paths)
                self.assertEqual(len(paths), 4)
                self.assertEqual(check['ssh_scope']['status'], status)
                self.assertEqual(check['ssh_scope']['connection_context'], 'user=alice')
                self.assertTrue(all(account['key_path_scope']['source'] == 'conventional defaults'
                                    for account in check['accounts']))
                self.assertTrue(any(item['level'] == 'UNKNOWN' and 'applicability unverified' in item['message']
                                    for item in findings))

    def test_none_applies_only_to_selected_user_and_scopes_survive_all_formats(self):
        check, findings, paths = self.collect('user=alice,host=<fixture>', 'authorizedkeysfile none')
        self.assertEqual(check['accounts'][0]['key_files'], [])
        self.assertEqual(len(check['accounts'][1]['key_files']), 2)
        self.assertFalse(any('/alice/' in path for path in paths))
        self.assertEqual(json.loads(json.dumps(check)), check)
        text = account_text_report(check)
        self.assertIn('user=alice,host=<fixture>', text)
        self.assertIn('Key-path scope:', text)
        html = render_html({'checks': {'accounts': check}, 'findings': findings})
        self.assertIn('user=alice,host=&lt;fixture&gt;', html)
        self.assertIn('key_path_scope', html)


@unittest.skipUnless(platform.system() == 'Linux', 'Linux account database')
class PrivilegeTests(unittest.TestCase):
    def collect(self, users, concerns=False, failed_command=None, sudo_grants=True, privileged_groups=True):
        calls = []
        def command(argv):
            calls.append(argv)
            if argv[0] == failed_command:
                return {'status': 'error', 'output': '', 'detail': 'Synthetic lookup failure'}
            output = ''
            if argv[0] == 'sudo' and sudo_grants:
                output = f'User {argv[-1]} may run the following commands:\n    (ALL) NOPASSWD: ALL'
            elif argv[0] == 'passwd':
                output = f'{argv[-1]} {"NP" if concerns else "P"} synthetic-state'
            elif argv[0] == 'chage':
                output = 'Account expires : never'
            return {'status': 'ok', 'output': output, 'detail': ''}
        def inventory(path, runner):
            keys = [{'line': 1, 'type': 'ssh-rsa', 'bits': 1024, 'fingerprint': 'SHA256:SyntheticRoot'},
                    {'line': 2, 'type': 'unknown', 'bits': None}] if concerns else []
            return {'path': str(path), 'status': 'ok' if concerns else 'absent', 'keys': keys}
        def permission(path, uid):
            if concerns and path.name == '.ssh':
                return {'path': str(path), 'symlink': True, 'mode': '0777', 'owner_uid': uid,
                        'unsafe': False, 'unknown': 'Synthetic link target permissions not inspected'}
            return {'path': str(path), 'mode': '0770' if concerns else '0700',
                    'owner_uid': uid, 'symlink': False, 'unsafe': concerns}
        groups = [SimpleNamespace(gr_name='sudo', gr_gid=1234, gr_mem=[user.pw_name for user in users])]
        if not privileged_groups:
            groups = []
        scope = {'status': 'ok', 'output': 'authorizedkeysfile .ssh/authorized_keys',
                 'configuration_source': 'custom', 'configuration_path': '/synthetic/sshd_config',
                 'connection_context': 'user=root'}
        with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=groups), \
             patch.object(accounts.os, 'geteuid', return_value=0), \
             patch.object(accounts, 'permission_info', side_effect=permission), \
             patch.object(accounts, 'key_inventory', side_effect=inventory):
            check, findings = accounts.collect(command, ssh_check=scope)
        return check, findings, calls

    def user(self, name='root', uid=0, shell='/bin/bash'):
        return SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=uid, pw_dir=f'/synthetic/{name}', pw_shell=shell)

    def test_normal_root_retains_complete_inventory_and_exports_without_generic_privilege_findings(self):
        check, findings, calls = self.collect([self.user()])
        self.assertEqual(findings, [])
        root = check['accounts'][0]
        self.assertEqual((root['user'], root['uid'], root['gid'], root['home'], root['shell']),
                         ('root', 0, 0, '/synthetic/root', '/bin/bash'))
        self.assertEqual(root['groups'], ['sudo'])
        self.assertIn('NOPASSWD: ALL', root['sudo_policy']['output'])
        self.assertEqual(root['password_state']['status'], 'ok')
        self.assertIn('Account expires', root['password_and_account_expiry']['output'])
        self.assertEqual(root['key_path_scope']['applicability'], 'selected_context')
        self.assertEqual(root['key_files'][0]['status'], 'absent')
        self.assertEqual(root['permissions'][0]['mode'], '0700')
        self.assertEqual(check['key_usage']['status'], 'ok')
        self.assertEqual(check['last_login']['status'], 'ok')
        for executable in ('passwd', 'chage', 'sudo'):
            self.assertTrue(any(argv[0] == executable and argv[-1] == 'root' for argv in calls))
        report = {'schema_version': 1, 'host': 'synthetic', 'timestamp_utc': '2026-01-01T12:00:00+00:00',
                  'checks': {'accounts': check}, 'findings': findings, 'summary': {'REVIEW': 0, 'UNKNOWN': 0}, 'limitations': []}
        with tempfile.TemporaryDirectory() as directory:
            folder = reporting.export_report(report, directory)
            self.assertEqual(json.loads((folder / 'data/report.json').read_text()), report)
            self.assertIn('NOPASSWD', (folder / 'report.html').read_text())
        self.assertIn('root', render_text(report))
        self.assertIn('NOPASSWD', account_text_report(check))

    def test_only_exact_root_uid_zero_is_exempt_and_service_accounts_remain_visible(self):
        for name, uid in (('root', 1001), ('administrator', 0), ('alice', 1001)):
            with self.subTest(name=name, uid=uid):
                check, findings, _ = self.collect([self.user(name, uid)])
                self.assertTrue(any(f'Account {name} has sudo command grants.' in item['message'] for item in findings))
                self.assertTrue(any(f'Account {name}: UID {uid}, privileged groups' in item['message'] for item in findings))
                self.assertEqual(check['accounts'][0]['uid'], uid)
        users = [self.user(), self.user('service-a', 1002, '/usr/sbin/nologin'), self.user('service-b', 1003, '/bin/false')]
        check, findings, _ = self.collect(users)
        self.assertEqual([item['shell'] for item in check['accounts']], [user.pw_shell for user in users])
        for user in users[1:]:
            self.assertTrue(any(f'Account {user.pw_name} has sudo command grants.' in item['message'] for item in findings))
            self.assertTrue(any(f'Account {user.pw_name}: UID' in item['message'] for item in findings))

    def test_nonroot_sudo_group_and_uid_privileges_remain_independent(self):
        for uid, grants, groups, expected in ((1001, True, False, 'has sudo command grants'),
                                              (1001, False, True, 'privileged groups'),
                                              (0, False, False, 'UID 0')):
            with self.subTest(uid=uid, sudo_grants=grants, privileged_groups=groups):
                _, findings, _ = self.collect([self.user('administrator', uid)], sudo_grants=grants, privileged_groups=groups)
                self.assertEqual(len([item for item in findings if item['level'] == 'REVIEW']), 1)
                self.assertTrue(any(expected in item['message'] for item in findings))

    def test_specific_root_concerns_and_collection_failures_are_not_exempt(self):
        check, findings, _ = self.collect([self.user()], concerns=True)
        messages = '\n'.join(item['message'] for item in findings)
        for expected in ('has no password', 'weak/obsolete key', 'could not validate key',
                         'group/other write permission', 'Synthetic link target permissions not inspected'):
            self.assertIn(expected, messages)
        self.assertEqual(len(check['accounts'][0]['key_files'][0]['keys']), 2)
        self.assertNotIn('has sudo command grants', messages)
        self.assertNotIn('privileged groups', messages)
        _, ssh_findings = ssh_audit.ssh_findings('permitrootlogin yes')
        self.assertTrue(any('permitrootlogin=yes' in item['message'] for item in ssh_findings))
        fields = {'passwd': 'password_state', 'chage': 'password_and_account_expiry', 'sudo': 'sudo_policy'}
        for executable in ('passwd', 'chage', 'sudo', 'journalctl', 'lastlog'):
            with self.subTest(failed_command=executable):
                check, findings, _ = self.collect([self.user()], failed_command=executable)
                self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
                if executable in fields:
                    self.assertEqual(check['accounts'][0][fields[executable]]['status'], 'error')
                self.assertEqual(len(check['accounts']), 1)


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
        self.assertTrue(any('observed in candidate key files for accounts: alice, bob' in item['message']
                            and 'authorization across these accounts is unverified' in item['message']
                            for item in findings))
        self.assertEqual(alice['password_state']['output'].split()[1], 'L')
        text = account_text_report(report)
        self.assertIn('last observed use=unknown', text)
        self.assertNotIn(public[1], text)


if __name__ == '__main__':
    unittest.main()
