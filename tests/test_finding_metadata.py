"""Producer identities are additive; policy messages and ordering stay unchanged."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from server_audit.collectors import accounts, docker_audit, git_secrets, network_audit, ssh_audit, system_audit


class FindingMetadataTests(unittest.TestCase):
    def assert_resource(self, finding, check, kind, identity, name=None):
        self.assertEqual({key: finding[key] for key in ('check', 'resource_type', 'resource_id', 'resource_name')},
                         {'check': check, 'resource_type': kind, 'resource_id': identity, 'resource_name': name or identity})

    def test_docker_identity_is_full_id_and_name_is_only_display_metadata(self):
        identity = 'a' * 64
        findings = docker_audit.findings_for({'id': identity, 'name': '/renamed', 'user': '1000',
                                             'privileged': True, 'network_mode': 'host'})
        self.assertEqual([(item['level'], item['message']) for item in findings], [
            ('REVIEW', 'Docker /renamed: privileged mode grants broad host access.'),
            ('REVIEW', 'Docker /renamed: network_mode uses host namespace.'),
        ])
        for finding in findings:
            self.assert_resource(finding, 'docker', 'container', identity, '/renamed')
        anonymous = docker_audit.findings_for({'name': '/renamed', 'user': '1000', 'privileged': True})
        self.assertEqual(anonymous, [{'level': 'REVIEW', 'message': findings[0]['message'], 'check': 'docker'}])

    def test_failed_docker_inspection_retains_full_identity_without_raw_output(self):
        identity = 'b' * 64
        for response in ({'status': 'error', 'detail': 'PRIVATE_SENTINEL'},
                         {'status': 'ok', 'output': 'PRIVATE_SENTINEL'}):
            with self.subTest(response=response):
                _, findings = docker_audit.collect(lambda command: {'status': 'ok', 'output': identity}
                                                   if 'ps' in command else response)
                self.assertEqual(len(findings), 1)
                self.assert_resource(findings[0], 'docker', 'container', identity)
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps(findings))

    def test_ssh_scope_changes_identity_without_changing_policy_sequence(self):
        output = 'permitrootlogin yes\npasswordauthentication yes\nkbdinteractiveauthentication yes'
        _, baseline = ssh_audit.ssh_findings(output)
        expected = [
            ('REVIEW', 'SSH permitrootlogin=yes. Prefer a named administrator with sudo; verify access before disabling root login.'),
            ('REVIEW', 'SSH passwordauthentication=yes. Prefer SSH keys; verify key access before disabling passwords.'),
            ('REVIEW', 'SSH keyboard-interactive authentication enabled; inspect PAM/MFA policy before changing it.'),
        ]
        self.assertEqual([(item['level'], item['message']) for item in baseline], expected)
        self.assertTrue(all(item['check'] == 'ssh' and 'resource_id' not in item for item in baseline))
        identities = []
        for config, context in (('/etc/ssh/custom.conf', None), (None, 'user=alice'),
                                ('/etc/ssh/custom.conf', 'user=alice'), ('/etc/ssh/custom.conf', 'user=bob')):
            _, findings = ssh_audit.collect(lambda command: {'status': 'ok', 'output': output}, context, config)
            self.assertEqual([(item['level'], item['message']) for item in findings], expected)
            identity = json.dumps([config, context], separators=(',', ':'))
            identities.append(identity)
            self.assertTrue(all(item['check'] == 'ssh' and item['resource_type'] == 'ssh_configuration'
                                and item['resource_id'] == identity for item in findings))
        self.assertEqual(len(set(identities)), 4)

    def test_socket_aggregate_has_check_identity_and_firewall_aggregate_remains_general(self):
        _, findings = network_audit.collect_ports(lambda command: {'status': 'ok', 'output': 'tcp LISTEN 0 128 *:22 *:*\nshort'})
        self.assertEqual([(item['level'], item['message']) for item in findings], [
            ('UNKNOWN', 'Socket inventory incomplete: 1 nonempty ss records could not be parsed. Review the retained command output; listed sockets remain available.'),
            ('REVIEW', '1 non-loopback TCP/UDP sockets. Confirm each service is needed and restricted by firewall where appropriate.'),
        ])
        self.assertTrue(all(item['check'] == 'ports' and 'resource_id' not in item for item in findings))
        self.assertEqual(network_audit.firewall_findings({}), [{'level': 'UNKNOWN', 'message':
            'No kernel firewall rules could be inspected. UFW status alone cannot establish filtering coverage.'}])

    def test_maintenance_preserves_aggregates_and_attributes_only_a_single_known_unit(self):
        checks = {'available_updates': {'status': 'ok', 'output': 'openssl/stable 3 amd64 [upgradable from: 2]'},
                  'failed_services': {'status': 'ok', 'output': 'app.service loaded failed failed App'}}
        findings = system_audit.maintenance_findings(checks)
        self.assertEqual([(item['level'], item['message']) for item in findings], [
            ('REVIEW', '1 package updates available in cached APT metadata. Review and apply relevant updates; security classification is not established.'),
            ('REVIEW', 'Failed services: app.service'),
        ])
        self.assertEqual(findings[0]['check'], 'available_updates')
        self.assertNotIn('resource_id', findings[0])
        self.assert_resource(findings[1], 'failed_services', 'service', 'app.service')
        checks['failed_services']['output'] += '\nsecond.service loaded failed failed Other'
        multiple = system_audit.maintenance_findings(checks)[1]
        self.assertEqual(multiple, {'level': 'REVIEW', 'message': 'Failed services: app.service, second.service', 'check': 'failed_services'})

    @unittest.skipUnless(os.name == 'posix', 'Account metadata requires POSIX NSS')
    def test_accounts_use_user_identity_and_shared_key_has_one_fingerprint_identity(self):
        users = [SimpleNamespace(pw_name=name, pw_uid=1000 + index, pw_gid=1000,
                                 pw_dir='/home/' + name, pw_shell='/bin/bash') for index, name in enumerate(('alice', 'bob'))]
        def inventory(path, run):
            return {'path': str(path), 'status': 'ok', 'keys': [
                {'line': 1, 'fingerprint': 'SHA256:shared', 'type': 'ssh-rsa', 'bits': 1024}]}
        def run(command):
            return {'status': 'ok', 'output': command[-1] + ' NP' if command[0] == 'passwd' else '', 'detail': ''}
        with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=[]), \
             patch.object(accounts.os, 'geteuid', return_value=0), patch.object(accounts, 'key_inventory', side_effect=inventory), \
             patch.object(accounts, 'permission_info', side_effect=lambda path, uid: {'path': str(path), 'unsafe': False}):
            _, findings = accounts.collect(run, 'authorizedkeysfile .ssh/authorized_keys')
        expected = []
        for name in ('alice', 'bob'):
            expected.extend([('REVIEW', f'Account {name} has no password. Actual login depends on PAM and SSH policy.'),
                             ('REVIEW', f'{name}: weak/obsolete key SHA256:shared (ssh-rsa, 1024 bits).')])
        expected.extend([
            ('REVIEW', 'SSH key SHA256:shared observed in candidate key files for accounts: alice, bob. Effective authorization across these accounts is unverified.'),
            ('UNKNOWN', 'SSH key-path applicability unverified for: alice, bob. Candidate files are inventoried; inspect key_path_scope and the selected SSH evaluation before treating entries as effective authorization.'),
        ])
        self.assertEqual([(item['level'], item['message']) for item in findings], expected)
        for finding, name in zip(findings[:4], ('alice', 'alice', 'bob', 'bob')):
            self.assert_resource(finding, 'accounts', 'account', name)
        self.assert_resource(findings[4], 'accounts', 'ssh_key', 'SHA256:shared')
        self.assertEqual(sum(item.get('resource_type') == 'ssh_key' for item in findings), 1)
        self.assertEqual(findings[5]['check'], 'accounts')
        self.assertNotIn('resource_id', findings[5])

    @unittest.skipUnless(os.name == 'posix', 'Git collector requires POSIX pipe support')
    def test_git_findings_share_repository_identity_without_changing_detection_order(self):
        repository = {'path': '/srv/example', 'status': 'partial', 'scans': [
            {'mode': 'git_configuration', 'detections': [{'rule': 'github-token', 'file': 'config', 'start_line': 2}]}]}
        with patch.object(git_secrets.shutil, 'which', return_value='/usr/bin/git'), \
             patch.object(git_secrets, 'git_directory', return_value=(Path('/srv/example'), Path('/srv/example/.git'))), \
             patch.object(git_secrets, 'scan_repository', return_value=repository):
            _, findings = git_secrets.collect(['/srv/example'])
        self.assertEqual([(item['level'], item['message']) for item in findings], [
            ('UNKNOWN', 'Git /srv/example: incomplete local secret inspection. See repository issues and limits.'),
            ('REVIEW', 'Git /srv/example: possible secret (github-token) in config:2 [git_configuration]. Verify locally; if genuine, revoke/rotate it and investigate exposure.'),
        ])
        for finding in findings:
            self.assert_resource(finding, 'git_secrets', 'repository', '/srv/example')


if __name__ == '__main__':
    unittest.main()
