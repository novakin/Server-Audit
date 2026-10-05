"""Opt-in checks for a disposable Ubuntu/Debian lab; never configure the target host."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
import urllib.request
from unittest.mock import patch

from server_audit.collectors import accounts
from server_audit.command_runner import run
from server_audit.collectors import docker_audit
from server_audit.collectors import env_files
from server_audit.collectors import network_audit
from server_audit.collectors import ssh_audit


@unittest.skipUnless(os.environ.get('AUDIT_LIVE_INTEGRATION') == '1', 'Requires explicitly prepared disposable Ubuntu/Debian integration lab')
class LiveIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not Path('/run/server-security-audit-integration-lab').is_file():
            raise RuntimeError('Refusing live integration without disposable-lab marker')
        if os.geteuid() != 0:
            raise RuntimeError('Disposable-lab validation requires root')

    def test_native_ssh_configuration_match_and_successful_login(self):
        baseline, _ = ssh_audit.collect(run, config='/opt/lab/sshd_config')
        matched, _ = ssh_audit.collect(run, 'user=root,addr=127.0.0.1,host=localhost', '/opt/lab/sshd_config')
        self.assertEqual(baseline['status'], 'ok', baseline.get('detail'))
        self.assertEqual(matched['status'], 'ok', matched.get('detail'))
        self.assertEqual(baseline['selected_settings']['allowtcpforwarding'], 'no')
        self.assertEqual(matched['selected_settings']['allowtcpforwarding'], 'yes')
        self.assertEqual(matched['selected_settings']['passwordauthentication'], 'no')
        self.assertEqual(Path('/results/ssh-client.txt').read_text(), 'audit-live-ssh-ok')
        self.assertIn('Accepted publickey for root', Path('/results/sshd.log').read_text())
        inventory = accounts.key_inventory(Path('/run/server-security-audit-authorized_keys'), run)
        self.assertEqual(inventory['status'], 'ok')
        self.assertEqual(len(inventory['keys']), 1)
        self.assertTrue(inventory['keys'][0]['fingerprint'].startswith('SHA256:'))
        other, _ = ssh_audit.collect(run, 'user=nobody,addr=127.0.0.1,host=localhost', '/opt/lab/sshd_config')
        self.assertEqual(other['status'], 'ok', other.get('detail'))
        self.assertIn('authorizedkeysfile .ssh/authorized_keys\n', baseline['output'] + '\n')
        self.assertIn('authorizedkeysfile .ssh/authorized_keys\n', other['output'] + '\n')
        self.assertIn('authorizedkeysfile /run/server-security-audit-authorized_keys\n', matched['output'] + '\n')

        # Only key validation uses a native command; account/password/history fixtures stay synthetic.
        def account_command(command, input_text=None):
            if command[0] == 'ssh-keygen':
                return run(command, input_text)
            return {'status': 'ok', 'output': '', 'detail': ''}
        users = [SimpleNamespace(pw_name=name, pw_uid=uid, pw_gid=uid,
                                 pw_dir=f'/opt/lab/{name}-home', pw_shell='/bin/bash')
                 for name, uid in (('root', 0), ('nobody', 1001))]
        with patch('pwd.getpwall', return_value=users), patch('grp.getgrall', return_value=[]):
            check, findings = accounts.collect(account_command, ssh_check=matched)
        root, nobody = check['accounts']
        self.assertEqual(root['key_path_scope']['applicability'], 'selected_context')
        self.assertEqual(root['key_files'], [inventory])
        self.assertEqual(nobody['key_path_scope']['source'], 'conventional defaults')
        self.assertTrue(all(item['status'] == 'absent' for item in nobody['key_files']))
        self.assertFalse(any('candidate key files for accounts:' in item['message'] for item in findings))

    def test_native_docker_projection_running_stopped_and_redaction(self):
        report, findings = docker_audit.collect(run)
        self.assertEqual(report['status'], 'ok', report.get('detail'))
        for item in report['containers']:
            self.assertEqual(item['inspection_status'], 'ok', item.get('detail'))
        containers = {item['name'].lstrip('/'): item for item in report['containers']}
        self.assertEqual(set(containers), {'audit-integration-web', 'audit-integration-stopped'})
        web = containers['audit-integration-web']
        stopped = containers['audit-integration-stopped']
        self.assertEqual(web['inspection_status'], 'ok')
        self.assertTrue(web['running'])
        self.assertIn(web['health'], ('starting', 'healthy'))
        self.assertEqual(web['published_ports']['80/tcp'][0]['HostIp'], '127.0.0.1')
        self.assertEqual(web['published_ports']['80/tcp'][0]['HostPort'], '18080')
        self.assertEqual(web['memory_bytes'], 64 * 1024 * 1024)
        self.assertEqual(web['pids_limit'], 64)
        self.assertGreaterEqual(web['environment_variable_count'], 1)
        self.assertEqual(stopped['inspection_status'], 'ok')
        self.assertFalse(stopped['running'])
        self.assertIsNone(stopped['health'])
        self.assertEqual(stopped['environment_variable_count'], 0)
        self.assertEqual(stopped['user'], '1000:1000')
        self.assertTrue(stopped['readonly_rootfs'])
        self.assertNotIn('PRIVATE_SENTINEL_LIVE', json.dumps([report, findings]))
        self.assertTrue(any('root/default' in item['message'] for item in findings))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open('http://127.0.0.1:18080', timeout=5) as response:
            self.assertEqual(response.read().strip(), b'audit-live-http-ok')

    def test_native_firewall_rules_are_collected(self):
        checks = network_audit.collect_firewalls(run)
        for name in ('nftables', 'iptables_ipv4', 'iptables_ipv6'):
            self.assertEqual(checks[name]['status'], 'ok', checks[name].get('detail'))
        self.assertIn('audit-integration-ssh', checks['nftables']['output'])
        self.assertIn('audit-integration-docker', checks['iptables_ipv4']['output'])
        self.assertFalse(any(item['level'] == 'UNKNOWN' for item in network_audit.firewall_findings(checks)))

    def test_native_socket_owner_and_loopback_binding(self):
        check, _ = network_audit.collect_ports(run)
        self.assertEqual(check['status'], 'ok', check.get('detail'))
        ssh = [item for item in check['listeners'] if item['address'] == '127.0.0.1:22222']
        self.assertEqual(len(ssh), 1)
        self.assertEqual(ssh[0]['binding'], 'loopback')
        self.assertIn('sshd', ssh[0]['process'])

    def test_native_systemd_environment_wildcards_preserve_unknown_and_discovery(self):
        unit = 'server-audit-environment-fixture.service'
        evidence = run(['systemctl', 'show', '--no-pager', '--property=EnvironmentFiles', '--property=ActiveState', '--', unit])
        self.assertEqual(evidence['status'], 'ok', evidence.get('detail'))
        self.assertIn('ActiveState=inactive', evidence['output'])
        self.assertIn('/opt/lab/*.env', evidence['output'], evidence['output'])
        # Select the synthetic loaded unit; it was not started and is not a running-service claim.
        checks = {'running_services': {'status': 'ok', 'output': unit},
                  'docker': {'status': 'ok', 'containers': []}}
        report, findings = env_files.collect(['/opt/lab'], run, checks)
        source = report['applications']['sources'][0]
        self.assertEqual(source['status'], 'partial', source)
        patterns = {item['path']: item for item in source['files'] if item.get('status') == 'unknown'}
        self.assertEqual(set(patterns), {'/opt/lab/*.env', '/opt/lab/missing-?.env', '/opt/lab/settings-[ab].conf'})
        self.assertTrue(patterns['/opt/lab/*.env']['optional'])
        self.assertFalse(patterns['/opt/lab/missing-?.env']['optional'])
        self.assertTrue(patterns['/opt/lab/settings-[ab].conf']['optional'])
        self.assertEqual(report['status'], 'partial')
        files = {item['path']: item for item in report['files']}
        literal_brackets = {'/opt/lab/' + name for name in ('settings[.conf', 'settings[].conf', 'settings[!].conf', 'settings[^].conf')}
        literal_brackets.add('/opt/lab/dir[/settings].conf')
        self.assertEqual(set(files), {'/opt/lab/literal.env', '/opt/lab/production.env'} | literal_brackets)
        self.assertEqual(files['/opt/lab/literal.env']['applications'], ['systemd:' + unit])
        for path in literal_brackets:
            self.assertEqual(files[path]['applications'], ['systemd:' + unit])
        self.assertNotIn('applications', files['/opt/lab/production.env'])
        absent = next(item for item in report['skipped'] if item['path'] == '/opt/lab/absent-literal')
        self.assertEqual(absent['reason'], 'Optional application file absent')
        self.assertEqual(len([item for item in findings if item['level'] == 'UNKNOWN'
                              and item['message'].startswith('EnvironmentFile reference')]), 3)
        self.assertNotIn('PRIVATE_SENTINEL_ENV', json.dumps((report, findings)))


if __name__ == '__main__':
    unittest.main()
