"""Opt-in checks for a disposable Ubuntu/Debian lab; never configure the target host."""

import json
import os
from pathlib import Path
import unittest
import urllib.request

from server_audit.collectors import accounts
from server_audit.command_runner import run
from server_audit.collectors import docker_audit
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
        inventory = accounts.key_inventory(Path('/root/.ssh/authorized_keys'), run)
        self.assertEqual(inventory['status'], 'ok')
        self.assertEqual(len(inventory['keys']), 1)
        self.assertTrue(inventory['keys'][0]['fingerprint'].startswith('SHA256:'))

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


if __name__ == '__main__':
    unittest.main()
