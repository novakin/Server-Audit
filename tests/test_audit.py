import subprocess
import unittest
from unittest.mock import patch

from server_audit import audit_runner
from server_audit import command_runner
from server_audit.collectors import network_audit
from server_audit.collectors import ssh_audit


class AuditTests(unittest.TestCase):
    def test_optional_tools_do_not_generate_individual_missing_findings(self):
        checks = {name: {'status': 'unavailable'} for name in ('ufw', 'nftables', 'iptables_ipv4', 'iptables_ipv6', 'docker')}
        findings = audit_runner.summarize(checks)
        self.assertEqual(len(findings), 1)
        self.assertIn('No kernel firewall', findings[0]['message'])

    def test_missing_firewall_tools_skip_but_filtering_remains_unknown(self):
        with patch('server_audit.command_runner.shutil.which', return_value=None), patch('server_audit.command_runner.subprocess.run') as process:
            checks = network_audit.collect_firewalls(command_runner.run)
        process.assert_not_called()
        self.assertTrue(all(check['status'] == 'skipped' for check in checks.values()))
        findings = audit_runner.summarize(checks)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['level'], 'UNKNOWN')
        self.assertIn('No kernel firewall', findings[0]['message'])

    def test_updates_and_failed_services_are_actionable(self):
        checks = {
            'nftables': {'status': 'ok', 'output': 'table inet filter {}'},
            'available_updates': {'status': 'ok', 'output': 'Listing...\nopenssl/stable 3.0 amd64 [upgradable from: 2.0]'},
            'failed_services': {'status': 'ok', 'output': 'nginx.service loaded failed failed Web server'},
        }
        findings = audit_runner.summarize(checks)
        self.assertEqual(checks['available_updates']['packages'], ['openssl'])
        self.assertEqual(checks['failed_services']['units'], ['nginx.service'])
        self.assertTrue(any('1 package updates' in item['message'] for item in findings))
        self.assertTrue(any('Failed services: nginx.service' in item['message'] for item in findings))

    def test_empty_firewall_is_not_reported_as_secure(self):
        findings = audit_runner.summarize({'nftables': {'status': 'ok', 'output': ''}})
        self.assertTrue(any('no rules' in item['message'] for item in findings))

    def test_permission_denial_remains_visible_for_optional_tool(self):
        findings = audit_runner.summarize({'nftables': {'status': 'error', 'detail': 'Permission denied'}})
        self.assertTrue(any('Permission denied' in item['message'] for item in findings))

    def test_ipv4_mapped_loopback(self):
        result = network_audit.listeners('tcp LISTEN 0 128 [::ffff:127.0.0.1]:8080 [::]:*')
        self.assertEqual(result[0]['binding'], 'loopback')

    def test_end_to_end_report_and_custom_ssh_config(self):
        def fake_run(command):
            output = 'permitrootlogin no\npasswordauthentication no' if command[0] == 'sshd' else ''
            return {'status': 'ok', 'output': output, 'detail': ''}
        with patch('server_audit.audit_runner.run', side_effect=fake_run) as runner, patch('server_audit.audit_runner.os.geteuid', return_value=0, create=True), patch('server_audit.audit_runner.collect_accounts', return_value=({'status': 'ok', 'accounts': []}, [])), patch('server_audit.audit_runner.collect_env_files', return_value=({'status': 'ok', 'files': []}, [])), patch('server_audit.audit_runner.collect_scheduled_tasks', return_value=({'status': 'ok', 'cron_files': []}, [])):
            report = audit_runner.audit('user=alice,addr=192.0.2.1', '/etc/ssh/custom.conf')
        runner.assert_any_call(['sshd', '-T', '-f', '/etc/ssh/custom.conf', '-C', 'user=alice,addr=192.0.2.1'])
        docker_command = next(call.args[0] for call in runner.call_args_list if call.args[0][0] == 'docker')
        self.assertEqual(docker_command[1:3], ['--host', 'unix:///var/run/docker.sock'])
        self.assertEqual(report['summary']['REVIEW'], sum(item['level'] == 'REVIEW' for item in report['findings']))

    def test_socket_addresses_and_process_ownership(self):
        result = network_audit.listeners('\n'.join([
            'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=10,fd=3))',
            'tcp LISTEN 0 128 [::1]:8000 [::]:*',
            'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=20,fd=3))',
            'udp UNCONN 0 0 10.0.0.5:53 0.0.0.0:*',
            'udp UNCONN 0 0 *:5353 *:*',
        ]))
        self.assertEqual([item['binding'] == 'loopback' for item in result], [True, True, False, False, False])
        self.assertIn('postgres', result[0]['process'])
        self.assertIn('unknown', result[1]['process'])

    def test_ssh_recommendations_and_mfa(self):
        settings, findings = ssh_audit.ssh_findings('permitrootlogin prohibit-password\npasswordauthentication no\npermitemptypasswords no\nkbdinteractiveauthentication yes\nallowtcpforwarding no\nx11forwarding no')
        self.assertEqual(settings['passwordauthentication'], 'no')
        self.assertEqual(len(findings), 2)
        self.assertIn('MFA', findings[1]['message'])

    def test_missing_command_is_unknown_not_success(self):
        with patch('server_audit.command_runner.shutil.which', return_value=None):
            self.assertEqual(command_runner.run(['ss'])['status'], 'unavailable')

    def test_permission_error_preserves_evidence(self):
        result = subprocess.CompletedProcess(['nft'], 1, '', 'Operation not permitted')
        with patch('server_audit.command_runner.shutil.which', return_value='/usr/sbin/nft'), patch('server_audit.command_runner.subprocess.run', return_value=result):
            check = command_runner.run(['nft', 'list', 'ruleset'])
        self.assertEqual(check['status'], 'error')
        self.assertEqual(check['exit_code'], 1)
        self.assertIn('not permitted', check['detail'])

    def test_timeout_is_reported(self):
        with patch('server_audit.command_runner.shutil.which', return_value='/usr/bin/docker'), patch('server_audit.command_runner.subprocess.run', side_effect=subprocess.TimeoutExpired('docker', 30)):
            self.assertEqual(command_runner.run(['docker', 'ps'])['status'], 'error')


if __name__ == '__main__':
    unittest.main()
