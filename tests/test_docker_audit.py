import json
import unittest
from unittest.mock import patch

from server_audit.collectors import docker_audit as docker
from server_audit import command_runner
from server_audit import audit_runner
from server_audit.reporting import docker_text_report


class DockerTests(unittest.TestCase):
    def container(self, **overrides):
        return {"id": "a" * 64, "name": "/web", "user": "1000:1000", "status": "running", **overrides}

    def test_privileges_mounts_and_unhealthy_findings(self):
        container = self.container(privileged=True, network_mode="host", user="", cap_add=["SYS_ADMIN"],
                                   health="unhealthy", oom_killed=True,
                                   mounts=[{"source": "/var/run/docker.sock", "writable": False, "type": "bind"}])
        messages = "\n".join(item["message"] for item in docker.findings_for(container))
        for phrase in ("privileged mode", "host namespace", "root/default", "SYS_ADMIN", "unhealthy", "out-of-memory", "API read-only"):
            self.assertIn(phrase, messages)

    def test_loopback_and_unpublished_ports_are_not_flagged(self):
        container = self.container(published_ports={"80/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}, {"HostIp": "::1", "HostPort": "8080"}], "443/tcp": None})
        self.assertEqual(docker.findings_for(container), [])
        container['published_ports']['80/tcp'].append({'HostIp': '0.0.0.0', 'HostPort': '8080'})
        self.assertEqual(len(docker.findings_for(container)), 1)
        self.assertIn('reachability unverified', docker.findings_for(container)[0]['message'])

    def test_stopped_container_and_failure_survive_inventory(self):
        calls = []
        def run(command):
            calls.append(command)
            if 'ps' in command:
                return {'status': 'ok', 'output': 'a' * 64 + '\n' + 'b' * 64}
            if command[-1] == 'b' * 64:
                return {'status': 'error', 'detail': 'No such container'}
            return {'status': 'ok', 'output': json.dumps(self.container(status='exited', exit_code=2, Env=['SECRET=value'], Labels={'secret': 'value'}))}
        report, findings = docker.collect(run)
        self.assertEqual(len(report['containers']), 2)
        self.assertEqual(report['containers'][1]['inspection_status'], 'error')
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
        self.assertTrue(any('exited with code 2' in item['message'] for item in findings))
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('Labels', docker_text_report(report))
        for command in calls:
            self.assertEqual(command[:3], docker.DOCKER)
        self.assertIn('--all', calls[0])

    def test_missing_docker_skips_without_launching_process(self):
        with patch('server_audit.command_runner.shutil.which', return_value=None), patch('server_audit.command_runner.subprocess.run') as process:
            report, findings = docker.collect(command_runner.run)
        process.assert_not_called()
        self.assertEqual(report['status'], 'skipped')
        self.assertIn('CLI not found', report['detail'])
        self.assertIn('daemon presence is unverified', report['detail'])
        self.assertEqual(findings, [])

    def test_denied_or_unreachable_daemon_is_not_skipped(self):
        for detail in ('Permission denied', 'Cannot connect to the Docker daemon'):
            report, _ = docker.collect(lambda command: {'status': 'error', 'detail': detail})
            self.assertEqual(report['status'], 'error')
            findings = audit_runner.summarize({'docker': report})
            self.assertTrue(any(item['level'] == 'UNKNOWN' and detail in item['message'] for item in findings))

    def test_empty_daemon_is_valid_inventory(self):
        report, findings = docker.collect(lambda command: {'status': 'ok', 'output': ''})
        self.assertEqual(report['containers'], [])
        self.assertEqual(findings, [])

    def test_invalid_inspect_does_not_crash_or_leak_output(self):
        def run(command):
            return {'status': 'ok', 'output': 'a' * 64 if 'ps' in command else 'secret invalid JSON'}
        report, findings = docker.collect(run)
        self.assertEqual(report['containers'][0]['inspection_status'], 'error')
        self.assertNotIn('secret', json.dumps(report))
        self.assertEqual(findings[0]['level'], 'UNKNOWN')

    def test_inspect_projection_excludes_secret_bearing_sections(self):
        self.assertIn('{{with index .Config "Env"}}{{len .}}{{else}}0{{end}}', docker.INSPECT_FORMAT)
        for forbidden in ('{{json .Config.Env}}', '.Config.Labels', '.Config.Cmd', '.Config.Entrypoint', '.State.Health.Log', '.HostConfig.LogConfig.Config'):
            self.assertNotIn(forbidden, docker.INSPECT_FORMAT)


if __name__ == '__main__':
    unittest.main()
