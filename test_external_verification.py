import contextlib
import copy
import datetime
import errno
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import external_probe as cli
import external_verification as external
import reporting


def audit_fixture():
    report = {'schema_version': 1, 'host': 'fixture-host', 'timestamp_utc': cli.now(),
            'findings': [], 'summary': {'REVIEW': 0, 'UNKNOWN': 0}, 'limitations': [],
            'checks': {'ports': {'status': 'ok', 'listeners': [
                {'protocol': 'tcp', 'address': '0.0.0.0:443', 'process': 'nginx'},
                {'protocol': 'udp', 'address': '[::]:53', 'process': 'dns'},
                {'protocol': 'tcp', 'address': '127.0.0.1:9000', 'process': 'internal'}]},
                'docker': {'status': 'ok', 'containers': [
                    {'inspection_status': 'ok', 'name': '/web', 'running': True,
                     'published_ports': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}},
                    {'inspection_status': 'ok', 'name': '/stopped', 'running': False,
                     'published_ports': {'90/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '9090'}]}}]}}}
    for item in report['checks']['ports']['listeners']:
        item['binding'] = 'loopback' if item['address'].startswith('127.') else 'non-loopback (reachability unverified)'
    report['checks']['docker'].update(endpoint='unix:///var/run/docker.sock', limitations=[])
    return report


def probe_fixture(report, independent=True, target='8.8.8.8', observation='connected'):
    def fake_connect(endpoint, timeout):
        ip, number = endpoint
        return {'target': ip, 'port': number, 'family': 'IPv6' if ':' in ip else 'IPv4',
                'protocol': 'tcp', 'observation': observation, 'source_address': None, 'observed_at_utc': cli.now()}
    # Public example here is always mocked; tests never connect to external IPs.
    with patch.object(cli, 'connect', side_effect=fake_connect):
        return cli.probe(report, [target], [443], 'independent test network', independent)


class ExternalVerificationTests(unittest.TestCase):
    def test_inventory_includes_tcp_udp_and_only_running_docker_bindings(self):
        entries = external.inventory(audit_fixture())
        self.assertEqual({(item['protocol'], item['port']) for item in entries}, {('tcp', 443), ('udp', 53), ('tcp', 9000), ('tcp', 8080)})

    def test_scope_is_explicit_literal_bounded_and_validated_before_network(self):
        report = audit_fixture()
        for targets, ports in [(['example.org'], [443]), (['0.0.0.0'], [443]), (['ff02::1'], [443]),
                               (['fe80::1%eth0'], [443]), (['::ffff:127.0.0.1'], [443]),
                               (['127.0.0.1'], [True]), (['127.0.0.1'] * 2, [443]),
                               (['127.0.0.1', '::1'], list(range(1, 1025)))]:
            with self.subTest(targets=targets), patch.object(cli, 'connect') as connect:
                with self.assertRaises(ValueError):
                    cli.probe(report, targets, ports, 'lab')
                connect.assert_not_called()
        self.assertEqual(cli.parse_ports('22,80,443,8000-8002,22'), [22, 80, 443, 8000, 8001, 8002])
        for value in ('0', '65536', '10-1', '1-65535', '22,,80', '-1', 'abc'):
            with self.assertRaises(ValueError):
                cli.parse_ports(value)

    def test_real_loopback_tcp_connection_and_refusal(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            endpoint = listener.getsockname()
            listener.listen()
            connected = cli.connect(endpoint, 1)
        self.assertEqual(connected['observation'], 'connected')
        self.assertEqual(connected['source_address'], '127.0.0.1')
        with socket.socket() as bound_not_listening:
            bound_not_listening.bind(('127.0.0.1', 0))
            refused = cli.connect(bound_not_listening.getsockname(), 1)
        self.assertIn(refused['observation'], ('refused', 'timeout'))  # OS firewall may silently drop.

    def test_timeout_and_local_failure_are_distinct(self):
        for error, expected in [(TimeoutError(), 'timeout'), (OSError(errno.ECONNREFUSED, 'refused'), 'refused'), (OSError(errno.ENETUNREACH, 'unreachable'), 'local_or_network_error')]:
            with patch('external_probe.socket.socket') as factory:
                client = factory.return_value.__enter__.return_value
                client.connect.side_effect = error
                client.getsockname.return_value = ('0.0.0.0', 0)
                self.assertEqual(cli.connect(('8.8.8.8', 443), 1)['observation'], expected)

    def test_real_ipv6_loopback_connection(self):
        try:
            listener = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        except OSError:
            self.skipTest('IPv6 sockets unavailable')
        with listener:
            try:
                listener.bind(('::1', 0))
            except OSError:
                self.skipTest('IPv6 loopback unavailable')
            listener.listen()
            endpoint = ('::1', listener.getsockname()[1])
            # Verify platform permission with an independent native socket first.
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as control:
                    control.settimeout(1)
                    control.connect(endpoint)
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EAFNOSUPPORT):
                    self.skipTest('OS/network policy blocks native IPv6 loopback: ' + str(error))
                raise
            observation = cli.connect(endpoint, 1)
            self.assertEqual(observation['observation'], 'connected')
            self.assertEqual(observation['family'], 'IPv6')

    def test_ipv6_family_is_explicit(self):
        report = audit_fixture()
        result = probe_fixture(report, target='2606:4700:4700::1111')
        # Imported timestamps are normalized for the UTC report column.
        offset = datetime.timezone(datetime.timedelta(hours=2))
        for field in ('started_at_utc', 'finished_at_utc'):
            result[field] = datetime.datetime.fromisoformat(result[field]).astimezone(offset).isoformat()
        row = result['results'][0]
        row['observed_at_utc'] = datetime.datetime.fromisoformat(row['observed_at_utc']).astimezone(offset).isoformat()
        self.assertEqual(result['results'][0]['family'], 'IPv6')
        observation = external.merge(report, [result])['checks']['external_verification']['observations'][0]
        self.assertEqual(observation['exposure'], 'externally reachable')
        self.assertTrue(observation['observed_at_utc'].endswith('+00:00'))

    def test_merge_preserves_source_and_marks_untested_inventory_unknown(self):
        report = audit_fixture()
        original = copy.deepcopy(report)
        result = probe_fixture(report)
        result['raw_secret'] = 'PRIVATE_SENTINEL'
        result['location'] = '<img src=x onerror=alert(1)>'
        result['results'][0]['banner'] = 'PRIVATE_SENTINEL'
        merged = external.merge(report, [result])
        check = merged['checks']['external_verification']
        self.assertEqual(report, original)
        self.assertEqual(check['status'], 'partial')
        self.assertEqual(check['observations'][0]['exposure'], 'externally reachable')
        self.assertIn('listener 0.0.0.0:443 | nginx', check['observations'][0]['local_candidates'])
        self.assertEqual({item['port'] for item in check['observations'] if item['exposure'] == 'unknown'}, {53, 9000, 8080})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps(merged))
        self.assertNotIn(result['location'], reporting.render_html(merged))
        self.assertIn('&lt;img', reporting.render_html(merged))
        self.assertEqual(merged['summary'], {'REVIEW': 1, 'UNKNOWN': 1})

    def test_negative_results_never_claim_protection(self):
        report = audit_fixture()
        for observation in ('refused', 'timeout', 'local_or_network_error'):
            check = external.merge(report, [probe_fixture(report, observation=observation)])['checks']['external_verification']
            expected = 'unknown' if observation == 'local_or_network_error' else 'not observed from this probe'
            self.assertEqual(check['observations'][0]['exposure'], expected)

    def test_unconfirmed_source_or_nonpublic_target_is_unknown(self):
        report = audit_fixture()
        for independent, target in [(False, '8.8.8.8'), (True, '127.0.0.1'), (True, '192.168.1.1')]:
            check = external.merge(report, [probe_fixture(report, independent, target)])['checks']['external_verification']
            self.assertEqual(check['observations'][0]['exposure'], 'unknown')
            self.assertTrue(check['observations'][0]['reason'])

    def test_import_rejects_mismatch_duplicate_missing_and_inconsistent_evidence(self):
        report = audit_fixture()
        good = probe_fixture(report)
        bad_results = []
        for mutate in [lambda p: p['audit'].update(host='other'), lambda p: p.update(results=[]),
                       lambda p: p['results'][0].update(family='IPv6'), lambda p: p['results'][0].update(port=80),
                       lambda p: p['results'][0].update(observation='secure'), lambda p: p.update(independent='yes'),
                       lambda p: p.update(finished_at_utc='2099-01-01T00:00:00+00:00'),
                       lambda p: p['results'][0].update(observed_at_utc='2000-01-01T00:00:00+00:00')]:
            bad = copy.deepcopy(good)
            mutate(bad)
            bad_results.append(bad)
        for bad in bad_results:
            with self.assertRaises(ValueError):
                external.merge(report, [bad])
        with self.assertRaises(ValueError):
            external.merge(report, [good, good])
        with self.assertRaises(ValueError):
            external.merge(external.merge(report, [good]), [good])

    def test_stale_snapshot_preserves_observation_but_flags_correlation(self):
        report = audit_fixture()
        report['timestamp_utc'] = '2000-01-01T00:00:00+00:00'
        merged = external.merge(report, [probe_fixture(report)])
        self.assertTrue(any('fresh audit' in item['message'] for item in merged['findings']))

    def test_input_size_duplicate_keys_and_nonobjects_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'input.json'
            for value, limit in [('{}', 1), ('{"x":1,"x":2}', 100), ('[]', 100)]:
                path.write_text(value)
                with self.assertRaises(ValueError):
                    external.load_json(path, limit)

    def test_cli_dry_run_and_offline_import_never_open_sockets(self):
        report = audit_fixture()
        result = probe_fixture(report)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            audit_path, result_path = root/'audit.json', root/'probe.json'
            audit_path.write_text(json.dumps(report))
            result_path.write_text(json.dumps(result))
            for arguments in [
                ['probe', '--audit', str(audit_path), '--target', '8.8.8.8', '--location', 'office', '--dry-run'],
                ['import', '--audit', str(audit_path), '--results', str(result_path), '--export', str(root/'exports')],
            ]:
                with patch('sys.argv', ['external_probe.py', *arguments]), patch('external_probe.socket.socket') as network, contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(), 0)
                    network.assert_not_called()
            bundle = next((root/'exports').iterdir())
            self.assertEqual(json.loads((bundle/'manifest.json').read_text())['status'], 'complete')
            html = (bundle/'report.html').read_text(encoding='utf-8')
            self.assertIn('externally reachable', html)
            self.assertIn('Same-port local candidates (unverified)', html)
            self.assertIn('external_verification', reporting.render_text(json.loads((bundle/'data/report.json').read_text())))

    def test_existing_output_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            audit_path, output = root/'audit.json', root/'probe.json'
            audit_path.write_text(json.dumps(audit_fixture()))
            output.write_text('retain')
            args = ['external_probe.py', 'probe', '--audit', str(audit_path), '--target', '8.8.8.8', '--ports', '443', '--location', 'office', '--output', str(output)]
            with patch('sys.argv', args), patch.object(cli, 'connect') as network, contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(), 1)
                network.assert_not_called()
            self.assertEqual(output.read_text(), 'retain')

    def test_probe_cli_private_output_and_complete_contract(self):
        with tempfile.TemporaryDirectory() as folder, socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            root = Path(folder)
            report = audit_fixture()
            audit_path, output = root/'audit.json', root/'probe.json'
            audit_path.write_text(json.dumps(report))
            args = ['external_probe.py', 'probe', '--audit', str(audit_path), '--target', '127.0.0.1', '--ports', str(listener.getsockname()[1]), '--location', 'loopback test', '--output', str(output)]
            with patch('sys.argv', args), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(), 0)
            checked = external.validate_probe(json.loads(output.read_text()), report)
            self.assertEqual(checked['results'][0]['observation'], 'connected')
            if os.name == 'posix':
                self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
