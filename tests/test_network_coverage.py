import unittest

from server_audit.collectors import network_audit


class SocketCoverageTests(unittest.TestCase):
    def collect(self, output):
        calls = []
        def run(command):
            calls.append(command)
            return {'status': 'ok', 'output': output, 'detail': ''}
        result = network_audit.collect_ports(run)
        self.assertEqual(calls, [['ss', '-H', '-lntup']])
        return result

    def test_empty_and_blank_output_are_successful_empty_inventories(self):
        for output in ('', '\n \t\n'):
            with self.subTest(output=output):
                check, findings = self.collect(output)
                self.assertEqual(check['status'], 'ok')
                self.assertEqual(check['output'], output)
                self.assertEqual(check['listeners'], [])
                self.assertEqual(check['parser_coverage'], {'status': 'ok', 'records_observed': 0,
                                                          'records_parsed': 0, 'records_unparsed': 0})
                self.assertEqual(findings, [])

    def test_short_nonempty_output_is_incomplete_without_inventing_listeners(self):
        output = 'unrecognized\ntcp LISTEN 0 128\n'
        check, findings = self.collect(output)
        self.assertEqual(check['status'], 'ok')
        self.assertEqual(check['output'], output)
        self.assertEqual(check['listeners'], [])
        self.assertEqual(check['parser_coverage'], {'status': 'partial', 'records_observed': 2,
                                                  'records_parsed': 0, 'records_unparsed': 2})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['level'], 'UNKNOWN')
        self.assertIn('2 nonempty ss records', findings[0]['message'])
        self.assertEqual(network_audit.listeners(output), [])

    def test_mixed_output_preserves_inventory_owners_and_raw_output_once(self):
        output = '\n'.join([
            'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=10,fd=3))',
            'tcp LISTEN 0 128 [::1]:8000 [::]:*',
            'tcp LISTEN 0 128 [::ffff:127.0.0.1]:8080 [::]:*',
            'tcp LISTEN 0 128 [::]:22 [::]:* users:(("sshd",pid=20,fd=3),("systemd",pid=1,fd=60))',
            'udp UNCONN 0 0 10.0.0.5:53 0.0.0.0:*',
            'udp UNCONN 0 0 *:5353 *:*',
            'udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:*',
            'malformed record',
            '',
        ])
        check, findings = self.collect(output)
        self.assertEqual(check['status'], 'ok')
        self.assertEqual(check['output'], output)
        self.assertEqual(check['listeners'], network_audit.listeners(output))
        self.assertEqual(check['parser_coverage'], {'status': 'partial', 'records_observed': 8,
                                                  'records_parsed': 7, 'records_unparsed': 1})
        self.assertEqual([item['binding'] == 'loopback' for item in check['listeners']],
                         [True, True, True, False, False, False, False])
        self.assertEqual(check['listeners'][0]['process'], 'users:(("postgres",pid=10,fd=3))')
        self.assertIn('unknown', check['listeners'][1]['process'])
        self.assertIn('systemd', check['listeners'][3]['process'])
        self.assertEqual([item['level'] for item in findings], ['UNKNOWN', 'REVIEW'])
        self.assertIn('4 non-loopback', findings[1]['message'])
        self.assertEqual(set(check), {'status', 'output', 'detail', 'listeners', 'parser_coverage'})

    def test_failed_command_does_not_treat_output_as_a_successful_inventory(self):
        original = {'status': 'error', 'output': 'Permission denied', 'detail': 'denied'}
        check, findings = network_audit.collect_ports(lambda command: original.copy())
        self.assertEqual(check, original)
        self.assertEqual(findings, [])

    def test_native_ipv6_variants_are_complete_without_process_owner_requirement(self):
        output = '\n'.join([
            'tcp LISTEN 0 128 [::ffff:127.0.0.1]:8080 [::]:*',
            'udp UNCONN 0 0 [fe80::1%eth0]:5353 [::]:* users:(("resolver",pid=30,fd=4))',
        ])
        check, findings = self.collect(output)
        self.assertEqual(check['parser_coverage'], {'status': 'ok', 'records_observed': 2,
                                                  'records_parsed': 2, 'records_unparsed': 0})
        self.assertEqual([item['level'] for item in findings], ['REVIEW'])
        self.assertEqual(check['listeners'][0]['binding'], 'loopback')
        self.assertIn('resolver', check['listeners'][1]['process'])


if __name__ == '__main__':
    unittest.main()
