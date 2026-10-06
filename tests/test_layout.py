"""Copy-and-run checks for the package layout; no real host audit or remote probe."""

import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def sample_report():
    return {
        'schema_version': 1, 'host': 'layout-fixture',
        'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'checks': {'ssh': {'status': 'ok', 'output': 'port 22'}},
        'findings': [], 'summary': {'REVIEW': 0, 'UNKNOWN': 0}, 'limitations': [],
    }


class LayoutTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.runtime = self.directory / 'runtime copy'
        self.runtime.mkdir()
        self.caller = self.directory / 'caller'
        self.caller.mkdir()
        for name in ('audit.py', 'external_probe.py'):
            shutil.copy2(ROOT / name, self.runtime / name)
        shutil.copytree(ROOT / 'server_audit', self.runtime / 'server_audit',
                        ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '*.pyo'))
        self.environment = os.environ.copy()
        self.environment.pop('PYTHONPATH', None)
        self.environment['PYTHONDONTWRITEBYTECODE'] = '1'

    def run_python(self, *arguments, cwd=None):
        result = subprocess.run(
            [sys.executable, *map(str, arguments)], cwd=cwd or self.caller,
            env=self.environment, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_both_launchers_and_subcommands_work_outside_runtime_directory(self):
        for name, arguments in (
            ('audit.py', ('--help',)), ('external_probe.py', ('--help',)),
            ('external_probe.py', ('probe', '--help')),
            ('external_probe.py', ('import', '--help')),
        ):
            with self.subTest(name=name, arguments=arguments):
                result = self.run_python(self.runtime / name, *arguments)
                self.assertIn('usage:', result.stdout)
                self.assertEqual(result.stderr, '')
        self.assertFalse((self.runtime / 'tests').exists())
        self.assertFalse((self.runtime / 'docs').exists())
        self.assertEqual(list(self.caller.iterdir()), [])

    def test_package_initializers_do_not_import_collectors_or_run_commands(self):
        # This process starts in the copied runtime, not in the source checkout.
        code = '''
import sys
from unittest.mock import patch
with patch('subprocess.Popen', side_effect=AssertionError('Unexpected process')):
    import server_audit
    import server_audit.collectors
assert sorted(name for name in sys.modules if name.startswith('server_audit')) == [
    'server_audit', 'server_audit.collectors']
'''
        self.run_python('-c', code, cwd=self.runtime)

    def test_launchers_delegate_exit_codes_without_running_audit_logic(self):
        for launcher, module in (('audit.py', 'cli'), ('external_probe.py', 'external_probe')):
            with self.subTest(launcher=launcher):
                code = '''
import runpy
import sys
from unittest.mock import patch
with patch(sys.argv[2], return_value=17) as main:
    try:
        runpy.run_path(sys.argv[1], run_name='__main__')
    except SystemExit as error:
        assert error.code == 17
    else:
        raise AssertionError('Launcher did not propagate exit code')
    main.assert_called_once_with()
'''
                self.run_python('-c', code, self.runtime / launcher,
                                f'server_audit.{module}.main', cwd=self.runtime)

    def test_host_launcher_exports_from_caller_directory_with_relative_scope(self):
        report = sample_report()
        (self.caller / 'fixture.json').write_text(json.dumps(report), encoding='utf-8')
        # The driver lives beside the launchers so it imports only the copied package.
        driver = self.runtime / 'synthetic_driver.py'
        driver.write_text('''
import json
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

report = json.loads(Path('fixture.json').read_text(encoding='utf-8'))
caller = Path.cwd()
launcher = Path(__file__).with_name('audit.py')
sys.argv = [str(launcher), '--json', '--export', 'reports',
            '--ssh-config', 'config/sshd.conf', '--git-root', 'repositories/app']
with patch('server_audit.cli.platform.system', return_value='Linux'), \\
        patch('server_audit.cli.audit', return_value=report) as collect, \\
        patch('subprocess.Popen', side_effect=AssertionError('Real host command')):
    try:
        runpy.run_path(str(launcher), run_name='__main__')
    except SystemExit as error:
        assert error.code == 0
    collect.assert_called_once_with(None, 'config/sshd.conf', None, ['repositories/app'], 60)
    assert Path.cwd() == caller
''', encoding='utf-8')
        result = self.run_python(driver)
        self.assertEqual(json.loads(result.stdout), report)
        self.assertIn('Audit exported:', result.stderr)
        bundle = next((self.caller / 'reports').iterdir())
        self.assertEqual(json.loads((bundle / 'data/report.json').read_text()), report)
        self.assertEqual(json.loads((bundle / 'manifest.json').read_text())['status'], 'complete')
        self.assertIn('Host security audit.', (bundle / 'report.html').read_text())
        self.assertFalse((self.runtime / 'reports').exists())

    def test_companion_dry_run_and_offline_import_from_caller_directory(self):
        report = sample_report()
        stamp = report['timestamp_utc']
        probe = {
            'probe_schema_version': 1,
            'audit': {key: report[key] for key in ('schema_version', 'host', 'timestamp_utc')},
            'targets': ['203.0.113.10'], 'ports': [443], 'location': 'synthetic fixture',
            'probe_host': 'fixture', 'independent': False, 'timeout_seconds': 2,
            'started_at_utc': stamp, 'finished_at_utc': stamp,
            'results': [{'target': '203.0.113.10', 'port': 443, 'family': 'IPv4',
                         'protocol': 'tcp', 'observation': 'refused',
                         'observed_at_utc': stamp, 'source_address': None}],
        }
        report_path = self.caller / 'fixture.json'
        report_path.write_text(json.dumps(report), encoding='utf-8')
        original = report_path.read_bytes()
        (self.caller / 'probe.json').write_text(json.dumps(probe), encoding='utf-8')
        # Guard sockets and child processes while executing the real copied launcher.
        driver = self.runtime / 'offline_driver.py'
        driver.write_text('''
from pathlib import Path
import runpy
import sys
from unittest.mock import patch
launcher = Path(__file__).with_name('external_probe.py')
sys.argv[0] = str(launcher)
with patch('socket.socket', side_effect=AssertionError('Unexpected network')), \\
        patch('subprocess.Popen', side_effect=AssertionError('Unexpected host command')):
    runpy.run_path(str(launcher), run_name='__main__')
''', encoding='utf-8')
        result = self.run_python(driver, 'probe', '--audit', 'fixture.json', '--target',
                                 '203.0.113.10', '--ports', '443', '--location', 'fixture', '--dry-run')
        self.assertEqual(json.loads(result.stdout)['tcp_ports'], [443])
        self.assertFalse((self.caller / 'exports').exists())
        self.run_python(driver, 'import', '--audit', 'fixture.json', '--results', 'probe.json',
                        '--export', 'exports')
        bundle = next((self.caller / 'exports').iterdir())
        self.assertEqual(json.loads((bundle / 'manifest.json').read_text())['status'], 'complete')
        self.assertIn('external_verification', json.loads((bundle / 'data/report.json').read_text())['checks'])
        self.assertEqual(report_path.read_bytes(), original)
        self.assertFalse((self.runtime / 'exports').exists())


if __name__ == '__main__':
    unittest.main()
