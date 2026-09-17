"""Failure isolation and scanner lifecycle regressions; synthetic inputs only."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import git_secrets
import system_audit
from test_runner import HostPath, fixture_report


def clean_scan(executable, root, mode, scratch):
    return {'mode': 'history' if mode == 'git' else 'working_directory',
            'status': 'ok', 'detections': []}


class OSFailureTests(unittest.TestCase):
    def test_read_failure_is_evidence_not_platform_fallback(self):
        for error in (PermissionError('denied'), OSError('read failed'), UnicodeError('invalid text')):
            with self.subTest(error=type(error).__name__), patch('system_audit.Path') as path, patch('system_audit.platform.platform') as fallback:
                path.return_value.read_text.side_effect = error
                check = system_audit.collect_os()
                self.assertEqual(check['status'], 'error')
                self.assertIn(str(error), check['detail'])
                fallback.assert_not_called()

    def test_missing_os_release_preserves_existing_fallback(self):
        with patch('system_audit.Path') as path, patch('system_audit.platform.platform', return_value='platform fixture'):
            path.return_value.read_text.side_effect = FileNotFoundError()
            self.assertEqual(system_audit.collect_os(), {'status': 'ok', 'output': 'platform fixture'})

    def test_programming_errors_are_not_swallowed(self):
        with patch('system_audit.Path') as path:
            path.return_value.read_text.side_effect = TypeError('programming defect')
            with self.assertRaises(TypeError):
                system_audit.collect_os()

    def test_failed_os_collection_preserves_later_checks_and_summary(self):
        with patch.object(HostPath, 'read_text', side_effect=PermissionError('fixture denied')):
            report, _ = fixture_report()
        self.assertEqual(report['checks']['os']['status'], 'error')
        self.assertIn('ports', report['checks'])
        self.assertIn('git_secrets', report['checks'])
        self.assertTrue(any(item['level'] == 'UNKNOWN' and item['message'].startswith('os:') for item in report['findings']))
        self.assertEqual(report['summary']['UNKNOWN'], sum(item['level'] == 'UNKNOWN' for item in report['findings']))


class ScannerScratchTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / 'repository'
        (self.root / '.git').mkdir(parents=True)

    def test_creation_failure_is_unknown_and_never_launches_scanner(self):
        with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', side_effect=OSError('PRIVATE_SENTINEL')), patch('git_secrets.scan_mode') as scan:
            report, findings = git_secrets.collect([str(self.root)])
        scan.assert_not_called()
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(report['repositories'][0]['status'], 'error')
        self.assertEqual(report['repositories'][0]['scans'], [])
        self.assertTrue(any(item['level'] == 'UNKNOWN' for item in findings))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_each_control_file_write_failure_cleans_scratch(self):
        native_write = Path.write_text
        for filename in ('config.toml', '.gitleaksignore'):
            with self.subTest(filename=filename):
                scratch = tempfile.TemporaryDirectory(dir=self.directory.name)
                self.addCleanup(scratch.cleanup)
                def write(path, *args, **kwargs):
                    if path.name == filename:
                        raise OSError('PRIVATE_SENTINEL')
                    return native_write(path, *args, **kwargs)
                with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', return_value=scratch.name), patch.object(Path, 'write_text', autospec=True, side_effect=write), patch('git_secrets.scan_mode') as scan:
                    report, findings = git_secrets.collect([str(self.root)])
                scan.assert_not_called()
                self.assertFalse(Path(scratch.name).exists())
                self.assertEqual(report['status'], 'partial')
                self.assertEqual(report['repositories'][0]['status'], 'error')
                self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_cleanup_failure_retains_scan_evidence_and_private_path(self):
        scratch = tempfile.TemporaryDirectory(dir=self.directory.name)
        self.addCleanup(scratch.cleanup)
        with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', return_value=scratch.name), patch('git_secrets.shutil.rmtree', side_effect=OSError('PRIVATE_SENTINEL')), patch('git_secrets.scan_mode', side_effect=clean_scan):
            report, findings = git_secrets.collect([str(self.root)])
        repository = report['repositories'][0]
        self.assertEqual(report['status'], 'partial')
        self.assertEqual(repository['status'], 'partial')
        self.assertEqual(repository['cleanup_status'], 'error')
        self.assertEqual(repository['scratch_path'], scratch.name)
        self.assertEqual(len(repository['scans']), 2)
        self.assertTrue(all(scan['status'] == 'ok' for scan in repository['scans']))
        self.assertTrue(any('cleanup failed' in item['message'] and item['level'] == 'UNKNOWN' for item in findings))
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))
        if os.name == 'posix':
            self.assertEqual(Path(scratch.name).stat().st_mode & 0o777, 0o700)

    def test_one_repository_failure_does_not_stop_the_next(self):
        second = Path(self.directory.name) / 'second'
        (second / '.git').mkdir(parents=True)
        scratch = tempfile.TemporaryDirectory(dir=self.directory.name)
        self.addCleanup(scratch.cleanup)
        with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', side_effect=[OSError('denied'), scratch.name]), patch('git_secrets.scan_mode', side_effect=clean_scan):
            report, findings = git_secrets.collect([str(self.root), str(second)])
        self.assertEqual([item['status'] for item in report['repositories']], ['error', 'ok'])
        self.assertEqual(len(report['repositories'][1]['scans']), 2)
        self.assertEqual(report['status'], 'partial')
        self.assertTrue(findings)

    def test_cleanup_does_not_mask_interruption_or_programming_error(self):
        for error in (KeyboardInterrupt(), TypeError('programming defect')):
            with self.subTest(error=type(error).__name__):
                scratch = tempfile.TemporaryDirectory(dir=self.directory.name)
                self.addCleanup(scratch.cleanup)
                with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', return_value=scratch.name), patch('git_secrets.shutil.rmtree', side_effect=OSError('cleanup failed')) as cleanup, patch('git_secrets.scan_mode', side_effect=error):
                    with self.assertRaises(type(error)):
                        git_secrets.collect([str(self.root)])
                cleanup.assert_called_once()

    def test_partial_scans_survive_later_io_failure(self):
        first = {'mode': 'history', 'status': 'ok', 'detections': [
            {'rule': 'fixture-rule', 'file': 'fixture.txt', 'start_line': 1, 'end_line': 1, 'commit': 'abc'}]}
        with patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.scan_mode', side_effect=[first, OSError('PRIVATE_SENTINEL')]):
            report, findings = git_secrets.collect([str(self.root)])
        self.assertEqual(report['repositories'][0]['scans'], [first])
        self.assertEqual(report['repositories'][0]['status'], 'partial')
        self.assertEqual({item['level'] for item in findings}, {'REVIEW', 'UNKNOWN'})
        self.assertNotIn('PRIVATE_SENTINEL', json.dumps([report, findings]))

    def test_runner_retains_other_evidence_after_scanner_setup_failure(self):
        with patch('audit_runner.collect_git_secrets', side_effect=lambda roots: git_secrets.collect([str(self.root)])), patch('git_secrets.shutil.which', return_value='fixture-scanner'), patch('git_secrets.tempfile.mkdtemp', side_effect=OSError('fixture failure')):
            report, _ = fixture_report()
        self.assertEqual(report['checks']['git_secrets']['status'], 'partial')
        self.assertEqual(report['checks']['ssh']['status'], 'ok')
        self.assertEqual(report['checks']['ports']['status'], 'ok')
        self.assertTrue(any('scratch' in item['message'] and item['level'] == 'UNKNOWN' for item in report['findings']))


class ScannerProcessTests(unittest.TestCase):
    def test_timeout_and_interrupt_use_the_same_cleanup(self):
        for error in (subprocess.TimeoutExpired('fixture', 120), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), patch('git_secrets.subprocess.Popen') as factory, patch('git_secrets._stop_scanner') as stop:
                process = factory.return_value
                process.wait.side_effect = error
                if isinstance(error, KeyboardInterrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        git_secrets.execute(['fixture'])
                else:
                    self.assertIsNone(git_secrets.execute(['fixture']))
                stop.assert_called_once_with(process)

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process-group handling')
    def test_exit_signal_race_still_reaps_scanner(self):
        process = Mock(pid=12345)
        with patch('git_secrets.os.killpg', side_effect=ProcessLookupError()) as kill:
            git_secrets._stop_scanner(process)
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        process.wait.assert_called_once_with()

    def test_success_preserves_suppressed_output_and_sanitized_environment(self):
        with patch.dict(os.environ, {'GIT_CONFIG_COUNT': '1', 'GITLEAKS_CONFIG': 'PRIVATE_SENTINEL'}), patch('git_secrets.subprocess.Popen') as factory:
            process = factory.return_value
            process.returncode = 0
            self.assertEqual(git_secrets.execute(['fixture']), 0)
        kwargs = factory.call_args.kwargs
        self.assertEqual(kwargs['stdout'], subprocess.DEVNULL)
        self.assertEqual(kwargs['stderr'], subprocess.DEVNULL)
        self.assertEqual(kwargs['start_new_session'], os.name == 'posix')
        self.assertNotIn('GIT_CONFIG_COUNT', kwargs['env'])
        self.assertNotIn('GITLEAKS_CONFIG', kwargs['env'])
        self.assertEqual(kwargs['env']['GIT_TERMINAL_PROMPT'], '0')

    @unittest.skipUnless(os.name == 'posix', 'POSIX SIGINT and process-group integration')
    def test_real_sigint_stops_and_reaps_synthetic_scanner(self):
        child_code = 'import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)'
        wrapper = (
            'import sys; import git_secrets\n'
            'try:\n'
            '    git_secrets.execute([sys.executable, "-c", sys.argv[1], sys.argv[2]])\n'
            'except KeyboardInterrupt:\n'
            '    print("interrupted", flush=True)\n'
            'else:\n'
            '    raise SystemExit("interruption did not propagate")\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'scanner.pid'
            parent = subprocess.Popen([sys.executable, '-c', wrapper, child_code, str(marker)],
                                      cwd=Path(__file__).resolve().parent,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      text=True, start_new_session=True)
            child_pid = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if marker.exists() and marker.read_text().strip():
                        child_pid = int(marker.read_text())
                        break
                    if parent.poll() is not None:
                        self.fail('Scanner wrapper exited before readiness: ' + str(parent.communicate(timeout=5)))
                    time.sleep(0.01)
                self.assertIsNotNone(child_pid, 'Synthetic scanner did not become ready')
                self.assertEqual(os.getpgid(child_pid), child_pid)
                os.kill(parent.pid, signal.SIGINT)
                stdout, stderr = parent.communicate(timeout=5)
                self.assertEqual(parent.returncode, 0, stderr)
                self.assertEqual(stdout.strip(), 'interrupted')
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
            finally:
                if child_pid is not None:
                    try:
                        os.killpg(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if parent.poll() is None:
                    parent.kill()
                parent.communicate(timeout=5)


if __name__ == '__main__':
    unittest.main()
