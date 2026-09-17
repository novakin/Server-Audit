"""Scanner cancellation and scratch ownership, using synthetic processes only."""

import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import audit
import git_secrets
from test_runner import fixture_report


class ScannerShutdownTests(unittest.TestCase):
    def test_interrupt_survives_shutdown_oserror(self):
        process = MagicMock(pid=12345)
        process.__enter__.return_value = process
        process.wait.side_effect = KeyboardInterrupt()
        with patch('git_secrets.subprocess.Popen', return_value=process), patch(
            'git_secrets._stop_scanner', side_effect=PermissionError('PRIVATE_SENTINEL')
        ):
            with self.assertRaises(KeyboardInterrupt) as caught:
                git_secrets.execute(['fixture'])
        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_interrupt_survives_reaping_oserror(self):
        process = MagicMock(pid=12345)
        process.__enter__.return_value = process
        process.wait.side_effect = [KeyboardInterrupt(), OSError('PRIVATE_SENTINEL')]
        with patch('git_secrets.subprocess.Popen', return_value=process), patch('git_secrets.os.killpg'):
            with self.assertRaises(KeyboardInterrupt) as caught:
                git_secrets.execute(['fixture'])
        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        self.assertEqual(process.wait.call_count, 2)

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_timeout_shutdown_failure_is_fatal(self):
        process = MagicMock(pid=12345)
        process.wait.side_effect = subprocess.TimeoutExpired('fixture', 120)
        with patch('git_secrets.subprocess.Popen', return_value=process), patch(
            'git_secrets.os.killpg', side_effect=PermissionError('PRIVATE_SENTINEL')
        ):
            with self.assertRaises(git_secrets.ScannerShutdownError) as caught:
                git_secrets.execute(['fixture'])
        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        process.__exit__.assert_not_called()
        self.assertEqual(process.wait.call_count, 1)

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_second_interrupt_during_stop_marks_shutdown_unconfirmed(self):
        process = MagicMock(pid=12345)
        process.wait.side_effect = [KeyboardInterrupt(), KeyboardInterrupt()]
        with patch('git_secrets.subprocess.Popen', return_value=process), patch('git_secrets.os.killpg'):
            with self.assertRaises(git_secrets.ScannerShutdownInterrupted):
                git_secrets.execute(['fixture'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_wait_oserror_still_stops_and_reaps_scanner(self):
        process = MagicMock(pid=12345)
        process.wait.side_effect = [OSError('PRIVATE_SENTINEL'), 0]
        with patch('git_secrets.subprocess.Popen', return_value=process), patch('git_secrets.os.killpg') as kill:
            self.assertIsNone(git_secrets.execute(['fixture']))
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(process.wait.call_count, 2)

    def test_launch_oserror_remains_an_ordinary_scan_failure(self):
        with patch('git_secrets.subprocess.Popen', side_effect=OSError('PRIVATE_SENTINEL')):
            self.assertIsNone(git_secrets.execute(['fixture']))

    def test_unconfirmed_shutdown_retains_scratch_and_stops_later_repositories(self):
        for failure in (git_secrets.ScannerShutdownError, git_secrets.ScannerShutdownInterrupted):
            with self.subTest(failure=failure.__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'repository'
                second = Path(directory) / 'second'
                (root / '.git').mkdir(parents=True)
                (second / '.git').mkdir(parents=True)
                scratch = Path(directory) / 'private-scratch'
                scratch.mkdir(mode=0o700)
                with patch('git_secrets.shutil.which', return_value='fixture'), patch(
                    'git_secrets.tempfile.mkdtemp', return_value=str(scratch)
                ), patch('git_secrets.scan_mode', side_effect=failure('Scanner PID 12345.')) as scan, patch(
                    'git_secrets.shutil.rmtree'
                ) as cleanup:
                    with self.assertRaises(failure) as caught:
                        git_secrets.collect([str(root), str(second)])
                    cleanup.assert_not_called()
                scan.assert_called_once()
                self.assertIn(str(scratch), str(caught.exception))
                self.assertTrue((scratch / 'config.toml').exists())
                self.assertTrue((scratch / '.gitleaksignore').exists())
                if os.name == 'posix':
                    self.assertEqual(scratch.stat().st_mode & 0o777, 0o700)

    def test_successful_stop_cleans_scratch_before_propagating_interruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repository'
            (root / '.git').mkdir(parents=True)
            scratch = Path(directory) / 'private-scratch'
            scratch.mkdir(mode=0o700)
            with patch('git_secrets.shutil.which', return_value='fixture'), patch(
                'git_secrets.tempfile.mkdtemp', return_value=str(scratch)
            ), patch('git_secrets.scan_mode', side_effect=KeyboardInterrupt()):
                with self.assertRaises(KeyboardInterrupt):
                    git_secrets.collect([str(root)])
            self.assertFalse(scratch.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_stop_and_reap_precede_scratch_cleanup(self):
        events = []
        process = MagicMock(pid=12345)
        native_remove = shutil.rmtree

        def wait(timeout=None):
            if timeout is not None:
                events.append('interrupted')
                raise KeyboardInterrupt()
            events.append('reaped')
            return -signal.SIGKILL

        def remove(path):
            events.append('cleanup')
            native_remove(path)

        process.wait.side_effect = wait
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'repository'
            (root / '.git').mkdir(parents=True)
            with patch('git_secrets.shutil.which', return_value='fixture'), patch(
                'git_secrets.subprocess.Popen', return_value=process
            ), patch('git_secrets.os.killpg', side_effect=lambda *args: events.append('stopped')), patch(
                'git_secrets.shutil.rmtree', side_effect=remove
            ):
                with self.assertRaises(KeyboardInterrupt):
                    git_secrets.collect([str(root)])
        self.assertEqual(events, ['interrupted', 'stopped', 'reaped', 'cleanup'])

    @unittest.skipUnless(os.name == 'posix', 'POSIX scanner process groups')
    def test_failed_shutdown_aborts_runner_and_never_exports(self):
        cases = (
            (KeyboardInterrupt(), KeyboardInterrupt),
            (subprocess.TimeoutExpired('fixture', 120), git_secrets.ScannerShutdownError),
        )
        for wait_error, expected in cases:
            with self.subTest(error=type(wait_error).__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / 'repository'
                (root / '.git').mkdir(parents=True)
                scratch = Path(directory) / 'private-scratch'
                scratch.mkdir(mode=0o700)
                process = MagicMock(pid=12345)
                process.wait.side_effect = wait_error
                with patch.dict(os.environ), patch('sys.argv', ['audit.py', '--export', directory]), patch(
                    'audit.platform.system', return_value='Linux'
                ), patch('audit.audit', side_effect=lambda *args: fixture_report()[0]), patch(
                    'audit_runner.collect_git_secrets', side_effect=lambda roots: git_secrets.collect([str(root)])
                ), patch('audit_runner.summarize') as summarize, patch('audit.export_report') as export, patch(
                    'git_secrets.shutil.which', return_value='fixture'
                ), patch('git_secrets.tempfile.mkdtemp', return_value=str(scratch)), patch(
                    'git_secrets.subprocess.Popen', return_value=process
                ) as launch, patch('git_secrets.os.killpg', side_effect=PermissionError('PRIVATE_SENTINEL')):
                    with self.assertRaises(expected) as caught:
                        audit.main()
                launch.assert_called_once()
                summarize.assert_not_called()
                export.assert_not_called()
                self.assertTrue(scratch.exists())
                self.assertIn(str(scratch), str(caught.exception))
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    @unittest.skipUnless(os.name == 'posix', 'POSIX SIGINT integration')
    def test_real_sigint_propagates_when_group_signal_is_denied(self):
        child_code = (
            'import os,sys,time; from pathlib import Path; '
            'Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)'
        )
        # Retain the actual Popen object so the test wrapper can stop and reap
        # its child after observing the deliberately failed production shutdown.
        wrapper = '''
import os
import signal
import subprocess
import sys
from unittest.mock import patch
import git_secrets

native_popen = subprocess.Popen
children = []
def launch(*args, **kwargs):
    child = native_popen(*args, **kwargs)
    children.append(child)
    return child

try:
    with patch('git_secrets.subprocess.Popen', side_effect=launch), patch(
        'git_secrets.os.killpg', side_effect=PermissionError('PRIVATE_SENTINEL')
    ):
        try:
            git_secrets.execute([sys.executable, '-c', sys.argv[1], sys.argv[2]])
        except KeyboardInterrupt as error:
            print('interrupted', flush=True)
            print(str(error), flush=True)
        else:
            raise SystemExit('Cancellation became a scan result')
finally:
    for child in children:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)
'''
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / 'scanner.pid'
            parent = subprocess.Popen(
                [sys.executable, '-c', wrapper, child_code, str(marker)],
                cwd=Path(__file__).resolve().parent,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, start_new_session=True,
            )
            child_pid = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if marker.exists() and marker.read_text().strip():
                        child_pid = int(marker.read_text())
                        break
                    if parent.poll() is not None:
                        self.fail('Wrapper exited before readiness: ' + str(parent.communicate(timeout=5)))
                    time.sleep(0.01)
                self.assertIsNotNone(child_pid, 'Synthetic scanner did not become ready')
                os.kill(parent.pid, signal.SIGINT)
                stdout, stderr = parent.communicate(timeout=5)
                self.assertEqual(parent.returncode, 0, stderr)
                self.assertTrue(stdout.startswith('interrupted\n'), stdout)
                self.assertIn('Cannot confirm shutdown of scanner PID', stdout)
                self.assertNotIn('PRIVATE_SENTINEL', stdout + stderr)
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
