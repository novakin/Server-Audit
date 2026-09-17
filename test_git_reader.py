"""Reader bounds, ownership and cancellation; synthetic processes and private fixtures."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

import git_reader


class ReaderUnitTests(unittest.TestCase):
    def test_environment_is_allowlisted_and_disables_network_and_overrides(self):
        injected = {'GIT_TRACE': '/fixture/trace', 'GIT_SSH_COMMAND': 'PRIVATE_SENTINEL',
                    'GIT_CONFIG_COUNT': '1', 'LD_PRELOAD': '/fixture/lib.so'}
        with patch.dict(os.environ, injected):
            env = git_reader.environment(Path('/fixture/view'), Path('/fixture/objects'))
        self.assertTrue(set(injected).isdisjoint(env))
        self.assertEqual(env['GIT_ALLOW_PROTOCOL'], '')
        self.assertEqual(env['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], os.devnull)
        self.assertEqual(env['GIT_CONFIG_SYSTEM'], os.devnull)
        self.assertEqual(env['GIT_OBJECT_DIRECTORY'], '/fixture/objects')

    def test_failed_launch_is_visible_not_success(self):
        with patch('git_reader.subprocess.Popen', side_effect=OSError('PRIVATE_SENTINEL')):
            with self.assertRaises(OSError):
                with git_reader.GitProcess(['fixture'], {}, '.', time.monotonic() + 5):
                    self.fail('Reader must not start')

    @unittest.skipUnless(os.name == 'posix', 'POSIX process groups')
    def test_exit_signal_race_still_reaps_with_bounded_grace(self):
        process = Mock(pid=12345)
        with patch('git_reader.os.killpg', side_effect=ProcessLookupError()):
            git_reader.stop_reader(process)
        process.wait.assert_called_once_with(timeout=git_reader.STOP_SECONDS)

    @unittest.skipUnless(os.name == 'posix', 'POSIX process groups')
    def test_failed_signalling_is_fatal_and_diagnostic_is_redacted(self):
        process = Mock(pid=12345)
        with patch('git_reader.os.killpg', side_effect=PermissionError('PRIVATE_SENTINEL')):
            with self.assertRaises(git_reader.GitShutdownError) as caught:
                git_reader.stop_reader(process)
        self.assertIn('12345', str(caught.exception))
        self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))

    def test_failed_reaping_and_second_interrupt_are_fatal(self):
        cases = [(OSError('PRIVATE_SENTINEL'), git_reader.GitShutdownError),
                 (subprocess.TimeoutExpired('fixture', 5), git_reader.GitShutdownError),
                 (KeyboardInterrupt(), git_reader.GitShutdownInterrupted)]
        for error, expected in cases:
            process = Mock(pid=12345)
            process.wait.side_effect = error
            with self.subTest(error=type(error).__name__), patch('git_reader.os.killpg', create=True):
                with self.assertRaises(expected):
                    git_reader.stop_reader(process)

    def test_cancellation_is_preserved_when_shutdown_fails(self):
        reader = git_reader.GitProcess(['fixture'], {}, '.', time.monotonic() + 5)
        reader.process = Mock(returncode=None)
        with patch('git_reader.stop_reader', side_effect=git_reader.GitShutdownError('safe diagnostic')):
            with self.assertRaises(git_reader.GitShutdownInterrupted):
                reader.__exit__(KeyboardInterrupt, KeyboardInterrupt(), None)
        reader.process.stdin.close.assert_called_once()
        reader.process.stdout.close.assert_called_once()

    def test_nested_shutdown_failures_preserve_both_reader_diagnostics(self):
        reader = git_reader.GitProcess(['fixture'], {}, '.', time.monotonic() + 5)
        reader.process = Mock(returncode=None)
        original = git_reader.GitShutdownInterrupted('Reader PID 111 unconfirmed.')
        failure = git_reader.GitShutdownError('Reader PID 222 unconfirmed.')
        with patch('git_reader.stop_reader', side_effect=failure):
            with self.assertRaises(git_reader.GitShutdownInterrupted) as caught:
                reader.__exit__(type(original), original, None)
        self.assertIn('111', str(caught.exception))
        self.assertIn('222', str(caught.exception))

    def test_pipe_setup_failure_stops_the_already_started_reader(self):
        with patch('git_reader.subprocess.Popen') as factory:
            process = factory.return_value
            process.returncode = None
            with patch('git_reader.os.set_blocking', side_effect=OSError('fixture')), patch('git_reader.stop_reader') as stop:
                with self.assertRaises(OSError):
                    with git_reader.GitProcess(['fixture'], {}, '.', time.monotonic() + 5):
                        self.fail('Pipe setup must fail')
        stop.assert_called_once_with(process)

    def test_unconfirmed_shutdown_retains_workspace(self):
        for error in (git_reader.GitShutdownError('safe error'), git_reader.GitShutdownInterrupted('safe interruption')):
            directory = None
            try:
                with self.subTest(error=type(error).__name__), self.assertRaises(type(error)) as caught:
                    with git_reader.repository_view() as directory:
                        raise error
                self.assertTrue(directory.exists())
                self.assertIn(str(directory), str(caught.exception))
                self.assertNotIn('PRIVATE_SENTINEL', (directory / 'config').read_text())
                if os.name == 'posix':
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            finally:
                if directory is not None:
                    git_reader.shutil.rmtree(directory)

    def test_confirmed_shutdown_and_normal_interruption_clean_workspace(self):
        with git_reader.repository_view() as directory:
            self.assertTrue(directory.exists())
        self.assertFalse(directory.exists())
        with self.assertRaises(KeyboardInterrupt):
            with git_reader.repository_view() as directory:
                raise KeyboardInterrupt()
        self.assertFalse(directory.exists())

    def test_workspace_cleanup_error_does_not_mask_interruption(self):
        directory = None
        try:
            with patch('git_reader.shutil.rmtree', side_effect=OSError('PRIVATE_SENTINEL')):
                with self.assertRaises(KeyboardInterrupt):
                    with git_reader.repository_view() as directory:
                        raise KeyboardInterrupt()
        finally:
            if directory is not None:
                git_reader.shutil.rmtree(directory)

    def test_workspace_cleanup_error_on_success_is_not_silent(self):
        directory = None
        try:
            with patch('git_reader.shutil.rmtree', side_effect=OSError('PRIVATE_SENTINEL')):
                with self.assertRaises(git_reader.GitReadError) as caught:
                    with git_reader.repository_view() as directory:
                        pass
                self.assertIn(str(directory), str(caught.exception))
                self.assertNotIn('PRIVATE_SENTINEL', str(caught.exception))
        finally:
            if directory is not None:
                git_reader.shutil.rmtree(directory)

    @unittest.skipUnless(os.name == 'posix', 'POSIX regular-file policy')
    def test_metadata_links_special_files_and_oversize_are_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            regular = root / 'config'
            regular.write_bytes(b'PRIVATE_SENTINEL')
            link = root / 'link'
            link.symlink_to(regular)
            fifo = root / 'fifo'
            os.mkfifo(fifo)
            for path in (link, fifo):
                with self.assertRaises(git_reader.GitReadError):
                    git_reader.read_local_file(path, 100)
            with self.assertRaises(git_reader.GitReadLimit):
                git_reader.read_local_file(regular, 1)


@unittest.skipUnless(os.name == 'posix', 'POSIX pipe/process integration')
class ReaderProcessTests(unittest.TestCase):
    def reader(self, code, seconds=5):
        return git_reader.GitProcess([sys.executable, '-c', code], {}, '.', time.monotonic() + seconds)

    def test_protocol_reads_split_headers_binary_content_and_eof(self):
        code = "import os,time; os.write(1,b'header\\nabc\\x00def\\n'); time.sleep(.01)"
        with self.reader(code) as reader:
            self.assertEqual(reader.line(), b'header')
            self.assertEqual(reader.exact(7), b'abc\x00def')
            self.assertEqual(reader.exact(1), b'\n')
            self.assertIsNone(reader.line())
            reader.finish()

    def test_timeout_kills_and_reaps_a_stalled_reader(self):
        started = time.monotonic()
        with self.assertRaises(git_reader.GitReadLimit):
            with self.reader('import time; time.sleep(30)', seconds=.05) as reader:
                reader.line()
        self.assertIsNotNone(reader.process.returncode)
        self.assertLess(time.monotonic() - started, 3)

    def test_output_and_header_limits_stop_reader_before_unbounded_capture(self):
        for method in ('line', 'all'):
            with self.subTest(method=method), self.assertRaises(git_reader.GitReadError):
                with self.reader("import os,time; os.write(1,b'x'*65536); time.sleep(30)") as reader:
                    getattr(reader, method)(128)
            self.assertIsNotNone(reader.process.returncode)
            self.assertLessEqual(len(reader.buffer), git_reader.CHUNK_BYTES + 128)

    def test_truncated_content_and_nonzero_exit_are_not_clean(self):
        with self.assertRaises(git_reader.GitReadError):
            with self.reader("print('a',end='',flush=True)") as reader:
                reader.exact(10)
        with self.assertRaises(git_reader.GitReadError):
            with self.reader('raise SystemExit(4)') as reader:
                self.assertEqual(reader.all(100), b'')
                reader.finish()

    def test_stderr_is_never_captured(self):
        code = "import os; os.write(2,b'PRIVATE_SENTINEL'); os.write(1,b'ok\\n')"
        with self.reader(code) as reader:
            self.assertEqual(reader.all(100), b'ok\n')
            reader.finish()

    def test_real_sigint_stops_reader_and_preserves_denied_shutdown(self):
        child = "import os,sys,time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(30)"
        wrapper = """
import contextlib,os,signal,sys,time
from unittest.mock import patch
import git_reader
deny_stop = sys.argv[3] == 'denied'
reader = None
failure = patch('git_reader.os.killpg', side_effect=PermissionError('PRIVATE_SENTINEL')) if deny_stop else contextlib.nullcontext()
try:
    with failure:
        with git_reader.GitProcess([sys.executable, '-c', sys.argv[1], sys.argv[2]], {}, '.', time.monotonic()+30) as reader:
            reader.line()
except git_reader.GitShutdownInterrupted:
    if not deny_stop:
        raise SystemExit('unexpected unconfirmed shutdown')
    print('unconfirmed', flush=True)
except KeyboardInterrupt:
    if deny_stop:
        raise SystemExit('shutdown failure was hidden')
    print('interrupted', flush=True)
else:
    raise SystemExit('cancellation was lost')
finally:
    # Test harness only: undo the injected denial, then stop/reap the child.
    if reader is not None and reader.process.returncode is None:
        try:
            os.killpg(reader.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        reader.process.wait(timeout=5)
"""
        for mode, expected in (('normal', 'interrupted'), ('denied', 'unconfirmed')):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                marker = Path(folder) / 'reader.pid'
                parent = subprocess.Popen(
                    [sys.executable, '-c', wrapper, child, str(marker), mode],
                    cwd=Path(__file__).parent, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, start_new_session=True,
                )
                child_pid = None
                try:
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if marker.exists() and marker.read_text().strip():
                            child_pid = int(marker.read_text())
                            break
                        time.sleep(.01)
                    self.assertIsNotNone(child_pid)
                    self.assertEqual(os.getpgid(child_pid), child_pid)
                    os.kill(parent.pid, signal.SIGINT)
                    stdout, stderr = parent.communicate(timeout=5)
                    self.assertEqual(parent.returncode, 0, stderr)
                    self.assertEqual(stdout.strip(), expected)
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
