"""Synthetic POSIX commands exercise capture bounds and process ownership."""

import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from server_audit import command_runner


@unittest.skipUnless(sys.platform.startswith('linux'), 'Native command pipes require Linux')
class CommandRunnerTests(unittest.TestCase):
    def run_python(self, code, input_text=None):
        return command_runner.run([sys.executable, '-c', code], input_text)

    def assert_withheld(self, result, reason):
        self.assertEqual(result['status'], 'error')
        self.assertIn(reason, result['detail'])
        self.assertNotIn('output', result)
        self.assertNotIn('exit_code', result)
        self.assertNotIn('PRIVATE_PAYLOAD', str(result))

    def tracked_processes(self):
        processes = []
        original = subprocess.Popen

        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        return processes, patch.object(command_runner.subprocess, 'Popen', side_effect=start)

    def assert_stopped(self, processes):
        self.assertTrue(processes)
        for process in processes:
            self.assertIsNotNone(process.returncode)
            self.assertEqual(process.poll(), process.returncode)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    self.assertTrue(stream.closed)

    def test_normal_nonzero_preserves_stdout_and_permission_evidence(self):
        result = self.run_python(
            "import os; os.write(1, b' inventory \\r\\n'); "
            "os.write(2, b'Operation not permitted\\n'); raise SystemExit(1)"
        )
        self.assertEqual(result, {
            'status': 'error', 'exit_code': 1,
            'output': 'inventory', 'detail': 'Operation not permitted',
        })

    def test_text_mode_replacement_newlines_and_locale_are_preserved(self):
        result = self.run_python(
            "import os; os.write(1, b' a\\xff\\r\\nb\\rc '); "
            "os.write(2, os.environ['LC_ALL'].encode())"
        )
        self.assertEqual(result, {
            'status': 'ok', 'exit_code': 0, 'output': 'a\ufffd\nb\nc', 'detail': 'C',
        })

    def test_both_streams_at_exact_caps_complete(self):
        with patch.object(command_runner, 'STDOUT_BYTES', 8192), patch.object(command_runner, 'STDERR_BYTES', 4096):
            result = self.run_python("import os; os.write(1, b'o'*8192); os.write(2, b'e'*4096)")
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(len(result['output']), 8192)
        self.assertEqual(len(result['detail']), 4096)

    def test_cap_counts_bytes_before_text_decoding(self):
        with patch.object(command_runner, 'STDOUT_BYTES', 1):
            result = self.run_python("import os; os.write(1, b'\\xc3\\xa9')")
        self.assert_withheld(result, 'stdout exceeded its byte limit')

    def test_each_overflow_discards_both_streams_and_reaps_process(self):
        for stream in (1, 2):
            with self.subTest(stream=stream):
                processes, track = self.tracked_processes()
                with track, patch.object(command_runner, 'STDOUT_BYTES', 64), patch.object(command_runner, 'STDERR_BYTES', 64):
                    result = self.run_python(
                        "import os, time; os.write(1, b'PRIVATE_PAYLOAD'); "
                        "os.write(2, b'PRIVATE_PAYLOAD'); "
                        f"os.write({stream}, b'x'*65); time.sleep(60)"
                    )
                self.assert_withheld(result, 'byte limit')
                self.assert_stopped(processes)

    def test_simultaneous_large_streams_cannot_deadlock_capture(self):
        processes, track = self.tracked_processes()
        with track, patch.object(command_runner, 'STDOUT_BYTES', 8192), patch.object(command_runner, 'STDERR_BYTES', 8192):
            result = self.run_python(
                "import os, threading; "
                "t=threading.Thread(target=lambda: os.write(2, b'e'*262144)); "
                "t.start(); os.write(1, b'o'*262144); t.join()"
            )
        self.assert_withheld(result, 'byte limit')
        self.assert_stopped(processes)

    def test_timeout_with_partial_output_discards_it_and_reaps(self):
        processes, track = self.tracked_processes()
        with track, patch.object(command_runner, 'COMMAND_SECONDS', 0.2):
            result = self.run_python(
                "import os, time; os.write(1, b'PRIVATE_PAYLOAD'); "
                "os.write(2, b'PRIVATE_PAYLOAD'); time.sleep(60)"
            )
        self.assert_withheld(result, 'time limit')
        self.assert_stopped(processes)

    def test_timeout_after_output_eof_still_stops_live_process(self):
        processes, track = self.tracked_processes()
        with track, patch.object(command_runner, 'COMMAND_SECONDS', 0.2):
            result = self.run_python("import os, time; os.close(1); os.close(2); time.sleep(60)")
        self.assert_withheld(result, 'time limit')
        self.assert_stopped(processes)

    def test_cancellation_during_selector_read_propagates_after_cleanup(self):
        processes, track = self.tracked_processes()
        with track, patch.object(selectors.EpollSelector, 'select', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_python('import time; time.sleep(60)', 'input')
        self.assert_stopped(processes)

    def test_real_sigint_during_constructor_reaps_the_created_child(self):
        processes, track = self.tracked_processes()
        original_read = os.read
        original_handler = signal.getsignal(signal.SIGINT)
        self.assertIs(original_handler, signal.default_int_handler)
        delivered = False

        def interrupted_read(fd, size):
            nonlocal delivered
            if not delivered:
                delivered = True
                os.kill(os.getpid(), signal.SIGINT)
            return original_read(fd, size)

        with track, patch.object(command_runner.os, 'read', side_effect=interrupted_read):
            with self.assertRaises(KeyboardInterrupt):
                self.run_python('import time; time.sleep(60)')
        self.assertTrue(delivered)
        self.assertIs(signal.getsignal(signal.SIGINT), original_handler)
        self.assert_stopped(processes)

    def test_constructor_failure_restores_default_sigint_handler(self):
        original_handler = signal.getsignal(signal.SIGINT)

        def fail_start(*args, **kwargs):
            self.assertIsNot(signal.getsignal(signal.SIGINT), original_handler)
            raise OSError('PRIVATE_PAYLOAD')

        with patch.object(command_runner.subprocess, 'Popen', side_effect=fail_start):
            result = self.run_python('pass')
        self.assert_withheld(result, 'I/O failed')
        self.assertIs(signal.getsignal(signal.SIGINT), original_handler)

    def test_sigint_with_constructor_failure_keeps_cancellation(self):
        original_handler = signal.getsignal(signal.SIGINT)

        def fail_start(*args, **kwargs):
            os.kill(os.getpid(), signal.SIGINT)
            raise OSError('PRIVATE_PAYLOAD')

        with patch.object(command_runner.subprocess, 'Popen', side_effect=fail_start):
            with self.assertRaises(KeyboardInterrupt):
                self.run_python('pass')
        self.assertIs(signal.getsignal(signal.SIGINT), original_handler)

    def test_ignored_and_custom_sigint_handlers_are_preserved(self):
        original_handler = signal.getsignal(signal.SIGINT)
        for handler in (signal.SIG_IGN, lambda signum, frame: None):
            try:
                signal.signal(signal.SIGINT, handler)

                def capture(process, input_data, deadline):
                    self.assertEqual(signal.getsignal(signal.SIGINT), handler)
                    process.wait(timeout=5)
                    return {'stdout': bytearray(b'done'), 'stderr': bytearray()}

                with self.subTest(handler=handler), patch.object(command_runner, '_capture', side_effect=capture):
                    result = self.run_python('pass')
                self.assertEqual(signal.getsignal(signal.SIGINT), handler)
                self.assertEqual(result['output'], 'done')
            finally:
                signal.signal(signal.SIGINT, original_handler)

    def test_io_failure_discards_partial_output_and_reaps(self):
        processes, track = self.tracked_processes()
        original = command_runner.os.read
        captured = []

        def fail_read(fd, size):
            # Popen also reads its exec-error pipe before the child is returned.
            if processes:
                if captured:
                    raise OSError('PRIVATE_PAYLOAD')
                chunk = original(fd, size)
                captured.append(chunk)
                return chunk
            return original(fd, size)

        with track, patch.object(command_runner.os, 'read', side_effect=fail_read):
            result = self.run_python(
                "import os, time; os.write(1, b'PRIVATE_PAYLOAD'); "
                "os.write(2, b'PRIVATE_PAYLOAD'); time.sleep(60)"
            )
        self.assertEqual(captured, [b'PRIVATE_PAYLOAD'])
        self.assert_withheld(result, 'I/O failed')
        self.assert_stopped(processes)

    def test_large_input_is_written_while_both_output_pipes_are_drained(self):
        text = 'input' * 300000
        result = self.run_python(
            "import os, sys; os.write(1, b'o'*131072); os.write(2, b'e'*131072); "
            "data=sys.stdin.buffer.read(); os.write(1, str(len(data)).encode())",
            text,
        )
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['output'], 'o' * 131072 + str(len(text)))
        self.assertEqual(result['detail'], 'e' * 131072)

    def test_closed_stdin_does_not_hide_normal_command_result(self):
        result = self.run_python("import os; os.close(0); os.write(1, b'done')", 'x' * 1500000)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['output'], 'done')

    def test_empty_input_delivers_eof(self):
        result = self.run_python("import sys; print(len(sys.stdin.buffer.read()))", '')
        self.assertEqual(result['output'], '0')

    def test_missing_tool_does_not_spawn(self):
        with patch.object(command_runner.shutil, 'which', return_value=None), patch.object(command_runner.subprocess, 'Popen') as process:
            self.assertEqual(command_runner.run(['missing'])['status'], 'unavailable')
        process.assert_not_called()

    def test_launch_io_failure_withholds_exception_payload(self):
        with patch.object(command_runner.subprocess, 'Popen', side_effect=OSError('PRIVATE_PAYLOAD')):
            result = self.run_python('pass')
        self.assert_withheld(result, 'I/O failed')

    def test_unconfirmed_reap_is_fatal_even_after_capture_failure(self):
        process = Mock(pid=123)
        process.wait.side_effect = subprocess.TimeoutExpired('synthetic', 5)
        with patch.object(command_runner.os, 'killpg') as kill:
            with self.assertRaises(command_runner.CommandShutdownError):
                command_runner._stop_process(process)
        self.assertEqual(kill.call_args_list[-1].args, (123, signal.SIGKILL))

    def test_failed_group_kill_is_fatal_even_if_parent_has_exited(self):
        process = Mock(pid=123)
        with patch.object(command_runner.os, 'killpg', side_effect=PermissionError):
            with self.assertRaises(command_runner.CommandShutdownError):
                command_runner._stop_process(process)

    def test_interrupt_during_termination_still_kills_and_reaps(self):
        process = Mock(pid=123)
        process.wait.side_effect = [KeyboardInterrupt, 0]
        with patch.object(command_runner.os, 'killpg') as kill:
            with self.assertRaises(KeyboardInterrupt):
                command_runner._stop_process(process)
        self.assertEqual(kill.call_args_list[-1].args, (123, signal.SIGKILL))
        self.assertEqual(process.wait.call_count, 2)

    def test_interrupted_termination_then_failed_kill_or_reap_keeps_cancellation(self):
        for error in (PermissionError('kill denied'), subprocess.TimeoutExpired('synthetic', 5)):
            process = Mock(pid=123)
            process.wait.side_effect = [KeyboardInterrupt, subprocess.TimeoutExpired('synthetic', 5)]
            kill_errors = [None, error] if isinstance(error, OSError) else [None, None]
            with self.subTest(error=type(error).__name__), patch.object(command_runner.os, 'killpg', side_effect=kill_errors):
                with self.assertRaises(command_runner.CommandShutdownInterrupted):
                    command_runner._stop_process(process)

    def test_pipe_cleanup_failure_cannot_hide_unconfirmed_shutdown(self):
        process = Mock(pid=123)
        process.stdout.close.side_effect = OSError('PRIVATE_PAYLOAD')
        with patch.object(command_runner.subprocess, 'Popen', return_value=process), patch.object(command_runner, '_capture', side_effect=command_runner._CaptureError('byte limit')), patch.object(command_runner, '_stop_process', side_effect=command_runner.CommandShutdownError('unconfirmed')):
            with self.assertRaisesRegex(command_runner.CommandShutdownError, 'unconfirmed'):
                self.run_python('pass')
        process.stderr.close.assert_called_once()

    def test_cancelled_run_keeps_cancellation_when_shutdown_is_unconfirmed(self):
        process = Mock(pid=123)
        with patch.object(command_runner.subprocess, 'Popen', return_value=process), patch.object(command_runner, '_capture', side_effect=KeyboardInterrupt), patch.object(command_runner, '_stop_process', side_effect=command_runner.CommandShutdownError('unconfirmed')):
            with self.assertRaisesRegex(command_runner.CommandShutdownInterrupted, 'unconfirmed'):
                self.run_python('pass')
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_parent_exit_with_descendant_retaining_pipes_is_bounded(self):
        processes, track = self.tracked_processes()
        with tempfile.TemporaryDirectory() as directory:
            pid_file = Path(directory) / 'child.pid'
            code = (
                "import os, signal, time; pid=os.fork(); "
                "\nif pid == 0:\n"
                " signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f" open({str(pid_file)!r}, 'w').write(str(os.getpid()))\n"
                " time.sleep(60)\n"
                "else:\n os._exit(0)\n"
            )
            with track, patch.object(command_runner, 'COMMAND_SECONDS', 0.5):
                result = self.run_python(code)
            self.assert_withheld(result, 'time limit')
            self.assert_stopped(processes)
            self.assertTrue(pid_file.exists(), 'Synthetic descendant did not start')
            child = int(pid_file.read_text())
            # An orphan may remain a zombie until the system reaps it; it is stopped.
            stat_path = Path(f'/proc/{child}/stat')
            deadline = time.monotonic() + 2
            while stat_path.exists():
                try:
                    state = stat_path.read_text().split()[2]
                except FileNotFoundError:
                    break
                if state == 'Z':
                    break
                self.assertLess(time.monotonic(), deadline, 'Descendant survived process-group shutdown')
                time.sleep(0.01)


if __name__ == '__main__':
    unittest.main()
