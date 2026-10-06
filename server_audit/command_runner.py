"""Bounded, shell-free host command execution on Linux."""

import locale
import os
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time


STDOUT_BYTES = 8 * 1024 * 1024
STDERR_BYTES = 1024 * 1024
COMMAND_SECONDS = 30
CHUNK_BYTES = 64 * 1024
STOP_SECONDS = 5


class CommandShutdownError(RuntimeError):
    """Child shutdown is unconfirmed; the audit must not continue."""


class CommandShutdownInterrupted(KeyboardInterrupt):
    """Cancellation with unconfirmed child shutdown."""


class _CaptureError(Exception):
    """A bounded-capture failure whose diagnostic contains no output."""


def _stop_process(process):
    """Stop the owned group, including descendants retaining output pipes."""
    interrupted = False
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except OSError:
            pass  # Still attempt the stronger stop and confirm it below.
        except KeyboardInterrupt:
            interrupted = True
        try:
            process.wait(timeout=0.2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        except KeyboardInterrupt:
            interrupted = True
        # The parent may have exited while a descendant still owns a pipe.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=STOP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        failure = CommandShutdownInterrupted if interrupted else CommandShutdownError
        raise failure(
            f'Cannot confirm shutdown of command PID {process.pid}; audit aborted.'
        ) from None
    except KeyboardInterrupt:
        raise CommandShutdownInterrupted(
            f'Shutdown of command PID {process.pid} interrupted; termination unconfirmed.'
        ) from None
    if interrupted:
        raise KeyboardInterrupt


def _remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise _CaptureError('Command exceeded its time limit; captured output withheld.')
    return seconds


def _capture(process, input_data, deadline):
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    limits = {'stdout': STDOUT_BYTES, 'stderr': STDERR_BYTES}
    position = 0
    with selectors.DefaultSelector() as selector:
        for name in output:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        if process.stdin is not None:
            if input_data:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, 'stdin')
            else:
                process.stdin.close()
        while selector.get_map():
            events = selector.select(_remaining(deadline))
            if not events:
                _remaining(deadline)
                continue
            for key, _ in events:
                _remaining(deadline)
                if key.data == 'stdin':
                    try:
                        written = os.write(key.fd, input_data[position:position + CHUNK_BYTES])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        written = 0
                    position += written
                    if not written or position == len(input_data):
                        selector.unregister(key.fileobj)
                        process.stdin.close()
                    continue
                data = output[key.data]
                # Read at most one byte beyond the remaining allowance.
                size = min(CHUNK_BYTES, limits[key.data] - len(data) + 1)
                try:
                    chunk = os.read(key.fd, size)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                elif len(chunk) > limits[key.data] - len(data):
                    raise _CaptureError(
                        f'Command {key.data} exceeded its byte limit; captured output withheld.'
                    )
                else:
                    data.extend(chunk)
        try:
            process.wait(timeout=_remaining(deadline))
        except subprocess.TimeoutExpired:
            raise _CaptureError('Command exceeded its time limit; captured output withheld.') from None
    return output


def _text(data, encoding):
    # Match subprocess text mode, including universal newline translation.
    return data.decode(encoding, errors='replace').replace('\r\n', '\n').replace('\r', '\n').strip()


def run(argv, input_text=None):
    executable = shutil.which(argv[0])
    if not executable:
        return {'status': 'unavailable', 'detail': 'Command not installed: ' + argv[0]}
    encoding = locale.getpreferredencoding(False)
    input_data = None if input_text is None else input_text.encode(encoding, errors='replace')
    process = None
    completed = False
    close_failed = False
    interrupted = False
    original_handler = signal.getsignal(signal.SIGINT)
    handler_changed = False

    def defer_interrupt(signum, frame):
        nonlocal interrupted
        interrupted = True

    try:
        deadline = time.monotonic() + COMMAND_SECONDS
        # SIGINT between fork and constructor return otherwise leaves no owned
        # Popen handle. Exec resets this Python handler in the native child.
        if threading.current_thread() is threading.main_thread() and original_handler is signal.default_int_handler:
            signal.signal(signal.SIGINT, defer_interrupt)
            handler_changed = True
        try:
            process = subprocess.Popen(
                [executable, *argv[1:]], stdin=subprocess.PIPE if input_data is not None else None,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                env={**os.environ, 'LC_ALL': 'C'}, start_new_session=True,
            )
            # Restore and replay only after entering the owned-child guard.
            if handler_changed:
                signal.signal(signal.SIGINT, original_handler)
                handler_changed = False
            if interrupted:
                raise KeyboardInterrupt
            output = _capture(process, input_data, deadline)
            completed = True
        finally:
            try:
                if handler_changed:
                    signal.signal(signal.SIGINT, original_handler)
                if interrupted and process is None:
                    raise KeyboardInterrupt
            finally:
                try:
                    if process is not None and not completed:
                        active_error = sys.exc_info()[1]
                        try:
                            _stop_process(process)
                        except CommandShutdownError as error:
                            if isinstance(active_error, KeyboardInterrupt):
                                raise CommandShutdownInterrupted(str(error)) from None
                            raise
                finally:
                    if process is not None:
                        for stream in (process.stdin, process.stdout, process.stderr):
                            if stream is not None:
                                try:
                                    stream.close()
                                except OSError:
                                    close_failed = True
    except _CaptureError as error:
        return {'status': 'error', 'detail': str(error)}
    except OSError:
        return {'status': 'error', 'detail': 'Command I/O failed; captured output withheld.'}
    if close_failed:
        return {'status': 'error', 'detail': 'Command pipe cleanup failed; captured output withheld.'}
    return {
        'status': 'ok' if process.returncode == 0 else 'error',
        'exit_code': process.returncode,
        'output': _text(output['stdout'], encoding),
        'detail': _text(output['stderr'], encoding),
    }
