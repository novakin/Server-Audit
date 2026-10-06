"""Bounded local Git plumbing; never run repository configuration or filters."""

from contextlib import contextmanager
import os
from pathlib import Path
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


CHUNK_BYTES = 64 * 1024
STOP_SECONDS = 5


class GitReadError(RuntimeError):
    """A reader failure with a safe, non-payload diagnostic."""


class GitReadLimit(GitReadError):
    """The selected repository exhausted a collection budget."""


class GitShutdownError(RuntimeError):
    """Reader termination is unconfirmed; abort rather than continue auditing."""


class GitShutdownInterrupted(KeyboardInterrupt):
    """Cancellation with unconfirmed reader termination."""


def remaining(deadline):
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise GitReadLimit('Repository time budget reached.')
    return seconds


def read_local_file(path, maximum):
    """Refuse links and special files before reading bounded metadata."""
    for part in (path, *path.parents):
        if part.is_symlink():
            raise GitReadError('Symlink metadata paths are not followed.')
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise GitReadError('Metadata is not a regular file.')
        data = source.read(maximum + 1)
    if len(data) > maximum:
        raise GitReadLimit('Metadata file exceeds the byte limit.')
    return data


def stop_reader(process):
    """Stop the private process group, then reap within a bounded grace period."""
    try:
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass
        process.wait(timeout=STOP_SECONDS)
    except (OSError, subprocess.TimeoutExpired):
        raise GitShutdownError(
            f'Cannot confirm shutdown of Git reader PID {process.pid}; audit aborted.'
        ) from None
    except KeyboardInterrupt:
        raise GitShutdownInterrupted(
            f'Shutdown of Git reader PID {process.pid} interrupted; termination unconfirmed.'
        ) from None


class GitProcess:
    """One pipe reader with bounded buffering, a deadline and explicit ownership."""

    def __init__(self, command, environment, directory, deadline):
        self.command = command
        self.environment = environment
        self.directory = directory
        self.deadline = deadline
        self.buffer = bytearray()
        self.eof = False
        self.stderr_seen = False
        self.stderr_eof = False
        self.process = None

    def __enter__(self):
        remaining(self.deadline)
        self.process = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=self.environment, cwd=self.directory,
            bufsize=0, start_new_session=os.name == 'posix',
        )
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
        except (OSError, KeyboardInterrupt) as error:
            self.__exit__(type(error), error, error.__traceback__)
            raise
        return self

    def __exit__(self, error_type, error, traceback):
        try:
            if self.process.returncode is None:
                try:
                    stop_reader(self.process)
                except (GitShutdownError, GitShutdownInterrupted) as shutdown:
                    detail = str(shutdown)
                    if isinstance(error, (GitShutdownError, GitShutdownInterrupted)):
                        detail = str(error) + ' ' + detail
                    if isinstance(error, KeyboardInterrupt) or isinstance(shutdown, KeyboardInterrupt):
                        raise GitShutdownInterrupted(detail) from None
                    raise GitShutdownError(detail) from None
        finally:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    stream.close()
                except OSError:
                    pass  # Closing a pipe must not replace cancellation/shutdown evidence.

    def _discard_stderr(self):
        # Remember only the presence of diagnostics, not their secret-bearing text.
        chunk = os.read(self.process.stderr.fileno(), CHUNK_BYTES)
        if chunk:
            self.stderr_seen = True
        else:
            self.stderr_eof = True

    def _fill(self):
        streams = []
        if not self.eof:
            streams.append(self.process.stdout)
        if not self.stderr_eof:
            streams.append(self.process.stderr)
        readable, _, _ = select.select(streams, [], [], remaining(self.deadline))
        if not readable:
            raise GitReadLimit('Repository time budget reached while reading Git output.')
        if self.process.stderr in readable:
            self._discard_stderr()
        if self.process.stdout in readable:
            chunk = os.read(self.process.stdout.fileno(), CHUNK_BYTES)
            if chunk:
                self.buffer.extend(chunk)
            else:
                self.eof = True

    def line(self, maximum=256):
        while True:
            remaining(self.deadline)
            end = self.buffer.find(b'\n')
            if end >= 0:
                if end > maximum:
                    raise GitReadError('Git returned an oversized protocol header.')
                value = bytes(self.buffer[:end])
                del self.buffer[:end + 1]
                return value
            if len(self.buffer) > maximum:
                raise GitReadError('Git returned an oversized protocol header.')
            if self.eof:
                if self.buffer:
                    raise GitReadError('Git returned a truncated protocol header.')
                return None
            self._fill()

    def exact(self, size):
        data = bytearray()
        while len(data) < size:
            remaining(self.deadline)
            if self.buffer:
                count = min(size - len(data), len(self.buffer))
                data.extend(self.buffer[:count])
                del self.buffer[:count]
            elif self.eof:
                raise GitReadError('Git returned truncated object content.')
            else:
                self._fill()
        return bytes(data)

    def all(self, maximum):
        while not self.eof:
            remaining(self.deadline)
            if len(self.buffer) > maximum:
                raise GitReadError('Git metadata output exceeds the byte limit.')
            self._fill()
        if len(self.buffer) > maximum:
            raise GitReadError('Git metadata output exceeds the byte limit.')
        data = bytes(self.buffer)
        self.buffer.clear()
        return data

    def write(self, data):
        position = 0
        while position < len(data):
            streams = [] if self.stderr_eof else [self.process.stderr]
            readable, writable, _ = select.select(streams, [self.process.stdin], [], remaining(self.deadline))
            if not readable and not writable:
                raise GitReadLimit('Repository time budget reached while requesting a Git object.')
            if readable:
                self._discard_stderr()
            if not writable:
                continue
            try:
                written = os.write(self.process.stdin.fileno(), data[position:position + 4096])
            except BlockingIOError:
                continue
            if written == 0:
                raise GitReadError('Git reader stopped accepting object requests.')
            position += written

    def finish(self, accepted=(0,)):
        self.process.stdin.close()
        # Drain both pipes before waiting: even an exit-zero reader may diagnose
        # incomplete storage, including after its final stdout byte.
        while True:
            if self.buffer:
                raise GitReadError('Git returned unexpected output after the requested data.')
            if self.eof and self.stderr_eof:
                break
            self._fill()
        try:
            code = self.process.wait(timeout=remaining(self.deadline))
        except subprocess.TimeoutExpired:
            raise GitReadLimit('Repository time budget reached while waiting for Git.') from None
        if code not in accepted:
            raise GitReadError('Git could not read the selected data; raw diagnostics withheld.')
        if self.stderr_seen:
            raise GitReadError('Git emitted diagnostics; coverage is unconfirmed. Raw diagnostics withheld.')
        return code


def environment(directory, objects=None):
    """Do not inherit Git configuration, tracing, injected commands or loader settings."""
    values = {
        'PATH': os.environ.get('PATH', os.defpath), 'LC_ALL': 'C',
        'HOME': str(directory), 'XDG_CONFIG_HOME': str(directory),
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': os.devnull,
        'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_NO_LAZY_FETCH': '1',
        'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0',
        'GIT_TERMINAL_PROMPT': '0', 'GIT_ALLOW_PROTOCOL': '',
        'GIT_PROTOCOL_FROM_USER': '0',
    }
    if objects is not None:
        values['GIT_OBJECT_DIRECTORY'] = str(objects)
    return values


def command(executable, directory, *arguments):
    return [executable, '--no-pager', '--no-replace-objects',
            '--git-dir=' + str(directory), *arguments]


@contextmanager
def repository_view():
    """Create only safe reader metadata; never copy credentials or inspected objects."""
    directory = Path(tempfile.mkdtemp(prefix='server-audit-git-reader-'))
    cleanup_safe = True
    try:
        (directory / 'objects').mkdir(mode=0o700)
        (directory / 'refs').mkdir(mode=0o700)
        (directory / 'HEAD').write_text('ref: refs/heads/audit-unused\n', encoding='ascii')
        (directory / 'config').write_text('[core]\nrepositoryformatversion = 0\nbare = true\n', encoding='ascii')
        yield directory
    except (GitShutdownError, GitShutdownInterrupted) as error:
        cleanup_safe = False
        detail = f'{error} Reader workspace retained at {directory}; confirm termination before removal.'
        if isinstance(error, KeyboardInterrupt):
            raise GitShutdownInterrupted(detail) from None
        raise GitShutdownError(detail) from None
    finally:
        if cleanup_safe:
            active_error = sys.exc_info()[1]
            try:
                shutil.rmtree(directory)
            except OSError:
                if active_error is None:
                    raise GitReadError(f'Reader workspace cleanup failed at {directory}; inspect locally.') from None


def object_format(executable, directory, config_path, deadline):
    """Parse only storage-format keys. Includes and all source-repository policy are ignored."""
    args = command(executable, directory, 'config', '--no-includes', '--null', '--file', str(config_path),
                   '--get-regexp', r'^(core\.repositoryformatversion$|extensions\.)')
    with GitProcess(args, environment(directory), directory, deadline) as reader:
        data = reader.all(4096)
        reader.finish(accepted=(0, 1))
    if data and not data.endswith(b'\0'):
        raise GitReadError('Git storage-format metadata is truncated.')
    values = {}
    for record in data.split(b'\0')[:-1]:
        key, separator, value = record.partition(b'\n')
        if not key or (not separator and key != b'extensions.worktreeconfig'):
            raise GitReadError('Git storage-format metadata is invalid.')
        # NUL ends a record; only the first newline separates key and value.
        # None (implicit true) is distinct from b'' (explicitly empty/false).
        values[key] = value if separator else None
    if values.get(b'core.repositoryformatversion', b'0') not in (b'0', b'1'):
        raise GitReadError('Unsupported Git repository format version.')
    supported = {b'extensions.objectformat', b'extensions.partialclone',
                 b'extensions.worktreeconfig', b'extensions.refstorage'}
    if any(key.startswith(b'extensions.') and key not in supported for key in values):
        raise GitReadError('Unsupported Git storage extension; object coverage is unknown.')
    if b'extensions.worktreeconfig' in values:
        # Let Git validate all its boolean spellings, including numeric values,
        # without loading includes or activating source-repository settings.
        args = command(executable, directory, 'config', '--no-includes', '--null',
                       '--type=bool', '--file', str(config_path), '--get', 'extensions.worktreeconfig')
        with GitProcess(args, environment(directory), directory, deadline) as reader:
            boolean = reader.all(16)
            reader.finish()
        if boolean not in (b'true\0', b'false\0'):
            raise GitReadError('Git boolean storage metadata is invalid.')
    algorithm = values.get(b'extensions.objectformat', b'sha1')
    if algorithm not in (b'sha1', b'sha256'):
        raise GitReadError('Unsupported Git object hash format.')
    if algorithm == b'sha256':
        (directory / 'config').write_text(
            '[core]\nrepositoryformatversion = 1\nbare = true\n'
            '[extensions]\nobjectformat = sha256\n', encoding='ascii',
        )
    return algorithm.decode('ascii'), b'extensions.partialclone' in values
