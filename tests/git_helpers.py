"""Small native-Git fixture operations; callers own scope and assertions."""

from pathlib import Path
import shutil
import subprocess

from server_audit.collectors import git_reader


def run_git(root, *arguments, data=None):
    executable = shutil.which('git')
    if executable is None:
        raise RuntimeError('Git fixture requires an installed Git executable.')
    result = subprocess.run(
        [executable, '-c', 'commit.gpgsign=false', '-C', str(root), *arguments],
        input=data, env=git_reader.environment(root), capture_output=True,
        check=True, timeout=10,
    )
    return result.stdout


def init_repository(root, algorithm='sha1', bare=False):
    root = Path(root)
    root.mkdir(exist_ok=True)
    arguments = ['init', '--quiet', '--object-format=' + algorithm]
    if bare:
        arguments.append('--bare')
    run_git(root, *arguments)
    return root if bare else root / '.git'


def snapshot(root):
    return {str(path.relative_to(root)): path.read_bytes()
            for path in root.rglob('*') if path.is_file()}
