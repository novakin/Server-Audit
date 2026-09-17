"""Run the routine Linux suite with explicit prerequisite and skip policy.

Invoke from the repository root with ``python -m tests.ci``. This is a
standard-library test runner, not a host-audit or lab-provisioning command.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import unittest


# These tests require a separately prepared disposable lab, not a hosted runner.
ALLOWED_SKIPS = frozenset({
    'tests.test_live_integrations.LiveIntegrationTests.test_native_ssh_configuration_match_and_successful_login',
    'tests.test_live_integrations.LiveIntegrationTests.test_native_docker_projection_running_stopped_and_redaction',
    'tests.test_live_integrations.LiveIntegrationTests.test_native_firewall_rules_are_collected',
    'tests.test_live_integrations.LiveIntegrationTests.test_native_socket_owner_and_loopback_binding',
})


def preflight():
    if platform.system() != 'Linux':
        raise RuntimeError('Routine CI requires Linux; use ordinary unittest for portable local checks.')
    if Path.cwd().resolve() != Path(__file__).resolve().parents[1]:
        raise RuntimeError('Run python -m tests.ci from the repository root.')
    if os.environ.get('AUDIT_LIVE_INTEGRATION') == '1':
        raise RuntimeError('Routine CI must not enable the prepared-lab tests.')
    for tool in ('git', 'ssh-keygen'):
        if shutil.which(tool) is None:
            raise RuntimeError(f'Required CI prerequisite is missing: {tool}. Nothing was installed.')


def result_problems(result):
    problems = []
    if result.testsRun == 0:
        problems.append('No tests were run.')
    if not result.wasSuccessful():
        problems.append('The test suite did not pass.')
    for test, reason in result.skipped:
        if test.id() not in ALLOWED_SKIPS:
            problems.append(f'Unexpected skip: {test.id()}: {reason}')
    return problems


def main():
    try:
        preflight()
        git_version = subprocess.run(
            ['git', '--version'], capture_output=True, text=True, check=True, timeout=10,
        ).stdout.strip()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(f'CI preflight failed: {error}', file=sys.stderr)
        return 1

    print(f'Environment: {platform.platform()}; Python {platform.python_version()}; {git_version}', flush=True)
    print(f'Tested revision: {os.environ.get("GITHUB_SHA", "local working tree")}', flush=True)
    print(f'PR head revision: {os.environ.get("AUDIT_CI_HEAD_SHA", "not supplied")}', flush=True)
    suite = unittest.defaultTestLoader.discover('tests', top_level_dir='.')
    result = unittest.TextTestRunner(verbosity=2, durations=10).run(suite)
    problems = result_problems(result)
    summary = ['## Routine Linux tests', '',
               f'Tests run: {result.testsRun}; failures: {len(result.failures)}; '
               f'errors: {len(result.errors)}; skipped: {len(result.skipped)}.', '']
    summary.extend(f'- Skipped `{test.id()}`: {reason}' for test, reason in result.skipped)
    summary.extend(f'- **Failure:** {problem}' for problem in problems)
    summary.append('\nResult: **failed**.' if problems else '\nResult: **passed**.')
    text = '\n'.join(summary) + '\n'
    print(text)
    summary_path = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary_path:
        with Path(summary_path).open('a', encoding='utf-8') as output:
            output.write(text)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
