"""Strict runner for the four prepared-lab tests; never provisions a host."""

import os
import platform
import sys
import unittest

from tests.ci import ALLOWED_SKIPS


def result_problems(result):
    problems = []
    if result.testsRun != len(ALLOWED_SKIPS):
        problems.append('Not all expected live tests ran.')
    if not result.wasSuccessful() or result.expectedFailures:
        problems.append('All live tests must pass, without expected failures.')
    if result.skipped:
        problems.append('Live integration must not skip tests.')
    return problems


def main():
    if os.environ.get('AUDIT_LIVE_INTEGRATION') != '1':
        print('The live lab must be explicitly enabled.', file=sys.stderr)
        return 1
    suite = unittest.defaultTestLoader.loadTestsFromName(
        'tests.test_live_integrations.LiveIntegrationTests',
    )
    # The same identities skipped by routine CI are required here.
    if {test.id() for test in suite} != ALLOWED_SKIPS:
        print('Live test identities differ from the routine CI skip policy.', file=sys.stderr)
        return 1
    print(f'Live environment: {platform.platform()}; Python {platform.python_version()}', flush=True)
    print(f'Tested revision: {os.environ.get("GITHUB_SHA", "local working tree")}', flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    problems = result_problems(result)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == '__main__':
    sys.exit(main())
