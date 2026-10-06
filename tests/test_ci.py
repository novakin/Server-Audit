"""Exercise CI policy without native tools, network access or host collection."""

import contextlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import ci


class CIPolicyTests(unittest.TestCase):
    def result(self, *, count=1, successful=True, skipped=()):
        return SimpleNamespace(testsRun=count, wasSuccessful=lambda: successful, skipped=list(skipped))

    def test_only_named_prepared_lab_skips_are_allowed(self):
        allowed = [(Mock(id=Mock(return_value=name)), 'Prepared lab not enabled') for name in ci.ALLOWED_SKIPS]
        self.assertEqual(ci.result_problems(self.result(skipped=allowed)), [])
        unexpected = Mock(id=Mock(return_value='tests.test_git_reader.ReaderTests.test_fixture'))
        problems = ci.result_problems(self.result(skipped=[(unexpected, 'Missing prerequisite')]))
        self.assertEqual(len(problems), 1)
        self.assertIn('Unexpected skip', problems[0])

    def test_zero_tests_and_unsuccessful_results_fail(self):
        self.assertEqual(ci.result_problems(self.result()), [])
        self.assertIn('No tests were run.', ci.result_problems(self.result(count=0)))
        self.assertIn('The test suite did not pass.', ci.result_problems(self.result(successful=False)))

    def test_preflight_requires_linux_tools_root_directory_and_no_live_lab(self):
        root = Path(ci.__file__).resolve().parents[1]
        with patch.object(ci.platform, 'system', return_value='Linux'), \
                patch.object(ci.shutil, 'which', return_value='/fixture/tool'), \
                patch.object(ci.Path, 'cwd', return_value=root), \
                patch.dict(os.environ, {'AUDIT_LIVE_INTEGRATION': '0'}):
            ci.preflight()
            with patch.object(ci.platform, 'system', return_value='Windows'), self.assertRaises(RuntimeError):
                ci.preflight()
            with patch.dict(os.environ, {'AUDIT_LIVE_INTEGRATION': '1'}), self.assertRaises(RuntimeError):
                ci.preflight()
            with patch.object(ci.Path, 'cwd', return_value=root / 'tests'), self.assertRaises(RuntimeError):
                ci.preflight()
            for tool in ('git', 'ssh-keygen'):
                with self.subTest(tool=tool), patch.object(ci.shutil, 'which',
                        side_effect=lambda name: None if name == tool else '/fixture/tool'):
                    with self.assertRaisesRegex(RuntimeError, tool):
                        ci.preflight()

    def test_preflight_failure_exits_before_discovery(self):
        with patch.object(ci, 'preflight', side_effect=RuntimeError('Missing prerequisite')), \
                patch.object(ci.unittest.defaultTestLoader, 'discover') as discover, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ci.main(), 1)
        discover.assert_not_called()

    def test_main_propagates_result_policy(self):
        for successful in (True, False):
            result = self.result(successful=successful)
            result.failures = [] if successful else [('fixture', 'failed')]
            result.errors = []
            with self.subTest(successful=successful), patch.object(ci, 'preflight'), \
                    patch.object(ci.subprocess, 'run', return_value=SimpleNamespace(stdout='git fixture')), \
                    patch.object(ci.unittest.defaultTestLoader, 'discover') as discover, \
                    patch.object(ci.unittest, 'TextTestRunner') as runner, \
                    patch.dict(os.environ, {'GITHUB_STEP_SUMMARY': ''}), \
                    contextlib.redirect_stdout(io.StringIO()):
                runner.return_value.run.return_value = result
                self.assertEqual(ci.main(), 0 if successful else 1)
                runner.return_value.run.assert_called_once_with(discover.return_value)
