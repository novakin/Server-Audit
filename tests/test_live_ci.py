"""Test the live runner's acceptance policy without preparing or using a lab."""

import contextlib
import io
import os
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from tests import live_ci


class LiveCIPolicyTests(unittest.TestCase):
    def result(self, *, count=4, successful=True, skipped=(), expected=()):
        return SimpleNamespace(testsRun=count, wasSuccessful=lambda: successful,
                               skipped=skipped, expectedFailures=expected)

    def test_requires_every_test_to_pass_without_skips_or_expected_failures(self):
        self.assertEqual(live_ci.result_problems(self.result()), [])
        for arguments in ({'count': 0}, {'count': 3}, {'count': 5},
                          {'successful': False}, {'skipped': [('fixture', 'disabled')]},
                          {'expected': [('fixture', 'known failure')]}):
            with self.subTest(arguments=arguments):
                self.assertTrue(live_ci.result_problems(self.result(**arguments)))

    def test_disabled_lab_is_rejected_before_test_import(self):
        with patch.dict(os.environ, {'AUDIT_LIVE_INTEGRATION': '0'}), \
                patch.object(live_ci.unittest.defaultTestLoader, 'loadTestsFromName') as load, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(live_ci.main(), 1)
        load.assert_not_called()

    def test_wrong_test_selection_is_rejected_before_execution(self):
        wrong = [Mock(id=Mock(return_value='tests.unrelated.Test.test_other'))]
        with patch.dict(os.environ, {'AUDIT_LIVE_INTEGRATION': '1'}), \
                patch.object(live_ci.unittest.defaultTestLoader, 'loadTestsFromName', return_value=wrong), \
                patch.object(live_ci.unittest, 'TextTestRunner') as runner, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(live_ci.main(), 1)
        runner.assert_not_called()

    def test_main_propagates_live_test_result(self):
        selected = [Mock(id=Mock(return_value=name)) for name in live_ci.ALLOWED_SKIPS]
        for successful in (True, False):
            with self.subTest(successful=successful), \
                    patch.dict(os.environ, {'AUDIT_LIVE_INTEGRATION': '1'}), \
                    patch.object(live_ci.unittest.defaultTestLoader, 'loadTestsFromName', return_value=selected), \
                    patch.object(live_ci.unittest, 'TextTestRunner') as runner, \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                runner.return_value.run.return_value = self.result(successful=successful)
                self.assertEqual(live_ci.main(), 0 if successful else 1)
                runner.return_value.run.assert_called_once_with(selected)
