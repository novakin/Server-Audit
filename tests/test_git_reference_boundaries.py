"""Reference-boundary regressions; synthetic values and disposable stores only."""

import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

from server_audit.collectors import git_secrets
from tests.git_helpers import init_repository, run_git, snapshot


SECRET = b'HardcodedSecret123!'
LITERAL = '$uperSecret123!'
REFERENCE = b'process.env.SECRET_KEY'
QUOTED_REFERENCE = b'"${PRIVATE_PASSWORD}"'
LINE_ENDINGS = (b'\n', b'\r\n', b'\r', b'\xe2\x80\xa8', b'\xe2\x80\xa9')


def detected(data):
    return list(git_secrets.detections(data, 'synthetic', 'blob', 'a' * 40,
                                       time.monotonic() + 5))


class ReferenceBoundaryTests(unittest.TestCase):

    def assert_candidate(self, data):
        found = detected(data)
        self.assertIn('credential-assignment', {row['rule'] for row in found})
        self.assertNotIn(SECRET.decode(), json.dumps(found))
        self.assertNotIn(LITERAL, json.dumps(found))
        return found

    def test_literal_prefixes_and_quoted_code_are_candidates(self):
        for value in (LITERAL, '$UnbracedLiteral123', '<PrivateLiteral123>', '%(PrivateLiteral123)',
                      '{{unfinishedSecret123', 'os.environ.PrivateLiteral123',
                      'os.getenv.PrivateLiteral123', 'process.env.SECRET_KEY'):
            with self.subTest(value=value):
                self.assert_candidate(json.dumps({'password': value}).encode())

    def test_literal_fallbacks_and_concatenation_are_not_excluded(self):
        cases = ['password="${PASSWORD:-HardcodedSecret123!}"',
                 'password="${PASSWORD-HardcodedSecret123!}"',
                 'password="{{ password | default(123456789) }}"',
                 'password=os.environ.get("PASSWORD", "HardcodedSecret123!")',
                 'secret=process.env.SECRET_KEY || "HardcodedSecret123!"',
                 'secret=process.env.SECRET_KEY + "HardcodedSecret123!"',
                 'password="${PRIVATE_PASSWORD}" + "HardcodedSecret123!"',
                 'password="${PRIVATE_PASSWORD}"HardcodedSecret123!']
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assert_candidate(assignment.encode())

    def test_truncated_and_ambiguous_expression_prefixes_remain_candidates(self):
        cases = ['password=os.environ.get', 'password=os.environ.getExtraSecret123',
                 'secret=process.env.', 'secret=process.env.' + 'A' * 300]
        for assignment in cases:
            with self.subTest(assignment=assignment):
                self.assert_candidate(assignment.encode())

    def test_fallbacks_and_concatenation_cross_line_endings(self):
        for newline in LINE_ENDINGS:
            for operator in (b'||', b'??', b'+', b'or'):
                for reference in (REFERENCE, QUOTED_REFERENCE):
                    with self.subTest(newline=newline, operator=operator, reference=reference):
                        self.assert_candidate(b'const secret = ' + reference + newline
                                              + b'  ' + operator + b' "' + SECRET + b'";')

    def test_line_comments_do_not_hide_next_line_operators(self):
        for newline in LINE_ENDINGS:
            for comment in (b'// fallback below', b'# fallback below'):
                for reference in (REFERENCE, QUOTED_REFERENCE):
                    with self.subTest(newline=newline, comment=comment, reference=reference):
                        self.assert_candidate(b'secret=' + reference + b' ' + comment
                                              + newline + b' || "' + SECRET + b'";')

    def test_block_comments_and_blank_lines_do_not_hide_continuation(self):
        suffixes = (b' /* comment */ + ', b'\n /* comment\n more */\n || ',
                    b'\n\n// first\n/* second */\n# third\n + ')
        for reference in (REFERENCE, QUOTED_REFERENCE):
            for suffix in suffixes:
                with self.subTest(reference=reference, suffix=suffix):
                    self.assert_candidate(b'secret=' + reference + suffix + b'"' + SECRET + b'"')

    def test_placeholders_have_the_same_continuation_checks(self):
        for placeholder in (b'"changeme"', b'"your_password"', b'"{{ password }}"', b'your_password'):
            with self.subTest(placeholder=placeholder):
                self.assert_candidate(b'password=' + placeholder + b'\n + "' + SECRET + b'"')

    def test_python_reference_calls_are_not_truncated_before_suffix_check(self):
        for reference in (b'os.environ.get("PASSWORD")', b'os.environ.get(  "PASSWORD"  )'):
            with self.subTest(reference=reference):
                self.assert_candidate(b'password=' + reference + b'\n or "' + SECRET + b'"')

    def test_unterminated_and_overlong_comments_are_not_completion(self):
        for suffix in (b' /* unterminated', b' /*' + b'x' * 300 + b'*/',
                       b' //' + b'x' * 300 + b'\n || "' + SECRET + b'"',
                       b'\n' + b' ' * 300 + b'+ "' + SECRET + b'"'):
            with self.subTest(suffix=suffix[:25]):
                self.assert_candidate(b'secret=' + REFERENCE + suffix)

    def test_delimiters_inside_comments_are_not_expression_endings(self):
        for suffix in (b' // ;,}]\n + ', b' /* ;,}] */\n || ', b' # ;,}]\r ?? '):
            with self.subTest(suffix=suffix):
                self.assert_candidate(b'secret=' + REFERENCE + suffix + b'"' + SECRET + b'"')

    def test_reference_syntax_in_json_and_terminated_assignments(self):
        cases = (
            ('template', b'password="{{ password }}"'),
            ('api-placeholder', b'api_key="your_api_key"'),
            ('secret-reference', b'secret=process.env.SECRET_KEY'),
            ('python-terminated', b'password=os.environ.get("PASSWORD"); # comment'),
            ('javascript-terminated', b'secret=process.env.SECRET_KEY; // comment'),
            ('json-reference', b'{"password":"${PRIVATE_PASSWORD}"}'),
        )
        for name, assignment in cases:
            with self.subTest(case=name):
                self.assertEqual(detected(assignment), [])

    def test_exact_references_at_eof_stay_excluded(self):
        for reference in (REFERENCE, QUOTED_REFERENCE, b'"changeme"', b'your_password',
                          b'os.environ.get("PASSWORD")', b"os.environ['PASSWORD']"):
            for suffix in (b'', b'\n\r\t ', b' /* comment */', b' // last comment',
                           b' // first\n/* second */\n# last comment'):
                with self.subTest(reference=reference, suffix=suffix):
                    self.assertEqual(detected(b'password=' + reference + suffix), [])

    def test_explicit_delimiters_stay_excluded_without_reading_later_statements(self):
        for reference in (REFERENCE, QUOTED_REFERENCE):
            for delimiter in (b';', b',', b'}', b']'):
                with self.subTest(reference=reference, delimiter=delimiter):
                    data = b'secret=' + reference + b'\n /* comment */ ' + delimiter + b'\nnext_statement();'
                    self.assertEqual(detected(data), [])

    def test_ambiguous_new_statement_is_conservatively_a_candidate(self):
        self.assert_candidate(b'secret=' + REFERENCE + b'\nnext_statement();')

    def test_array_property_call_and_template_continuations_are_not_excluded(self):
        for suffix in (b'\n["HardcodedSecret123!"]', b'\n.concat("HardcodedSecret123!")',
                       b'\n("HardcodedSecret123!")', b'\n`HardcodedSecret123!`'):
            with self.subTest(suffix=suffix):
                self.assert_candidate(b'password=' + QUOTED_REFERENCE + suffix)

    def test_suffix_window_does_not_mistake_a_bound_for_eof(self):
        for reference in (REFERENCE, QUOTED_REFERENCE):
            for count in (255, 256, 257, 258, 4096):
                with self.subTest(reference=reference, count=count):
                    self.assert_candidate(b'secret=' + reference + b' ' * count + b'\n||"' + SECRET + b'"')
        self.assertEqual(detected(b'secret=' + REFERENCE + b' ' * 20 + b'\n'), [])

    def test_locations_redaction_and_per_line_deduplication_are_preserved(self):
        first_line = b'secret="' + SECRET + b'"; password="' + SECRET + b'";\n'
        prefix = b'# synthetic\n'
        data = prefix + first_line + b'secret=' + REFERENCE + b'\n||"' + SECRET + b'"'
        found = self.assert_candidate(data)
        self.assertEqual([row['rule'] for row in found], ['credential-assignment'] * 2)
        self.assertEqual([row['start_line'] for row in found], [2, 3])
        self.assertEqual([row['byte_offset'] for row in found], [len(prefix), len(prefix + first_line)])
        self.assertTrue(all(row['object_id'] == 'a' * 40 for row in found))
        self.assertNotIn('SECRET_KEY', json.dumps(found))

    def test_detector_does_not_launch_subprocesses(self):
        with patch('subprocess.Popen', side_effect=AssertionError('No process expected')):
            self.assert_candidate(b'secret=' + REFERENCE + b'\n||"' + SECRET + b'"')
            self.assertEqual(detected(b'secret=' + REFERENCE + b';'), [])


@unittest.skipUnless(os.name == 'posix' and shutil.which('git'), 'Requires installed Git and POSIX')
class StoredReferenceBoundaryTests(unittest.TestCase):

    def test_loose_and_packed_sha1_sha256_objects_keep_multiline_candidates(self):
        for algorithm in ('sha1', 'sha256'):
            for packed in (False, True):
                with self.subTest(algorithm=algorithm, packed=packed), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    init_repository(root, algorithm)
                    run_git(root, 'config', 'user.name', 'Synthetic test')
                    run_git(root, 'config', 'user.email', 'audit@example.invalid')
                    content = b'const secret=' + REFERENCE + b' // fallback\n||"' + SECRET + b'";'
                    (root / 'settings.js').write_bytes(content)
                    run_git(root, 'add', '--', 'settings.js')
                    run_git(root, '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Synthetic fixture')
                    identifier = run_git(root, 'rev-parse', 'HEAD:settings.js').decode().strip()
                    if packed:
                        run_git(root, 'gc', '--prune=now', '--quiet')
                        self.assertTrue(list((root / '.git/objects/pack').glob('*.pack')))
                    before = snapshot(root)
                    result, findings = git_secrets.collect([str(root)], scan_seconds=10)
                    self.assertEqual(snapshot(root), before)
                    self.assertEqual(result['status'], 'ok')
                    self.assertEqual(result['ruleset_version'], 2)
                    found = [row for scan in result['repositories'][0]['scans'] for row in scan['detections']]
                    self.assertIn(identifier, {row['object_id'] for row in found})
                    self.assertTrue(any(row['level'] == 'REVIEW' for row in findings))
                    self.assertNotIn(SECRET.decode(), json.dumps([result, findings]))


if __name__ == '__main__':
    unittest.main()
