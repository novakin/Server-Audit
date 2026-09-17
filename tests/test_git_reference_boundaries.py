"""Reference-boundary regressions; synthetic values and disposable stores only."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from server_audit.collectors import git_reader, git_secrets


SECRET = b'HardcodedSecret123!'
REFERENCE = b'process.env.SECRET_KEY'
QUOTED_REFERENCE = b'"${PRIVATE_PASSWORD}"'
LINE_ENDINGS = (b'\n', b'\r\n', b'\r', b'\xe2\x80\xa8', b'\xe2\x80\xa9')


def detected(data):
    return list(git_secrets.detections(data, 'synthetic', 'blob', 'a' * 40,
                                       time.monotonic() + 5))


class ReferenceBoundaryTests(unittest.TestCase):
    def assert_candidate(self, data):
        # Prove that this is an exclusion-boundary test, not new regex coverage.
        self.assertIsNotNone(dict(git_secrets.RULES)['credential-assignment'].search(data))
        found = detected(data)
        self.assertIn('credential-assignment', {row['rule'] for row in found})
        self.assertNotIn(SECRET.decode(), json.dumps(found))
        return found

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

    def test_quoted_placeholders_have_the_same_continuation_checks(self):
        for placeholder in (b'"changeme"', b'"your_password"', b'"{{ password }}"'):
            with self.subTest(placeholder=placeholder):
                self.assert_candidate(b'password=' + placeholder + b'\n + "' + SECRET + b'"')

    def test_unquoted_placeholders_have_the_same_continuation_checks(self):
        self.assert_candidate(b'password=your_password\n + "' + SECRET + b'"')

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
        for count in (255, 256, 257, 258, 4096):
            with self.subTest(count=count):
                self.assert_candidate(b'secret=' + REFERENCE + b' ' * count + b'\n||"' + SECRET + b'"')
        self.assertEqual(detected(b'secret=' + REFERENCE + b' ' * 20 + b'\n'), [])

    def test_locations_redaction_and_deduplication_are_preserved(self):
        data = b'# synthetic\nsecret=' + REFERENCE + b'\n||"' + SECRET + b'"'
        found = self.assert_candidate(data)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['start_line'], 2)
        self.assertEqual(found[0]['byte_offset'], len(b'# synthetic\n'))
        self.assertEqual(found[0]['object_id'], 'a' * 40)
        self.assertNotIn('SECRET_KEY', json.dumps(found))

    def test_expressions_are_not_evaluated(self):
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
                    environment = git_reader.environment(root)
                    def git(*arguments, data=None):
                        return subprocess.run([shutil.which('git'), '-C', str(root), *arguments],
                                              input=data, capture_output=True, env=environment,
                                              check=True, timeout=10).stdout
                    git('init', '--quiet', '--object-format=' + algorithm)
                    git('config', 'user.name', 'Synthetic test')
                    git('config', 'user.email', 'audit@example.invalid')
                    content = b'const secret=' + REFERENCE + b' // fallback\n||"' + SECRET + b'";'
                    (root / 'settings.js').write_bytes(content)
                    git('add', '--', 'settings.js')
                    git('-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'Synthetic fixture')
                    identifier = git('rev-parse', 'HEAD:settings.js').decode().strip()
                    if packed:
                        git('gc', '--prune=now', '--quiet')
                        self.assertTrue(list((root / '.git/objects/pack').glob('*.pack')))
                    def snapshot():
                        return {str(path.relative_to(root)): path.read_bytes()
                                for path in root.rglob('*') if path.is_file()}
                    before = snapshot()
                    result, findings = git_secrets.collect([str(root)], scan_seconds=10)
                    self.assertEqual(snapshot(), before)
                    self.assertEqual(result['status'], 'ok')
                    self.assertEqual(result['ruleset_version'], 2)
                    found = [row for scan in result['repositories'][0]['scans'] for row in scan['detections']]
                    self.assertIn(identifier, {row['object_id'] for row in found})
                    self.assertTrue(any(row['level'] == 'REVIEW' for row in findings))
                    self.assertNotIn(SECRET.decode(), json.dumps([result, findings]))


if __name__ == '__main__':
    unittest.main()
