"""Finding identity, preservation and legacy report compatibility."""

import copy
from html.parser import HTMLParser
import unittest

from server_audit import reporting


class FindingMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.rows, self.headings = [], []
        self.row, self.heading, self.message = None, None, False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'li' and attrs.get('class') == 'finding':
            self.row = {'index': int(attrs['data-finding-index']), 'level': attrs['data-level'],
                        'search': attrs['data-search'], 'message': ''}
        elif tag == 'p' and self.row is not None:
            self.message = True
        elif tag in ('h3', 'h4'):
            self.heading = [tag, '']

    def handle_data(self, data):
        if self.message:
            self.row['message'] += data
        if self.heading is not None:
            self.heading[1] += data

    def handle_endtag(self, tag):
        if tag == 'p':
            self.message = False
        elif tag == 'li' and self.row is not None:
            self.rows.append(self.row)
            self.row = None
        elif tag in ('h3', 'h4') and self.heading is not None:
            self.headings.append(tuple(self.heading))
            self.heading = None


def report_with(findings):
    return {'schema_version': 1, 'host': 'fixture.example', 'timestamp_utc': '2026-01-01T12:00:00+00:00',
            'checks': {}, 'findings': findings, 'limitations': [],
            'summary': {level: sum(item['level'] == level for item in findings) for level in ('REVIEW', 'UNKNOWN')}}


class FindingGroupTests(unittest.TestCase):
    def test_grouping_uses_identity_and_preserves_first_appearance_and_duplicates(self):
        findings = [
            {'check': 'docker', 'resource_type': 'container', 'resource_id': 'a' * 64,
             'resource_name': 'same name', 'level': 'REVIEW', 'message': 'First exact message.'},
            {'check': 'ssh', 'resource_type': 'ssh_configuration', 'resource_id': 'selected',
             'resource_name': 'SSH configuration', 'level': 'UNKNOWN', 'message': 'SSH exact message.'},
            {'check': 'docker', 'resource_type': 'container', 'resource_id': 'b' * 64,
             'resource_name': 'same name', 'level': 'UNKNOWN', 'message': 'Other container.'},
            {'check': 'docker', 'resource_type': 'container', 'resource_id': 'a' * 64,
             'resource_name': 'same name', 'level': 'REVIEW', 'message': 'First exact message.'},
        ]
        original = copy.deepcopy(findings)
        groups = reporting.finding_groups(findings)
        self.assertEqual(list(groups), ['docker', 'ssh'])
        self.assertEqual(list(groups['docker']), [('container', 'a' * 64), ('container', 'b' * 64)])
        document = reporting.render_html(report_with(findings))
        parser = FindingMarkup()
        parser.feed(document)
        self.assertEqual([row['index'] for row in parser.rows], [0, 3, 2, 1])
        self.assertEqual(sorted(row['index'] for row in parser.rows), list(range(len(findings))))
        for row in parser.rows:
            self.assertEqual((row['level'], row['message']), (findings[row['index']]['level'], findings[row['index']]['message']))
        self.assertEqual(parser.headings.count(('h4', 'same name')), 2)
        self.assertIn(('h3', 'SSH'), parser.headings)
        self.assertEqual(findings, original)

    def test_legacy_and_partial_metadata_are_not_inferred_from_messages_or_names(self):
        findings = [
            {'level': 'REVIEW', 'message': 'Docker same name: retained legacy entry.'},
            {'level': 'UNKNOWN', 'message': 'Partial identity.', 'check': 'docker', 'resource_name': 'same name'},
            {'level': 'REVIEW', 'message': 'Resource without check.', 'resource_type': 'container', 'resource_id': 'id'},
            {'level': 'UNKNOWN', 'message': 'Invalid identity type.', 'check': 'docker', 'resource_type': 'container', 'resource_id': []},
        ]
        groups = reporting.finding_groups(findings)
        self.assertEqual(list(groups), [None, 'docker'])
        self.assertEqual([index for index, _ in groups[None][None]], [0, 2])
        self.assertEqual([index for index, _ in groups['docker'][None]], [1, 3])
        parser = FindingMarkup()
        parser.feed(reporting.render_html(report_with(findings)))
        self.assertEqual(len(parser.rows), 4)
        self.assertNotIn(('h4', 'same name'), parser.headings)

    def test_search_includes_metadata_and_every_value_is_escaped(self):
        attack = '<img src=x onerror=alert(1)>'
        finding = {'level': 'UNKNOWN', 'message': 'Full SSH prefix: ' + attack, 'check': 'docker',
                   'resource_type': 'container', 'resource_id': 'full-id-only-in-metadata', 'resource_name': attack}
        original = report_with([finding])
        unchanged = copy.deepcopy(original)
        document = reporting.render_html(original)
        self.assertNotIn(attack, document)
        self.assertIn('&lt;img', document)
        parser = FindingMarkup()
        parser.feed(document)
        self.assertIn('full-id-only-in-metadata', parser.rows[0]['search'])
        self.assertIn(attack, parser.rows[0]['search'])
        self.assertEqual(parser.rows[0]['message'], finding['message'])
        self.assertEqual(original, unchanged)

    def test_visible_resource_heading_is_searchable_for_every_row_in_its_group(self):
        common = {'check': 'docker', 'resource_type': 'container', 'resource_id': 'same-id', 'level': 'REVIEW'}
        findings = [{**common, 'message': 'First.', 'resource_name': 'visible-name'},
                    {**common, 'message': 'Second.'},
                    {**common, 'message': 'Third.', 'resource_name': 'later-name'}]
        parser = FindingMarkup()
        parser.feed(reporting.render_html(report_with(findings)))
        self.assertEqual(len(parser.rows), 3)
        self.assertTrue(all('visible-name' in row['search'] for row in parser.rows))

    def test_group_totals_keep_review_and_unknown_separate_including_zero(self):
        totals = reporting.finding_totals([{'level': 'REVIEW'}, {'level': 'REVIEW'}, {'level': 'UNKNOWN'}])
        self.assertIn('Totals:', totals)
        self.assertIn('2 Review', totals)
        self.assertIn('1 Unknown', totals)
        self.assertIn('0 Review', reporting.finding_totals([{'level': 'UNKNOWN'}]))

    def test_docker_application_coverage_is_visible_in_html_and_text(self):
        report = report_with([])
        report['checks']['environment_files'] = {'status': 'ok', 'roots': [], 'files': [], 'entries_examined': 0,
                                                'skipped': [], 'limitations': [], 'applications': {
            'status': 'ok', 'sources': [], 'docker_coverage': {
                'status': 'partial', 'containers_inspected': 1, 'containers_retained': 2,
                'detail': 'Docker application references incomplete: container inspection failed.'}}}
        for output in (reporting.render_html(report), reporting.render_text(report)):
            self.assertIn('container inspection failed', output)
            self.assertIn('Successfully inspected 1 of 2 retained containers', output)
            self.assertIn('Directory discovery is independent', output)

    def test_empty_report_and_single_line_utc_timestamp_remain_readable(self):
        document = reporting.render_html(report_with([]))
        self.assertIn('No findings were recorded', document)
        self.assertIn('01 Jan 2026 - 12:00:00 UTC', document)

    def test_scope_topics_preserve_every_note_including_duplicates(self):
        report = report_with([])
        report['limitations'] = ['General <boundary>.']
        report['checks'] = {'docker': {'status': 'ok', 'limitations': ['Repeated note.', 'Repeated note.']},
                            'future_check': {'status': 'partial', 'limitations': ['Future scope.']}}
        markup = reporting.render_limitations(report)
        self.assertEqual(markup.count('Repeated note.'), 2)
        self.assertIn('General &lt;boundary&gt;.', markup)
        self.assertIn('Future scope.', markup)
        self.assertEqual(markup.count('class="limitation-topic"'), 2)


if __name__ == '__main__':
    unittest.main()
