"""External TCP evidence: explicit targets, bounded input and conservative correlation."""

import copy
import datetime
import ipaddress
import json
import os
import stat


MAX_ENDPOINTS = 1024
OBSERVATIONS = {'connected', 'refused', 'timeout', 'local_or_network_error'}
LABELS = {'reachable': 'externally reachable', 'not_observed': 'not observed from this probe', 'unknown': 'unknown'}
LIMITATIONS = [
    'Independent location and target ownership/mapping are operator assertions, not automatically verified. Imported evidence is not signed or authenticated.',
    'TCP connect only: no UDP probe, application identification, TLS/HTTP checks, DNS discovery or external source-IP discovery. No response payload is read.',
    'A failed observation is specific to the probe source, target, time and timeout. It does not prove universal filtering or protection.',
    'Same-port local listeners and Docker bindings are candidates only. NAT, reverse proxies, CDN edges and port translation can change the service or host reached.',
    'Only explicitly selected IPs and TCP ports are tested. Other addresses, UDP and untested ports remain unknown; the imported audit remains a separate-time snapshot.',
]


def load_json(path, limit):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Input must be a regular JSON file')
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Input exceeds size limit')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError('Expected a JSON object')
    return result


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('Timestamp must be an ISO 8601 string')
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Timestamp must include timezone')
    return parsed.astimezone(datetime.timezone.utc)


def text(value, name, maximum=200):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid ' + name)
    return value


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise ValueError('Use a literal IPv4/IPv6 address without a zone identifier')
    ip = ipaddress.ip_address(value)
    if ip.is_multicast or ip.is_unspecified or getattr(ip, 'ipv4_mapped', None):
        raise ValueError('Multicast, unspecified and IPv4-mapped IPv6 targets are not supported')
    return str(ip)


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('Ports must be integers from 1 through 65535')
    return value


def audit_identity(report):
    if type(report.get('schema_version')) is not int or report['schema_version'] != 1 or not isinstance(report.get('checks'), dict) or not isinstance(report.get('findings'), list):
        raise ValueError('Expected a schema_version 1 host audit')
    text(report.get('host'), 'audit host')
    timestamp(report.get('timestamp_utc'))
    return {key: report[key] for key in ('schema_version', 'host', 'timestamp_utc')}


def inventory(report):
    """Port candidates do not assert public-address or process identity equivalence."""
    entries = []
    checks = report['checks']
    for item in checks.get('ports', {}).get('listeners', []):
        if item.get('protocol') not in ('tcp', 'udp'):
            continue
        try:
            number = port(int(item['address'].rsplit(':', 1)[1]))
        except (KeyError, ValueError, IndexError):
            continue
        entries.append({'protocol': item['protocol'], 'port': number,
                        'source': 'listener ' + item['address'] + ' | ' + item.get('process', 'unknown')})
    for container in checks.get('docker', {}).get('containers', []):
        if container.get('inspection_status') != 'ok' or not container.get('running'):
            continue
        for internal, bindings in (container.get('published_ports') or {}).items():
            protocol = internal.rsplit('/', 1)[-1]
            if protocol not in ('tcp', 'udp'):
                continue
            for binding in bindings or []:
                try:
                    number = port(int(binding['HostPort']))
                except (KeyError, ValueError):
                    continue
                entries.append({'protocol': protocol, 'port': number,
                                'source': 'Docker ' + (container.get('name') or container.get('id', 'unknown')) + ' | ' + binding.get('HostIp', '*') + ':' + str(number) + ' to ' + internal})
    if len(entries) > 4096:
        raise ValueError('Local inventory exceeds 4096 candidates')
    return entries


def scope(targets, ports):
    if not isinstance(targets, list) or not targets or len(targets) > 8:
        raise ValueError('Select one through eight explicit IP addresses')
    if not isinstance(ports, list) or not ports or len(ports) > MAX_ENDPOINTS:
        raise ValueError('Select at least one TCP port, within the endpoint limit')
    normalized = [address(target) for target in targets]
    checked_ports = [port(number) for number in ports]
    if len(set(normalized)) != len(normalized) or len(set(checked_ports)) != len(checked_ports):
        raise ValueError('Duplicate addresses or ports')
    if len(normalized) * len(checked_ports) > MAX_ENDPOINTS:
        raise ValueError('At most 1024 address/port pairs per probe')
    return normalized, checked_ports


def validate_probe(probe, report):
    """Project recognized fields; reject inconsistent/partial result files."""
    if probe.get('probe_schema_version') != 1 or probe.get('audit') != audit_identity(report):
        raise ValueError('Probe schema or source audit identity does not match')
    targets, ports = scope(probe.get('targets'), probe.get('ports'))
    location = text(probe.get('location'), 'probe location')
    probe_host = text(probe.get('probe_host'), 'probe host')
    independent = probe.get('independent')
    if type(independent) is not bool:
        raise ValueError('Independent-source assertion must be boolean')
    started = timestamp(probe.get('started_at_utc'))
    finished = timestamp(probe.get('finished_at_utc'))
    if finished < started:
        raise ValueError('Probe finish precedes start')
    if finished > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
        raise ValueError('Probe timestamp is more than five minutes in the future; check clock synchronization')
    timeout = probe.get('timeout_seconds')
    if type(timeout) not in (int, float) or not 0 < timeout <= 5:
        raise ValueError('Timeout must be positive and at most five seconds')
    rows = probe.get('results')
    if not isinstance(rows, list) or len(rows) != len(targets) * len(ports):
        raise ValueError('Probe results do not cover the declared scope')
    expected = {(target, number) for target in targets for number in ports}
    validated = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Invalid observation')
        target, number = address(row.get('target')), port(row.get('port'))
        key = target, number
        family = 'IPv4' if ipaddress.ip_address(target).version == 4 else 'IPv6'
        if key not in expected or row.get('family') != family or row.get('protocol') != 'tcp':
            raise ValueError('Duplicate or inconsistent observation scope')
        expected.remove(key)
        observation = row.get('observation')
        if observation not in OBSERVATIONS:
            raise ValueError('Unsupported observation')
        checked = timestamp(row.get('observed_at_utc'))
        if not started <= checked <= finished:
            raise ValueError('Observation time outside probe interval')
        source = row.get('source_address')
        if source is not None:
            source = address(source)
            if ipaddress.ip_address(source).version != ipaddress.ip_address(target).version:
                raise ValueError('Source address family mismatch')
        validated.append({'target': target, 'port': number, 'family': family, 'protocol': 'tcp',
                          'observation': observation, 'observed_at_utc': checked.isoformat(), 'source_address': source})
    return {'probe_schema_version': 1, 'audit': audit_identity(report), 'targets': targets, 'ports': ports,
            'location': location, 'probe_host': probe_host, 'independent': independent,
            'started_at_utc': started.isoformat(), 'finished_at_utc': finished.isoformat(),
            'timeout_seconds': timeout, 'results': validated}


def merge(report, probes):
    audit_identity(report)
    if 'external_verification' in report['checks']:
        raise ValueError('Import into the original audit, not an already enriched report')
    if not 1 <= len(probes) <= 8:
        raise ValueError('Import one through eight probe files together')
    candidates = inventory(report)
    observations, findings, evidence = [], [], []
    for raw in probes:
        probe = validate_probe(raw, report)
        if probe in evidence:
            raise ValueError('Duplicate probe file')
        evidence.append(probe)
        age = (timestamp(probe['started_at_utc']) - timestamp(report['timestamp_utc'])).total_seconds()
        if age < 0 or age > 86400:
            findings.append({'level': 'UNKNOWN', 'message': 'External probe at ' + probe['location'] + ' is before or more than 24 hours after the host snapshot; service correlation needs a fresh audit.'})
        for row in probe['results']:
            status = 'unknown'
            reason = 'Independent external source not confirmed' if not probe['independent'] else 'Nonpublic target: not evidence of internet reachability'
            if probe['independent'] and ipaddress.ip_address(row['target']).is_global:
                reason = 'Local or network error prevented an interpretable TCP observation'
                if row['observation'] == 'connected':
                    status = 'reachable'
                    reason = 'TCP connection succeeded from the declared independent source'
                elif row['observation'] in ('refused', 'timeout'):
                    status = 'not_observed'
                    reason = 'TCP connection refused or timed out from this source only'
            matches = [item['source'] for item in candidates if item['protocol'] == 'tcp' and item['port'] == row['port']]
            observations.append({**row, 'location': probe['location'], 'exposure': LABELS[status],
                                 'reason': reason, 'local_candidates': matches, 'snapshot_age_seconds': age})
            if status == 'reachable':
                findings.append({'level': 'REVIEW', 'message': f"TCP {row['target']}:{row['port']} externally reachable from {probe['location']} at {row['observed_at_utc']}; service/host mapping is unverified."})
        # Inventory omissions stay explicit rather than inheriting a negative result.
        for protocol, number in sorted({(item['protocol'], item['port']) for item in candidates}):
            if protocol != 'tcp' or number not in probe['ports']:
                observations.append({'target': 'Not tested', 'port': number, 'family': 'Not tested', 'protocol': protocol,
                                     'observation': 'not_tested', 'observed_at_utc': None, 'source_address': None,
                                     'location': probe['location'], 'exposure': LABELS['unknown'],
                                     'reason': 'Local inventory port outside selected TCP probe scope',
                                     'local_candidates': [item['source'] for item in candidates if item['port'] == number and item['protocol'] == protocol]})
    incomplete = any(item['exposure'] == LABELS['unknown'] for item in observations)
    if incomplete:
        findings.append({'level': 'UNKNOWN', 'message': 'External verification includes untested ports, local/network errors, nonpublic targets or an unconfirmed independent source. Review raw observations and scope.'})
    merged = copy.deepcopy(report)
    merged['checks']['external_verification'] = {'status': 'partial' if incomplete or any(item['level'] == 'UNKNOWN' for item in findings) else 'ok',
                                                'observations': observations, 'probes': evidence, 'limitations': LIMITATIONS}
    merged['findings'].extend(findings)
    merged['summary'] = {level: sum(item['level'] == level for item in merged['findings']) for level in ('REVIEW', 'UNKNOWN')}
    return merged
