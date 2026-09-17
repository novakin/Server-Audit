#!/usr/bin/env python3
"""Opt-in TCP probing from an independent machine; offline import into audit bundles."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import errno
import ipaddress
import json
import os
import platform
import socket
import sys
from pathlib import Path

from external_verification import audit_identity, inventory, load_json, merge, scope, text, validate_probe
from reporting import export_report


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_ports(value):
    ports = set()
    for part in value.split(','):
        bounds = part.split('-')
        if len(bounds) > 2 or not all(item.isascii() and item.isdigit() for item in bounds):
            raise ValueError('Use comma-separated TCP ports or ranges, such as 22,80,443,8000-8010')
        low, high = int(bounds[0]), int(bounds[-1])
        if not 1 <= low <= high <= 65535 or high - low >= 1024:
            raise ValueError('Invalid or oversized port range')
        ports.update(range(low, high + 1))
        if len(ports) > 1024:
            raise ValueError('At most 1024 TCP ports per probe')
    return sorted(ports)


def connect(endpoint, timeout):
    target, number = endpoint
    family = socket.AF_INET if ipaddress.ip_address(target).version == 4 else socket.AF_INET6
    row = {'target': target, 'port': number, 'family': 'IPv4' if family == socket.AF_INET else 'IPv6',
           'protocol': 'tcp', 'observation': 'local_or_network_error', 'source_address': None}
    try:
        with socket.socket(family, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            try:
                client.connect((target, number))
                row['observation'] = 'connected'
            except (TimeoutError, socket.timeout):
                row['observation'] = 'timeout'
            except OSError as error:
                if error.errno == errno.ECONNREFUSED:
                    row['observation'] = 'refused'
            source = client.getsockname()[0]
            if not ipaddress.ip_address(source).is_unspecified:
                row['source_address'] = source
    except OSError:
        pass
    row['observed_at_utc'] = now()
    return row


def probe(report, targets, ports, location, independent=False, timeout=2):
    identity = audit_identity(report)
    targets, ports = scope(targets, ports)
    location = text(location, 'probe location')
    if type(independent) is not bool:
        raise ValueError('Independent-source assertion must be boolean')
    if type(timeout) not in (int, float) or not 0 < timeout <= 5:
        raise ValueError('Timeout must be positive and at most five seconds')
    result = {'probe_schema_version': 1, 'audit': identity, 'targets': targets, 'ports': ports,
              'location': location, 'probe_host': platform.node() or 'unknown', 'independent': independent,
              'timeout_seconds': timeout, 'started_at_utc': now()}
    pool = ThreadPoolExecutor(max_workers=8)
    try:
        result['results'] = list(pool.map(lambda endpoint: connect(endpoint, timeout), ((target, number) for target in targets for number in ports)))
    finally:
        # On interruption, cancel queued endpoints; only active socket attempts may finish.
        pool.shutdown(wait=True, cancel_futures=True)
    result['finished_at_utc'] = now()
    return validate_probe(result, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    scan = commands.add_parser('probe', help='Connect only to explicitly selected authorized IP addresses')
    scan.add_argument('--audit', required=True, help='Original server report.json')
    scan.add_argument('--target', action='append', required=True, help='Literal IPv4/IPv6 address; repeat for each authorized target')
    scan.add_argument('--ports', help='TCP ports/ranges; default: union of recorded TCP listeners and running Docker published bindings')
    scan.add_argument('--location', required=True, help='Operator-supplied probe network/location label')
    scan.add_argument('--independent', action='store_true', help='Assert this machine is on an independent external network; otherwise internet exposure remains unknown')
    scan.add_argument('--timeout', type=float, default=2, help='Per-connection seconds, greater than 0 and at most 5 (default 2)')
    scan.add_argument('--output', help='New private probe JSON file; never overwrite')
    scan.add_argument('--dry-run', action='store_true', help='Print selected addresses/ports without opening sockets or writing a result')
    combine = commands.add_parser('import', help='Offline merge into a new HTML/JSON bundle; no host commands or sockets')
    combine.add_argument('--audit', required=True, help='Same original report.json used by the probes')
    combine.add_argument('--results', action='append', required=True, help='Probe JSON file; repeat for multiple locations')
    combine.add_argument('--export', required=True, help='Parent directory for a new enriched audit bundle')
    args = parser.parse_args()
    try:
        report = load_json(args.audit, 32 * 1024 * 1024)
        audit_identity(report)
        if args.command == 'import':
            if len(args.results) > 8:
                raise ValueError('Import at most eight probe files together')
            result = merge(report, [load_json(path, 2 * 1024 * 1024) for path in args.results])
            print('Audit exported: ' + str(export_report(result, args.export) / 'report.html'))
            return 0
        ports = parse_ports(args.ports) if args.ports else sorted({item['port'] for item in inventory(report) if item['protocol'] == 'tcp'})
        targets, ports = scope(args.target, ports)
        text(args.location, 'probe location')
        if not 0 < args.timeout <= 5:
            raise ValueError('Timeout must be positive and at most five seconds')
        if args.dry_run:
            print(json.dumps({'targets': targets, 'tcp_ports': ports, 'connections': len(targets) * len(ports), 'location': args.location, 'independent': args.independent}, indent=2))
            return 0
        if not args.output:
            raise ValueError('--output is required unless --dry-run is selected')
        # Reserve output before network activity, including rejection of existing files/symlinks.
        output = Path(args.output)
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as destination:
            result = probe(report, targets, ports, args.location, args.independent, args.timeout)
            json.dump(result, destination, indent=2)
            destination.write('\n')
        print('Probe written: ' + str(output))
        return 0
    except KeyboardInterrupt:
        print('Probe interrupted; any output file is incomplete and must not be imported.', file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        print('External verification failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
