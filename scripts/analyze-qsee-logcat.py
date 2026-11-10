#!/usr/bin/env python3
"""Offline, allowlisted aggregates from `logcat -d -b main -v epoch`.

No ADB, raw messages, absolute times, process/thread IDs, app IDs or file names
in the report. Unknown messages are counted, never echoed. Input stays private.
Sequence matching is conservative: same PID/TID, at most five seconds,
one load, matching app IDs when available. It is not causal attribution.
"""
import argparse
from collections import Counter, defaultdict
from decimal import Decimal
import json
from pathlib import Path
import re

TAGS = {'QSEECOMAPI', 'MTService-TEE', 'MTService'}
LINE = re.compile(r'^\s*(\d+\.\d+)\s+(\d+)\s+(\d+)\s+([VDIWEF])\s+([^:]+):\s*(.*)$')
WINDOW = Decimal('5')


def classify(tag, message):
    """Return fixed labels only; arbitrary input is never a report key."""
    if tag == 'QSEECOMAPI':
        for prefix, label in (
            ('QSEECom_get_handle sb_length', 'get_handle'),
            ('App is not loaded in QSEE', 'not_loaded_probe'),
            ('Loaded image: APP id', 'loaded'),
            ('QSEECom_shutdown_app, app_id', 'shutdown'),
            ('QSEECom_dealloc_memory', 'dealloc_call'),
            ('Error::Cannot de-alloc memory. priv handle is NULL', 'null_dealloc'),
        ):
            if message.startswith(prefix):
                return label
    if tag == 'MTService-TEE' and re.match(r'^Response OK, size:\s*\d+\s*$', message):
        return 'response_ok'
    if tag == 'MTService' and message.startswith('get sn from prop:'):
        # E severity in the observed build, but an identifier-bearing diagnostic.
        return 'identifier_diagnostic_omitted'
    if re.search(r'\b(error|failed|failure|cannot|denied)\b', message, re.I):
        return 'other_failure_text'
    if tag == 'MTService' and message.startswith(('getFidoService:', 'getMlipayService:')):
        return 'service_lookup_diagnostic'
    return 'other'


def parse(text):
    rows, rejected, excluded = [], 0, 0
    for line in text.splitlines():
        if not line.strip() or line.startswith('--------- beginning of '):
            continue
        m = LINE.fullmatch(line)
        if not m:
            rejected += 1
            continue
        timestamp, pid, tid, level, tag, message = m.groups()
        tag = tag.strip()
        if tag not in TAGS:
            excluded += 1
            continue
        event = classify(tag, message)
        app = re.search(r'(?:APP id|app_id)\s*=\s*([^\s,]+)', message) if event in {'loaded', 'shutdown'} else None
        app_id = app.group(1) if app else None
        if app_id and app_id.lower().startswith(('[', '<', 'redact', 'omitted', 'omés')):
            app_id = None  # Two redaction placeholders are not identity evidence.
        size = re.fullmatch(r'Response OK, size:\s*(32|64)\s*', message)
        rows.append({'time': Decimal(timestamp), 'pid': pid, 'tid': tid,
                     'level': level, 'tag': tag, 'event': event,
                     'app': app_id,
                     'size_bucket': size.group(1) if size else 'other',
                     # Private comparison key, NEVER serialized.
                     'identity': (timestamp, pid, tid, level, tag, message)})
    return rows, rejected, excluded


def mtd_pids(ps_text):
    lines = ps_text.splitlines()
    if not lines:
        return set()
    columns = lines[0].split()
    if 'PID' not in columns or 'NAME' not in columns:
        return set()
    p, n = columns.index('PID'), columns.index('NAME')
    result = set()
    for line in lines[1:]:
        fields = line.split()
        if len(fields) > max(p, n) and fields[n] == 'mtd@1.3':
            result.add(fields[p])
    return result


def failure_candidate(row):
    return (row['event'] == 'other_failure_text' or
            (row['level'] in 'EF' and row['event'] not in
             {'null_dealloc', 'identifier_diagnostic_omitted'}))


def summarize(rows):
    events = Counter(r['event'] for r in rows)
    by_thread = defaultdict(list)
    for row in rows:
        by_thread[row['pid'], row['tid']].append(row)
    complete = with_prior = with_double = matching_ids = mismatches = unknown_ids = 0
    durations, shutdown_delays = [], []
    for thread in by_thread.values():
        window = []
        for row in thread:
            # Do not bridge backwards timestamps, long gaps, or new requests.
            if window and (row['time'] < window[-1]['time'] or
                           row['time'] - window[0]['time'] > WINDOW):
                window = []
            if row['event'] == 'get_handle':
                window = []
            window.append(row)
            if row['event'] != 'null_dealloc':
                continue
            kinds = [r['event'] for r in window]
            if kinds.count('loaded') == 1 and kinds.count('shutdown') == 1:
                load, shut = kinds.index('loaded'), kinds.index('shutdown')
                responses = [i for i, k in enumerate(kinds) if k == 'response_ok' and load < i < shut]
                if responses and shut < len(window) - 1:
                    a, b = window[load]['app'], window[shut]['app']
                    if a is not None and b is not None and a != b:
                        mismatches += 1
                    else:
                        complete += 1
                        matching_ids += int(a is not None and b is not None)
                        unknown_ids += int(a is None or b is None)
                        with_prior += int(any(failure_candidate(r) for r in window[:-1]))
                        with_double += int('dealloc_call' in kinds[responses[-1] + 1:shut] and
                                           'dealloc_call' in kinds[shut + 1:-1])
                        durations.append(float((row['time'] - window[load]['time']) * 1000))
                        shutdown_delays.append(float((row['time'] - window[shut]['time']) * 1000))
            window = []
    def extent(values):
        return {'min': min(values), 'max': max(values)} if values else None
    return {
        'records': len(rows), 'event_counts': dict(sorted(events.items())),
        'error_severity_records': sum(r['level'] in 'EF' for r in rows),
        'other_failure_candidates': sum(failure_candidate(r) for r in rows),
        'response_size_buckets': dict(sorted(Counter(r['size_bucket'] for r in rows if r['event'] == 'response_ok').items())),
        'complete_ordered_cycles': complete,
        'cycles_with_matching_app_ids': matching_ids,
        'cycles_without_app_id_evidence': unknown_ids,
        'rejected_app_id_mismatches': mismatches,
        'null_errors_without_complete_cycle': events['null_dealloc'] - complete,
        'cycles_with_prior_failure_candidate': with_prior,
        'cycles_with_dealloc_before_and_after_shutdown': with_double,
        'loaded_to_null_ms': extent(durations),
        'shutdown_to_null_ms': extent(shutdown_delays),
    }


def analyze(logs, process_snapshots=None):
    """Inputs are chronological snapshots from one boot; no union stitching.

    Multiset differences retain identical records repeated within a capture,
    while avoiding counting the same ring-buffer records again across captures.
    No overlap means continuity unknown, not evidence of a quiet interval.
    """
    if process_snapshots is not None and len(process_snapshots) != len(logs):
        raise ValueError('One process snapshot per log is required')
    report = {'format': 'qsee-aggregate-v1', 'snapshots': [], 'comparisons': []}
    previous = None
    pid_sets = []
    for index, log in enumerate(logs):
        rows, rejected, excluded = parse(log)
        pids = mtd_pids(process_snapshots[index]) if process_snapshots else set()
        pid_sets.append(pids)
        groups = {'mtd': [], 'other_or_unattributed': []}
        for row in rows:
            groups['mtd' if row['pid'] in pids else 'other_or_unattributed'].append(row)
        times = [r['time'] for r in rows]
        snapshot = {'index': index + 1, 'unparsed_lines': rejected,
                    'excluded_tag_records': excluded, 'mtd_process_found': bool(pids),
                    'retained_event_span_seconds': float(max(times) - min(times)) if times else None,
                    'timestamp_regressions': sum(b < a for a, b in zip(times, times[1:])),
                    'groups': {key: summarize(value) for key, value in groups.items()}}
        report['snapshots'].append(snapshot)
        current = Counter(r['identity'] for r in rows)
        if previous is not None:
            delta = current - previous
            new_rows = []
            for row in rows:
                if delta[row['identity']]:
                    new_rows.append(row)
                    delta[row['identity']] -= 1
            overlap = sum((current & previous).values())
            report['comparisons'].append({
                'from_snapshot': index, 'to_snapshot': index + 1,
                'identical_record_multisets': current == previous,
                'overlapping_records': overlap,
                'continuity': 'overlap_present_not_proof_of_completeness' if overlap else 'unknown',
                'newly_observed_records': len(new_rows),
                'newly_observed_event_counts': dict(sorted(Counter(r['event'] for r in new_rows).items())),
            })
        previous = current
    report['same_single_mtd_pid_in_all_process_snapshots'] = (
        bool(pid_sets) and len(pid_sets[0]) == 1 and all(p == pid_sets[0] for p in pid_sets))
    report['limits'] = [
        'Selected tags and retained main buffer only; absence is not proof of no error.',
        'Current ps mapping does not exclude historical PID reuse.',
        'Ordered same-thread cycles are temporal evidence, not call stacks or ownership proof.',
        'Retained event span is not the observation duration or a population error rate.',
        'Comparisons require one boot and stable clock; no loss-free logging guarantee.',
        'Unknown message contents are omitted; review private inputs before publishing aggregates.',
    ]
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', nargs='+', type=Path)
    parser.add_argument('--ps', nargs='+', type=Path, help='One ps -A snapshot per log, same order')
    args = parser.parse_args()
    if args.ps and len(args.ps) != len(args.logs):
        parser.error('Provide one --ps file per log')
    try:
        result = analyze([p.read_text(errors='replace') for p in args.logs],
                         [p.read_text(errors='replace') for p in args.ps] if args.ps else None)
    except OSError:
        parser.exit(1, 'Cannot read input; path and contents omitted.\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
