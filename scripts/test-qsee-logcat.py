#!/usr/bin/env python3
"""Synthetic log analysis tests. No device, firmware, or memory fault tests."""
import json
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

API = runpy.run_path(str(Path(__file__).with_name('analyze-qsee-logcat.py')))
analyze = API['analyze']
PS = 'USER PID PPID VSZ RSS WCHAN ADDR S NAME\nroot 123 1 0 0 0 0 S mtd@1.3\n'
COLLECTOR = runpy.run_path(str(Path(__file__).with_name('collect-qsee-diagnostics.py')))


def line(t, message, tag='QSEECOMAPI', level='D', pid=123, tid=456):
    return f'190000000{t:.3f} {pid} {tid} {level} {tag}: {message}'


def cycle():
    return [
        line(0, 'QSEECom_get_handle sb_length = 0x8080'),
        line(.001, 'App is not loaded in QSEE'),
        line(.002, 'Loaded image: APP id = SYNTHETIC_APP'),
        line(.003, 'Response OK, size: 32', 'MTService-TEE'),
        line(.004, 'QSEECom_dealloc_memory'),
        line(.005, 'QSEECom_shutdown_app, app_id = SYNTHETIC_APP'),
        line(.006, 'QSEECom_dealloc_memory'),
        line(.007, 'Error::Cannot de-alloc memory. priv handle is NULL!!.', level='E'),
    ]


def summary(lines):
    return analyze(['\n'.join(lines)], [PS])['snapshots'][0]['groups']['mtd']


class LogAnalysis(unittest.TestCase):
    def test_full_cycle_and_deallocation_order(self):
        s = summary(cycle())
        self.assertEqual(s['complete_ordered_cycles'], 1)
        self.assertEqual(s['cycles_with_matching_app_ids'], 1)
        self.assertEqual(s['cycles_with_dealloc_before_and_after_shutdown'], 1)
        self.assertEqual(s['loaded_to_null_ms'], {'min': 5.0, 'max': 5.0})
        self.assertEqual(s['cycles_with_prior_failure_candidate'], 0)

    def test_probe_is_not_a_prior_failure(self):
        self.assertEqual(summary(cycle())['other_failure_candidates'], 0)

    def test_prior_failure_before_load_is_retained(self):
        rows = cycle()
        rows.insert(1, line(.0005, 'allocation failed: SYNTHETIC_SECRET', level='E'))
        self.assertEqual(summary(rows)['cycles_with_prior_failure_candidate'], 1)

    def test_error_level_identifier_diagnostic_is_not_failure(self):
        rows = cycle()
        rows.insert(2, line(.0015, 'get sn from prop: SYNTHETIC_SERIAL', 'MTService', 'E'))
        s = summary(rows)
        self.assertEqual(s['error_severity_records'], 2)
        self.assertEqual(s['cycles_with_prior_failure_candidate'], 0)

    def test_no_free_text_identifiers_or_absolute_times_in_output(self):
        rows = cycle() + [line(.008, 'unknown SYNTHETIC_SECRET account@example.test /private/path', level='E'),
                          line(.009, 'get sn from prop: SYNTHETIC_SERIAL', 'MTService', 'E'),
                          'malformed SYNTHETIC_SECRET']
        out = json.dumps(analyze(['\n'.join(rows)], [PS]))
        for private in ('SYNTHETIC', '1900000000', '123', '456', 'account@', '/private/path'):
            self.assertNotIn(private, out)

    def test_unknown_tag_is_excluded(self):
        rows = cycle() + [line(.008, 'password SYNTHETIC_SECRET', 'PRIVATE_TAG')]
        report = analyze(['\n'.join(rows)], [PS])
        self.assertEqual(report['snapshots'][0]['excluded_tag_records'], 1)
        self.assertNotIn('PRIVATE_TAG', json.dumps(report))

    def test_cross_thread_is_not_a_cycle(self):
        rows = cycle()
        rows[3] = rows[3].replace('123 456', '123 789')
        self.assertEqual(summary(rows)['complete_ordered_cycles'], 0)

    def test_cross_process_is_not_a_cycle(self):
        rows = cycle()
        rows[3] = rows[3].replace('123 456', '999 456')
        self.assertEqual(summary(rows)['complete_ordered_cycles'], 0)

    def test_mismatched_app_ids_rejected(self):
        rows = cycle()
        rows[5] = rows[5].replace('SYNTHETIC_APP', 'DIFFERENT_APP')
        s = summary(rows)
        self.assertEqual(s['complete_ordered_cycles'], 0)
        self.assertEqual(s['rejected_app_id_mismatches'], 1)

    def test_redacted_app_ids_do_not_prove_identity(self):
        s = summary([r.replace('SYNTHETIC_APP', '[redacted]') for r in cycle()])
        self.assertEqual(s['complete_ordered_cycles'], 1)
        self.assertEqual(s['cycles_with_matching_app_ids'], 0)
        self.assertEqual(s['cycles_without_app_id_evidence'], 1)

    def test_service_lookup_failure_is_not_hidden_by_diagnostic_label(self):
        rows = cycle()
        rows.insert(2, line(.0015, 'getFidoService: failed', 'MTService', 'I'))
        self.assertEqual(summary(rows)['cycles_with_prior_failure_candidate'], 1)

    def test_long_gap_does_not_join_cycles(self):
        rows = cycle()
        rows[-1] = rows[-1].replace('1900000000.007', '1900000009.007')
        self.assertEqual(summary(rows)['complete_ordered_cycles'], 0)

    def test_timestamp_regression_invalidates_pairing(self):
        rows = cycle()
        rows[-1] = rows[-1].replace('1900000000.007', '1899999999.007')
        report = analyze(['\n'.join(rows)], [PS])
        self.assertEqual(report['snapshots'][0]['timestamp_regressions'], 1)
        self.assertEqual(report['snapshots'][0]['groups']['mtd']['complete_ordered_cycles'], 0)

    def test_truncated_log_does_not_invent_success(self):
        self.assertEqual(summary(cycle()[4:])['null_errors_without_complete_cycle'], 1)

    def test_repeated_capture_is_not_new_activity(self):
        log = '\n'.join(cycle())
        delta = analyze([log, log], [PS, PS])['comparisons'][0]
        self.assertEqual(delta['newly_observed_records'], 0)
        self.assertEqual(delta['overlapping_records'], 8)

    def test_identical_lines_in_one_capture_keep_multiplicity(self):
        log = '\n'.join(cycle())
        more = log + '\n' + cycle()[-1]
        report = analyze([log, more], [PS, PS])
        self.assertEqual(report['comparisons'][0]['newly_observed_event_counts'], {'null_dealloc': 1})
        self.assertEqual(report['snapshots'][1]['groups']['mtd']['event_counts']['null_dealloc'], 2)

    def test_empty_snapshots_do_not_establish_continuity(self):
        self.assertEqual(analyze(['', ''])['comparisons'][0]['continuity'], 'unknown')

    def test_process_mapping_requires_matching_snapshot(self):
        s = analyze(['\n'.join(cycle())])['snapshots'][0]
        self.assertFalse(s['mtd_process_found'])
        self.assertEqual(s['groups']['mtd']['records'], 0)
        self.assertEqual(s['groups']['other_or_unattributed']['records'], 8)
        with self.assertRaises(ValueError):
            analyze(['a', 'b'], [PS])


class PassiveCollector(unittest.TestCase):
    def test_only_fixed_queries_and_allowlisted_property_values(self):
        calls = []

        def fake_adb(*args):
            calls.append(args)
            if args == ('get-state',):
                return 'device\n'
            if args[:2] == ('shell', 'getprop'):
                self.assertIn(args[2], COLLECTOR['PROPERTIES'])
                return 'SYNTHETIC_PRIVATE_VALUE'
            if args == ('shell', 'ps', '-A'):
                return PS
            if args == ('shell', 'cat', '/proc/uptime'):
                return '100.0 50.0'
            self.assertEqual(args, ('shell', 'logcat', '-d', '-b', 'main', '-v', 'epoch',
                                    'QSEECOMAPI:V', 'MTService-TEE:V', 'MTService:V', '*:S'))
            return '\n'.join(cycle())

        collect = COLLECTOR['collect']
        with patch.dict(collect.__globals__, {'adb': fake_adb}):
            report = collect(1, 1)
        self.assertNotIn('SYNTHETIC', json.dumps(report))
        self.assertEqual(len(calls), 1 + len(COLLECTOR['PROPERTIES']) + 3)

    def test_unavailable_device_stops_before_queries(self):
        collect = COLLECTOR['collect']
        with patch.dict(collect.__globals__, {'adb': lambda *args: 'offline'}):
            with self.assertRaises(RuntimeError):
                collect(1, 1)

    def test_adb_error_does_not_echo_serial_or_stderr(self):
        adb = COLLECTOR['adb']
        class Failed:
            returncode = 1
            stdout = 'SYNTHETIC_SERIAL'
            stderr = 'SYNTHETIC_SECRET'
        with patch.object(adb.__globals__['subprocess'], 'run', return_value=Failed()):
            with self.assertRaises(RuntimeError) as error:
                adb('get-state')
        self.assertNotIn('SYNTHETIC', str(error.exception))

    def test_reboot_during_collection_rejects_comparison(self):
        uptimes = iter(['100.0 0.0', '1.0 0.0'])
        def fake_adb(*args):
            if args == ('get-state',):
                return 'device'
            if args == ('shell', 'cat', '/proc/uptime'):
                return next(uptimes)
            return ''
        collect = COLLECTOR['collect']
        with patch.dict(collect.__globals__, {'adb': fake_adb}), \
                patch.object(collect.__globals__['time'], 'sleep'):
            with self.assertRaises(RuntimeError):
                collect(2, 1)


if __name__ == '__main__':
    unittest.main()
