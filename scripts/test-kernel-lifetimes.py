#!/usr/bin/env python3
"""Host-only tests of explicit ownership states; never exercise the kernel bugs."""
import itertools
from pathlib import Path
import runpy
import unittest

M = runpy.run_path(str(Path(__file__).with_name('model-kernel-lifetimes.py')))


class Contracts(unittest.TestCase):
    def test_proxy_rollback_exposes_old_identity_mismatch(self):
        old = M['rt_cleanup'](version='old',proxy=True,armed=True,result=-1)
        self.assertTrue(old['dangling_waiter_reference'])
        self.assertTrue(old['unrelated_current_modified'])
        self.assertFalse(old['chain_target_matches'])

    def test_same_task_cleanup_does_not_show_identity_bug(self):
        for version in ('old','full'):
            state=M['rt_cleanup'](version=version,proxy=False,armed=True,result=-1)
            self.assertTrue(state['cleaned'])
            self.assertFalse(state['dangling_waiter_reference'])

    def test_full_fix_uses_waiter_identity_on_proxy_error(self):
        state=M['rt_cleanup'](version='full',proxy=True,armed=True,result=-1)
        self.assertTrue(state['cleaned'])
        self.assertFalse(state['dangling_waiter_reference'])
        self.assertFalse(state['unrelated_current_modified'])
        self.assertTrue(state['chain_target_matches'])

    def test_identity_substitution_alone_breaks_unarmed_case(self):
        self.assertTrue(M['rt_cleanup'](version='identity-only',proxy=True,
                                       armed=False,result=-1)['null_task_access'])
        self.assertFalse(M['rt_cleanup'](version='full',proxy=True,
                                        armed=False,result=-1)['cleaned'])

    def test_full_wrapper_preserves_queued_and_acquired_results(self):
        for result in (0,1):
            for armed in (False,True):
                self.assertFalse(M['rt_cleanup'](version='full',proxy=True,
                                                armed=armed,result=result)['cleaned'])

    def test_old_success_check_is_too_broad(self):
        self.assertTrue(M['rt_cleanup'](version='old',proxy=True,
                                       armed=False,result=1)['cleaned'])

    def test_old_timer_handover_leaves_queue_edge_after_grace(self):
        state=M['timer_delete'](version='old',target='handover',queued=True)
        self.assertTrue(state['queue_points_to_freed'])
        self.assertFalse(state['retry'])

    def test_fixed_timer_handover_relooks_up_and_dequeues(self):
        state=M['timer_delete'](version='full',target='handover',queued=True)
        self.assertTrue(state['relooked_up'])
        self.assertFalse(state['queue_points_to_freed'])

    def test_disarmed_timer_is_negative_control(self):
        for version in ('old','full'):
            self.assertFalse(M['timer_delete'](version=version,target='handover',
                                              queued=False)['queue_points_to_freed'])

    def test_normal_exit_is_not_leader_handover(self):
        for version in ('old','full'):
            self.assertFalse(M['timer_delete'](version=version,target='gone',
                                              queued=True)['queue_points_to_freed'])

    def test_firing_preserves_retry_and_prevents_free(self):
        for version in ('old','full'):
            state=M['timer_delete'](version=version,target='stable',queued=True,firing=True)
            self.assertTrue(state['retry'])
            self.assertFalse(state['freed_after_grace'])

    def test_full_timer_cases_preserve_queue_lifetime(self):
        for target,queued,firing in itertools.product(
                ('stable','handover','gone'),(False,True),(False,True)):
            self.assertFalse(M['timer_delete'](version='full',target=target,
                                              queued=queued,firing=firing)['queue_points_to_freed'])

    def test_ddr_two_by_two_bound_with_zero_and_partial_ranges(self):
        observed=set()
        for values in itertools.product(range(6), repeat=4):
            count=M['ddr_fragment_count'](values[:2],values[2:])
            observed.add(count)
            self.assertLessEqual(count,3)
        self.assertEqual(observed,{0,1,2,3})

    def test_model_inputs_are_explicit(self):
        with self.assertRaises(ValueError):
            M['ddr_fragment_count']((1,-1),(1,2))
        with self.assertRaises(ValueError):
            M['rt_cleanup'](version='guess',proxy=True,armed=True,result=-1)


if __name__=='__main__':unittest.main()
