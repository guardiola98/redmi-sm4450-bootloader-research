#!/usr/bin/env python3
"""Synthetic contracts only: symbolic owners/statuses, no firmware or payloads.

Evidence: TzDxeLA 0x1e74/0x1f2c/0x3454; ShmBridgeDxe 0x2890/0x2b4c.
These tests establish conditional state transitions, not runtime observations.
"""
import unittest

EFI_ERROR = 1 << 63


def diagnostic_route(security_status, marker, flags, encrypted_status, encrypted):
    if not security_status & EFI_ERROR and marker == 1 and flags & 0x501:
        return 'security-stop'
    if encrypted_status & EFI_ERROR:
        return 'query-stop'
    return 'encrypted' if encrypted == 1 else 'policy'


def load_result(transport_status, application_id):
    # 0x1d08 discards the ID on any nonzero status; diagnostic returns void.
    value = 0 if transport_status else application_id & 0xffffffff
    return EFI_ERROR | 1 if ((value + 1) & 0xffffffff) < 2 else 0


class SharedBlock:
    """One symbolic registered node, initially owned by TzDxeLA."""
    def __init__(self):
        self.owner = 'tz'
        self.capacity = 0x82000
        self.available_bytes = 0

    def release(self):
        # Matching pointer is enough: provider does not check the busy flag.
        self.owner = None
        self.available_bytes += self.capacity

    def acquire(self, owner):
        if self.owner is not None:
            raise ValueError('Model only allows reuse of a free block')
        self.owner = owner
        self.available_bytes -= self.capacity


def cached_get(block, size):
    if not 0 < size <= block.capacity:
        raise ValueError('This bounded model covers the cache-hit path only')
    # TzDxeLA returns cached pointer without acquiring the provider node.
    return block


def private_release(registry, pointer):
    """Unknown pointers are silently ignored; registries model distinct lists."""
    if pointer in registry:
        registry[pointer] = False


def initial_loads(version_status, version, config_status, flags, operation18):
    """Successful GUID paths in 0x2fb0 only; no file contents or secure calls.

    Service operations do not enter the application-error diagnostic helper.
    All selected reads/loads are assumed to return successfully in this model.
    """
    if version_status & EFI_ERROR:
        return []
    loads = []
    if version >= 0x401000 and config_status == 0 and flags & 4 and operation18:
        loads.extend(['service', 'service'])
    if config_status == 0 and flags & 0x80:
        loads.append('application')
    return loads


def feature_load_route(family, locate_status, first_status, second_status):
    """FeatureEnabler 0x1444/0x2450, non-null context/interface, empty cache.

    Status arguments model returning calls, not induced firmware failures.
    """
    if family not in (116, 127, 123, 130) or locate_status:
        return []
    calls = ['qsee+8:first-label']
    if first_status:
        calls.append('qsee+8:second-label')
        if second_status:
            calls.append('qsee+0x20:partition-guid')
    return calls


def tz_load_source(interface, slot, file_argument):
    """Equal slot numbers in distinct interfaces do not imply equal ABIs."""
    if (interface, slot) == ('qsee', 0x20):
        # 0x3228 forces x2=0; incoming x2 is the out-ID, not a file name.
        file_argument = None
    elif (interface, slot) == ('first-tz', 0x38):
        return 'filesystem'  # 0x27ec calls 0x2630 (which validates inputs).
    elif (interface, slot) != ('first-tz', 0x20):
        raise ValueError('Outside reviewed entries')
    return 'filesystem' if file_argument is not None else 'partition-guid'


def publication_lifetime(first=0, qsee=0, last=0, enable_qsee=True):
    """Symbolic image/registration ownership, no allocator failure injection.

    Each publication is a separate one-pair InstallMultiple call. Its failed
    transaction cannot remove protocols from earlier successful transactions.
    Assume valid native image, returning cleanup callbacks and successful
    DxeCore page release after a returned EFI_ERROR. ASSERT does not return.
    """
    state = dict(registrations=set(), cache_busy=True, image_live=True,
                 returned=True)
    status = first
    if first == 0:
        state['registrations'].add('first-on-child')
        if enable_qsee:
            if qsee & EFI_ERROR:
                state['returned'] = False
                return state
            if qsee == 0:
                state['registrations'].add('qsee-on-image')
            status = qsee
        if status == 0:
            status = last
            if last == 0:
                state['registrations'].add('last-on-image')
    if status & EFI_ERROR:
        state['image_live'] = False
    return state


def notification_observation(old_tpl, notify_tpl, subscriber):
    """DxeCore RestoreTPL can dispatch pending higher-TPL notifications.

    Tz publishes with SCM still uninitialized, then locates SCM after the
    InstallMultiple return. None means no callback in that interval.
    """
    if not 0 <= old_tpl <= 16 or notify_tpl not in (8, 16):
        raise ValueError('Outside the bounded TPL model')
    scm_ready = False
    observed = scm_ready if subscriber and notify_tpl > old_tpl else None
    scm_ready = True
    return observed, scm_ready


class ResourceTests(unittest.TestCase):
    def test_qsee_guid_wrapper_cannot_select_file_branch(self):
        for argument in (None, 'symbolic-out-id'):
            self.assertEqual(tz_load_source('qsee', 0x20, argument), 'partition-guid')

    def test_first_protocol_file_entry_is_a_different_interface(self):
        self.assertEqual(tz_load_source('first-tz', 0x20, 'symbolic-path'), 'filesystem')
        self.assertEqual(tz_load_source('first-tz', 0x20, None), 'partition-guid')
        self.assertEqual(tz_load_source('first-tz', 0x38, 'symbolic-path'), 'filesystem')

    def test_feature_fallback_requires_two_nonzero_named_results(self):
        self.assertEqual(len(feature_load_route(130, 0, 0, 1)), 1)
        self.assertEqual(len(feature_load_route(130, 0, 1, 0)), 2)
        self.assertEqual(feature_load_route(130, 0, 1, 1)[-1], 'qsee+0x20:partition-guid')

    def test_feature_platform_and_locate_gates(self):
        self.assertEqual(feature_load_route(0, 0, 1, 1), [])
        self.assertEqual(feature_load_route(130, EFI_ERROR | 14, 1, 1), [])
        # Android soc_id is not the UEFI ChipFamily enum.
        self.assertEqual(feature_load_route(568, 0, 1, 1), [])

    def test_observed_chip_family_does_not_enter_feature_qsee_route(self):
        # Observed Android chip_family=0x8d, distinct from soc_id=568.
        for first in (0, 1):
            for second in (0, 1):
                self.assertEqual(feature_load_route(141, 0, first, second), [])
        for family in (116, 127, 123, 130):
            self.assertTrue(feature_load_route(family, 0, 1, 1))

    def test_security_and_encryption_errors_are_distinct_gates(self):
        self.assertEqual(diagnostic_route(0, 1, 0x100, 0, 0), 'security-stop')
        self.assertEqual(diagnostic_route(EFI_ERROR | 7, 1, 0x100, 0, 0), 'policy')
        self.assertEqual(diagnostic_route(0, 0, 0x100, EFI_ERROR | 3, 0), 'query-stop')
        self.assertEqual(diagnostic_route(0, 1, 0, 0, 1), 'encrypted')

    def test_returned_diagnostic_cannot_repair_load_error(self):
        for error in (1, EFI_ERROR | 3, EFI_ERROR | 9):
            self.assertEqual(load_result(error, 17), EFI_ERROR | 1)
        for invalid_id in (0, 0xffffffff):
            self.assertEqual(load_result(0, invalid_id), EFI_ERROR | 1)
        self.assertEqual(load_result(0, 17), 0)

    def test_serial_cache_reuse_does_not_reacquire_ownership(self):
        block = SharedBlock()
        cached_get(block, 16).release()
        reused = cached_get(block, 16)
        self.assertIsNone(reused.owner)
        reused.release()
        self.assertEqual(block.available_bytes, 2 * block.capacity)

    def test_intervening_allocation_can_alias_the_stale_cache(self):
        block = SharedBlock()
        cached_get(block, 16).release()
        block.acquire('another-client')
        reused = cached_get(block, 16)
        self.assertEqual(reused.owner, 'another-client')
        # Caller still releases it. No actual memory access is performed.
        reused.release()
        self.assertIsNone(block.owner)

    def test_foreign_allocator_cannot_release_shared_node(self):
        shared = {'shared-node': True}
        private = {'private-node': True}
        private_release(private, 'shared-node')
        self.assertTrue(shared['shared-node'])
        self.assertTrue(private['private-node'])
        private_release(private, 'private-node')
        self.assertFalse(private['private-node'])

    def test_one_lazy_initialization_can_repeat_cache_release(self):
        loads = initial_loads(0, 0x401000, 0, 0xc4, 1)
        self.assertEqual(loads, ['service', 'service', 'application'])
        block = SharedBlock()
        for _ in loads:
            cached_get(block, 16).release()
        self.assertEqual(block.available_bytes, 3 * block.capacity)
        self.assertIsNone(block.owner)

    def test_load_sequence_requires_each_gate(self):
        self.assertEqual(initial_loads(EFI_ERROR | 7, 0x401000, 0, 0xc4, 1), [])
        self.assertEqual(initial_loads(0, 0x400fff, 0, 0xc4, 1), ['application'])
        self.assertEqual(initial_loads(0, 0x401000, EFI_ERROR | 14, 0xc4, 1), [])
        self.assertEqual(initial_loads(0, 0x401000, 0, 0xc4, 0), ['application'])
        self.assertEqual(initial_loads(0, 0x401000, 0, 0, 1), [])

    def test_late_publication_error_outlives_image(self):
        state = publication_lifetime(last=EFI_ERROR | 9)
        self.assertEqual(state['registrations'], {'first-on-child', 'qsee-on-image'})
        self.assertFalse(state['image_live'])
        # QSEE is optional; the first independent publication is sufficient.
        state = publication_lifetime(last=EFI_ERROR | 9, enable_qsee=False)
        self.assertEqual(state['registrations'], {'first-on-child'})
        self.assertFalse(state['image_live'])

    def test_first_publication_failure_retains_cache_without_protocol(self):
        state = publication_lifetime(first=EFI_ERROR | 9)
        self.assertEqual(state['registrations'], set())
        self.assertTrue(state['cache_busy'])
        self.assertFalse(state['image_live'])

    def test_qsee_assert_does_not_imply_returned_error_unload(self):
        state = publication_lifetime(qsee=EFI_ERROR | 9)
        self.assertFalse(state['returned'])
        self.assertTrue(state['image_live'])
        self.assertEqual(state['registrations'], {'first-on-child'})

    def test_successful_publications_keep_their_image_live(self):
        state = publication_lifetime()
        self.assertTrue(state['returned'])
        self.assertTrue(state['image_live'])
        self.assertEqual(len(state['registrations']), 3)

    def test_pending_notification_can_observe_partial_initialization(self):
        for notify_tpl in (8, 16):
            self.assertEqual(notification_observation(4, notify_tpl, True), (False, True))

    def test_no_subscriber_is_not_evidence_of_reentry(self):
        self.assertEqual(notification_observation(4, 8, False), (None, True))

    def test_equal_or_lower_priority_stays_deferred_at_this_restore(self):
        self.assertEqual(notification_observation(8, 8, True), (None, True))
        self.assertEqual(notification_observation(16, 8, True), (None, True))


if __name__ == '__main__':
    unittest.main()
