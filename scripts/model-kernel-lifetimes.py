#!/usr/bin/env python3
"""Finite contract illustrations, not kernel reproductions or race schedulers.

No threads, syscalls, addresses, memory allocation primitives or device access.
Each state is supplied explicitly. Python does not model ARM64 memory ordering.
Models explain reviewed ownership rules; they cannot establish reachability,
timing, exploitability, or absence of other bugs in the actual kernel.
"""


def rt_cleanup(*, version, proxy, armed, result):
    """Compare the proxy wrapper and cleanup ownership, abstracting PI trees.

    result: -1 error, 0 queued, 1 acquired. armed: waiter->task initialized.
    'identity-only' deliberately represents an incomplete fix, not a release.
    """
    if version not in ('old', 'identity-only', 'full') or result not in (-1, 0, 1):
        raise ValueError('Unknown model state')
    state = dict(cleaned=False, dangling_waiter_reference=False,
                 unrelated_current_modified=False, null_task_access=False,
                 chain_target_matches=True)
    called = result < 0 if version == 'full' else result != 0
    if not called or (version == 'full' and not armed):
        return state
    if version != 'old' and not armed:
        state['null_task_access'] = True
        return state
    state['cleaned'] = True
    if version == 'old' and proxy and armed:
        state.update(dangling_waiter_reference=True,
                     unrelated_current_modified=True, chain_target_matches=False)
    return state


def timer_delete(*, version, target, queued, firing=False):
    """Object graph after deletion and an assumed completed RCU grace period.

    target='handover': the cached old leader lost sighand while the process
    and its CPU-timer queue survived. 'gone': normal exit cleaned the queue.
    The full case assumes the fix's ordering guarantees; it does not prove them.
    """
    if version not in ('old', 'full') or target not in ('stable', 'handover', 'gone'):
        raise ValueError('Unknown model state')
    if target == 'gone':
        queued = False
    locked = target == 'stable' or (version == 'full' and target == 'handover')
    retry = locked and firing
    if locked and not firing:
        queued = False
    freed_after_grace = not retry
    return dict(relooked_up=version == 'full' and target == 'handover',
                retry=retry, freed_after_grace=freed_after_grace,
                queue_points_to_freed=queued and freed_after_grace)


def ddr_fragment_count(sizes, capacities):
    """Counts only: two DDR amounts consumed across two fixed range capacities.

    Abstracts XBL's min/subtract loop; no bases, SMEM descriptors or firmware.
    Assumes the source arrays/count are not modified during the loop.
    """
    if len(sizes) != 2 or len(capacities) != 2 or any(
            type(x) is not int or x < 0 for x in (*sizes, *capacities)):
        raise ValueError('Expected two nonnegative counts per input')
    capacities = list(capacities)
    index = count = 0
    for remaining in sizes:
        while remaining and index < 2:
            amount = min(remaining, capacities[index])
            capacities[index] -= amount
            remaining -= amount
            count += 1
            if capacities[index] == 0:
                index += 1
    return count
