#!/usr/bin/env python3
"""Passive ADB snapshots; print only aggregate JSON, keep raw data in memory.

No root, service calls, log clearing, setprop, reboot, fastboot or stimulation.
Only an already connected, uniquely authorized device is accepted. Inspect
the aggregate before sharing. Capture tags can contain sensitive identifiers.
"""
import argparse
import json
from pathlib import Path
import runpy
import subprocess
import time

ANALYZE = runpy.run_path(str(Path(__file__).with_name('analyze-qsee-logcat.py')))['analyze']
PROPERTIES = {
    'ro.boot.verifiedbootstate': {'green', 'yellow', 'orange', 'red'},
    'ro.boot.flash.locked': {'0', '1'},
    'ro.boot.vbmeta.device_state': {'locked', 'unlocked'},
    'ro.boot.secureboot': {'0', '1'},
    'ro.boot.veritymode': {'enforcing', 'logging', 'eio', 'disabled'},
    'ro.boot.slot_suffix': {'_a', '_b'},
    'init.svc.qseecom-service': {'running', 'stopped', 'restarting'},
    'init.svc.qseelogd': {'running', 'stopped', 'restarting'},
}


def adb(*args):
    try:
        p = subprocess.run(['adb', *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError('ADB unavailable or timed out; details omitted') from None
    if p.returncode:
        raise RuntimeError('ADB query failed; device details omitted')
    return p.stdout


def collect(samples, interval):
    # Do not print serials, daemon stderr, arbitrary properties or process names.
    if adb('get-state').strip() != 'device':
        raise RuntimeError('Exactly one authorized ADB device is required')
    logs, processes, properties, times, uptimes = [], [], [], [], []
    for index in range(samples):
        if index:
            time.sleep(interval)
        state = {}
        for key, allowed in PROPERTIES.items():
            value = adb('shell', 'getprop', key).strip()
            state[key] = value if value in allowed else 'unavailable_or_unrecognized'
        properties.append(state)
        processes.append(adb('shell', 'ps', '-A'))
        uptimes.append(float(adb('shell', 'cat', '/proc/uptime').split()[0]))
        times.append(time.monotonic())
        logs.append(adb('shell', 'logcat', '-d', '-b', 'main', '-v', 'epoch',
                        'QSEECOMAPI:V', 'MTService-TEE:V', 'MTService:V', '*:S'))
    if any(b < a for a, b in zip(uptimes, uptimes[1:])):
        raise RuntimeError('Uptime regressed; do not compare different boots')
    report = ANALYZE(logs, processes)
    report['observation_interval_seconds'] = round(times[-1] - times[0], 3)
    report['uptime_interval_seconds'] = round(uptimes[-1] - uptimes[0], 3)
    report['selected_properties'] = properties
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=3, choices=range(1, 11), metavar='1..10')
    parser.add_argument('--interval', type=int, default=30, choices=range(1, 61), metavar='1..60',
                        help='Seconds between captures (default 30)')
    args = parser.parse_args()
    try:
        result = collect(args.samples, args.interval)
    except (RuntimeError, ValueError, IndexError):
        parser.exit(1, 'Capture unavailable or incomplete; no raw details emitted.\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
