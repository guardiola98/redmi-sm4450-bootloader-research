#!/usr/bin/env python3
"""Offline, hash-pinned kernel identity and privacy-preserving ADB observations.

No device commands, firmware execution, vulnerability stimulus or exploit logic.
Run from the repository root after collecting private inputs in ignored work/.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

COMMIT = '730d06ec05ff5dc34389ff99ea4009411efba5e6'
RELEASE = '5.10.246-android12-9-00012-g730d06ec05ff-ab15159037'
BOOT_SHA = '5e31f9004b4151c22edbe3ff2324284b7a08691f3d48d98a235cc7ec4b7e9120'
IMAGE_SHA = 'ab8958caf17a31b0a532aac0ecff2dda021ea4cfd6bbf0070098d04fd58569e7'
MAP_SHA = '165ee9ef732026c9bf902e6647e5e3076982b26286cfc4e88b64bc2b15f3b052'
CONFIG_SHA = 'f0f2ca7bd70fa65dae1930c7bf904e70d3e107bd2cbeab9e9450c5e6f4d3abc7'
SOURCE_HASHES = {'kernel/locking/rtmutex.c': 'f04c31a25bb4ddf8e4d79f55807e9656351f0ce049fc76d7b8fb895b3301a90e',
 'kernel/time/posix-cpu-timers.c': 'ac3bbf676f09074a84a46674a1d1e8113ad9199354bbac9b6f1ec0e38f34f862',
 'kernel/exit.c': 'e81c58332835633bda87d01ca779650889184f48b9fb9251b809456c221df188',
 'kernel/signal.c': '00af7ad1259a33319fbe42e938632d01949705e531d0443db8e92c48fd247377',
 'lib/iov_iter.c': 'b120ae7a256a2095a41d63d8a0047976d9acc33725e04be3b37b90913fb556f7',
 'kernel/bpf/verifier.c': '034bafaaef8d0148c488930950b723b70e0ebe853cee07156f921f0fe755db09',
 'drivers/android/binder.c': '71d729856231b65a5d31adb19ab22af51a641ed8f1fe1feb228e870f95d035c3',
 'kernel/fork.c': 'e6adce8f5d83eb523fcae30895addf01fa1e5f0e89091c4916316545a96175da',
 'mm/memory.c': '17b7f201d75a00a56ccf357ff613e37527a539fd149b3aed53d34e06a86cf3d1',
 'mm/pgsize_migration.c': 'ccf96eb4b2ad0e05e6770e236f210b2e5fa832daa5d87caed94b568496753899',
 'include/linux/pgsize_migration.h': 'c554508f7a4a011737c9b3bc45f03bea0ca14ca86679b23c167d2df13e806a46'}
CONFIG_KEYS = '''64BIT ARM64_4K_PAGES ARM64_16K_PAGES RANDOMIZE_BASE
ARM64_PAN ARM64_SW_TTBR0_PAN ARM64_UAO ARM64_PTR_AUTH ARM64_BTI ARM64_BTI_KERNEL
ARM64_MTE CFI_CLANG CFI_PERMISSIVE SHADOW_CALL_STACK STACKPROTECTOR_STRONG
VMAP_STACK STRICT_KERNEL_RWX STRICT_MODULE_RWX SLAB_FREELIST_RANDOM
SLAB_FREELIST_HARDENED HARDENED_USERCOPY FORTIFY_SOURCE MODULE_SIG
SECURITY_SELINUX SECURITY_SELINUX_DISABLE SECURITY_YAMA SECCOMP SECCOMP_FILTER
USER_NS NET_NS NF_TABLES CRYPTO_USER_API_AEAD BPF_SYSCALL BPF_JIT_ALWAYS_ON
FUTEX FUTEX_PI RT_MUTEXES POSIX_TIMERS POSIX_CPU_TIMERS_TASK_WORK
ANDROID_BINDER_IPC IO_URING XFRM_USER INET_ESP DMABUF_SYSFS_STATS'''.split()
SYSCTLS = '''kernel-randomize_va_space kernel-kptr_restrict kernel-dmesg_restrict
kernel-unprivileged_bpf_disabled kernel-perf_event_paranoid kernel-yama-ptrace_scope
kernel-unprivileged_userns_clone user-max_user_namespaces vm-mmap_rnd_bits
vm-mmap_rnd_compat_bits kernel-modules_disabled kernel-io_uring_disabled'''.split()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_read(path, limit):
    with path.open('rb') as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError('Input exceeds read limit')
    return data


def gunzip(data, limit=512*1024):
    decoder = zlib.decompressobj(31)
    try:
        result = decoder.decompress(data, limit + 1)
    except zlib.error as exc:
        raise ValueError('Invalid gzip input') from exc
    if len(result) > limit or not decoder.eof or decoder.unused_data:
        raise ValueError('Oversized, truncated or concatenated gzip input')
    return result


def boot_kernel(data):
    if len(data) < 4096 or data[:8] != b'ANDROID!':
        raise ValueError('Invalid boot header')
    size, ramdisk, _, header = struct.unpack_from('<IIII', data, 8)
    version, = struct.unpack_from('<I', data, 40)
    if version != 4 or header != 1584 or not 64 <= size <= 64*1024*1024:
        raise ValueError('Unsupported boot layout')
    end = 4096 + size
    ramdisk_start = (end + 4095) & ~4095
    if end > len(data) or ramdisk_start + ramdisk > len(data):
        raise ValueError('Truncated boot payload')
    image = data[4096:end]
    if image[56:60] != b'ARM\x64':
        raise ValueError('Not an uncompressed ARM64 Image')
    return image


def image_config(image):
    marker = b'IKCFG_ST'
    if image.count(marker) != 1:
        raise ValueError('Ambiguous IKCONFIG marker')
    start = image.index(marker) + len(marker)
    end = image.find(b'IKCFG_ED', start)
    if end < start or end - start > 512*1024:
        raise ValueError('Invalid IKCONFIG extent')
    return gunzip(image[start:end])


def selected_config(data):
    values = {}
    for line in data.decode('ascii').splitlines():
        set_match = re.fullmatch(r'CONFIG_(\w+)=(.*)', line)
        off_match = re.fullmatch(r'# CONFIG_(\w+) is not set', line)
        if set_match:
            key, value = set_match.groups()
        elif off_match:
            key, value = off_match.group(1), 'n'
        else:
            continue
        if key not in CONFIG_KEYS:
            continue
        if key in values:
            raise ValueError('Duplicate selected config key')
        if value not in ('y', 'm', 'n'):
            raise ValueError('Unexpected selected config value')
        values[key] = value
    return {'CONFIG_'+key: values.get(key, 'unknown') for key in CONFIG_KEYS}


def scalar_status(stdout, stderr, exit_code, pattern):
    """Never echo error text or unmatched values, even with host exit code zero."""
    combined = stdout + stderr
    for token, state in [(b'Permission denied', 'denied'),
                         (b'No such file', 'missing'),
                         (b'no devices/emulators', 'unavailable')]:
        if token in combined:
            return {'status': state}
    if exit_code != 0 or stderr.strip():
        return {'status': 'error'}
    try:
        value = stdout.decode('ascii').strip()
    except UnicodeDecodeError:
        return {'status': 'invalid'}
    if not re.fullmatch(pattern, value):
        return {'status': 'invalid'}
    return {'status': 'observed', 'value': value}


def probe_summary(records):
    if not records or len(records) > 20:
        raise ValueError('Expected 1..20 own-process samples')
    result = {'samples': len(records)}
    for key in ('uid', 'euid', 'page_size', 'seccomp', 'paca', 'pacg', 'bti', 'mte'):
        vals = [r.get(key) for r in records]
        if any(type(v) is not int or not 0 <= v <= 65536 for v in vals):
            raise ValueError('Invalid probe scalar')
        if key in ('paca','pacg','bti','mte') and any(v not in (0,1) for v in vals):
            raise ValueError('Invalid capability bit')
        result[key] = sorted(set(vals))
    result['distinct_addresses'] = {}
    for key in ('image', 'stack', 'mapping'):
        vals = [r.get(key) for r in records]
        if any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{1,16}',v) for v in vals):
            raise ValueError('Invalid private address')
        result['distinct_addresses'][key] = len(set(vals))
    return result


def observations(directory):
    meta = json.loads(bounded_read(directory/'commands.json', 65536))
    def read(name, pattern):
        if name not in meta or meta[name].get('timeout'):
            return {'status':'not_collected'}
        return scalar_status(bounded_read(directory/(name+'.bin'),65536),
                             bounded_read(directory/(name+'.err'),65536),
                             meta[name]['exit'], pattern)
    props = {
        'ro.build.version.security_patch':r'20\d{2}-\d{2}-\d{2}',
        'ro.vendor.build.security_patch':r'20\d{2}-\d{2}-\d{2}',
        'ro.build.version.incremental':r'OS2\.0\.218\.0\.VMWEUXM',
        'ro.boot.verifiedbootstate':r'green|yellow|orange|red',
        'ro.boot.flash.locked':r'[01]', 'ro.boot.vbmeta.device_state':r'locked|unlocked',
        'ro.boot.secureboot':r'[01]', 'ro.secure':r'[01]', 'ro.debuggable':r'[01]',
        'ro.adb.secure':r'[01]', 'ro.build.type':r'user|userdebug|eng',
    }
    result = dict(kernel_release=read('kernel-release',re.escape(RELEASE)),
                  selinux=read('selinux',r'Enforcing|Permissive|Disabled'),
                  properties={k:read(k,v) for k,v in props.items()},
                  sysctls={k:read(k,r'-?\d{1,10}') for k in SYSCTLS})
    samples = sorted(directory.glob('probe-[0-9].json'))
    if samples:
        result['own_process'] = probe_summary([json.loads(bounded_read(f,4096)) for f in samples])
    return result


def source_checks(directory):
    paths = ['kernel/locking/rtmutex.c','kernel/time/posix-cpu-timers.c',
             'kernel/exit.c','kernel/signal.c','lib/iov_iter.c','kernel/bpf/verifier.c',
             'drivers/android/binder.c','kernel/fork.c','mm/memory.c',
             'mm/pgsize_migration.c','include/linux/pgsize_migration.h']
    texts, files = {}, []
    for path in paths:
        data = bounded_read(directory/('ack-'+path.replace('/','_')), 2*1024*1024)
        if digest(data) != SOURCE_HASHES[path]:
            raise ValueError('ACK source does not match the reviewed revision')
        texts[path] = data.decode('utf-8')
        files.append(dict(path=path,sha256=digest(data),
                          url='https://android.googlesource.com/kernel/common/+/'+COMMIT+'/'+path))
    rt = texts['kernel/locking/rtmutex.c'].split('static void remove_waiter(',1)[1].split('\n}',1)[0]
    timer = texts['kernel/time/posix-cpu-timers.c']
    delete = timer.split('static int posix_cpu_timer_del(',1)[1].split('\n}',1)[0]
    run = timer.split('\nvoid run_posix_cpu_timers(',1)[1].split('\n}',1)[0]
    pipe = texts['lib/iov_iter.c']
    verifier = texts['kernel/bpf/verifier.c'].split('static int backtrack_insn(',1)[1].split('\n}',1)[0]
    binder = texts['drivers/android/binder.c']
    checks = {
        '43499_remove_waiter_uses_current': all(s in rt for s in [
            'raw_spin_lock(&current->pi_lock)', 'current->pi_blocked_on = NULL',
            'next_lock, NULL, current']),
        '64560_old_timer_delete_and_no_retry_helper':
            'lock_task_sighand(p, &flags)' in delete and 'WARN_ON_ONCE(ctmr->head' in delete
            and 'timer_lock_sighand' not in timer,
        '64560_exit_without_release_store': 'tsk->sighand = NULL;' in texts['kernel/exit.c'],
        '64560_sighand_lookup_without_acquire_barrier':
            'smp_acquire__after_ctrl_dep' not in texts['kernel/signal.c'].split(
                'struct sighand_struct *__lock_task_sighand(',1)[1].split('\n}',1)[0],
        '38352_exit_state_guard_present': 'if (tsk->exit_state)' in run,
        '0847_pipe_flags_initialized': all('buf->flags = 0;' in pipe.split(n+'(',1)[1].split('\n}',1)[0]
            for n in ['copy_page_to_iter_pipe','push_pipe']),
        '2163_verifier_jmp32_marks_both_registers': '*reg_mask |= (sreg | dreg);' in verifier,
        '20938_deferred_copy_and_fda_guards_present': all(s in binder for s in [
            'binder_do_deferred_txn_copies(', 'if (fda->num_fds == 0)',
            'sender_ufda_base = (void __user *)(uintptr_t)sender_uparent->buffer',
            'list_for_each_entry_safe(pf, tmppf, pf_head, node)',
            'copy_from_user(&fd, sender_ufda_base + sender_uoffset, sizeof(fd))']),
        '23184_binder_netlink_report_absent': 'binder_netlink_report' not in binder,
        '58825_fork_dmabuf_info_absent': 'dmabuf_info' not in texts['kernel/fork.c'],
        '58942_page_migration_code_present_not_a_vulnerability_verdict':
            'vma_data_pages(vmf->vma)' in texts['mm/memory.c'] and
            'DEFINE_STATIC_KEY_TRUE(pgsize_migration_enabled)' in texts['mm/pgsize_migration.c'],
    }
    if not all(checks.values()):
        raise ValueError('Selected source evidence changed; review manually')
    return {'files':files,'checks':checks,
            'scope':'Selected source predicates reviewed against public fixes, not a universal CVE scanner'}


def inspect(boot, official, system_map, live_config):
    if digest(boot) != BOOT_SHA or digest(official) != IMAGE_SHA or digest(system_map) != MAP_SHA:
        raise ValueError('Unexpected public firmware/build artifact hash')
    image = boot_kernel(boot)
    if image != official:
        raise ValueError('Firmware payload differs from official GKI')
    config = image_config(image)
    if config != live_config or digest(config) != CONFIG_SHA:
        raise ValueError('Live and package config do not match expected build')
    functions = {}
    entries = []
    for line in system_map.decode('ascii').splitlines():
        addr, typ, name = line.split()
        entries.append((int(addr,16),typ,name))
    base = next(a for a,t,n in entries if n == '_text')
    for name in ['remove_waiter','posix_cpu_timer_del','run_posix_cpu_timers','copy_page_to_iter_pipe']:
        matches = [a for a,t,n in entries if n == name and t.lower() == 't']
        if len(matches) != 1:
            raise ValueError('Ambiguous selected function')
        a = matches[0]
        end = min(p for p,t,n in entries if p > a and t.lower() == 't')
        start, stop = a-base, end-base
        if not 0 <= start < stop <= len(image):
            raise ValueError('Symbol not in Image')
        functions[name] = dict(size=stop-start,sha256=digest(image[start:stop]))
    return dict(commit=COMMIT,release=RELEASE,build_id=15159037,
                tag='android12-5.10-2025-12_r3',boot_sha256=BOOT_SHA,
                image_url='https://ci.android.com/builds/submitted/15159037/kernel_aarch64/latest/raw/Image',
                system_map_url='https://ci.android.com/builds/submitted/15159037/kernel_aarch64/latest/raw/System.map',
                image_sha256=IMAGE_SHA,image_bytes=len(image),system_map_sha256=MAP_SHA,
                config_sha256=CONFIG_SHA,package_equals_official=True,
                live_config_equals_package=True,selected_functions=functions,
                config=selected_config(config),
                limit='Package identity and live config/release correlation; no live-memory or active-partition attestation')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs',type=Path,default=Path('work/kernel-audit-2026-11-10'))
    args = ap.parse_args()
    p = args.inputs
    result = inspect(bounded_read(Path('work/audit-images/boot.img'),128*1024*1024),
                     bounded_read(p/'sources/official-Image',64*1024*1024),
                     bounded_read(p/'sources/System.map',8*1024*1024),
                     gunzip(bounded_read(p/'config.bin',512*1024)))
    result['observations'] = observations(p)
    result['source_evidence'] = source_checks(p/'sources')
    Path('docs/android-kernel-evidence.json').write_text(json.dumps(result,indent=2)+'\n')
    print('Verified package/GKI identity, live config, selected source checks and anonymized observations')


if __name__ == '__main__':
    main()
