#!/usr/bin/env python3
"""One pass of fixed, read-only ADB diagnostics, kept in a private ignored folder.

No serial listing, broad getprop, logs, privileged IPC, node opens/ioctls,
root, permission changes, reboot or fault stimulus. Does not run the C probe.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def queries(scope='baseline'):
    if scope == 'followup':
        return {
            'gpu-model':('Which GPU model is exposed?', ['shell','cat','/sys/class/kgsl/kgsl-3d0/gpu_model']),
            'gpu-revision':('Which GPU revision is exposed?', ['shell','cat','/sys/class/kgsl/kgsl-3d0/gpu_revision']),
            'vendor-module-names':('Which selected vendor modules are loaded?',
                ['shell',"grep -E '^(msm_kgsl|frpc_adsprpc|qcom_fastrpc|fastrpc|adsprpc) ' /proc/modules | cut -d ' ' -f 1-5"]),
            'vendor-module-files':('Are the selected module files exposed?',
                ['shell',"ls -l /vendor/lib/modules/*kgsl* /vendor_dlkm/lib/modules/*kgsl* /vendor/lib/modules/*fastrpc* /vendor_dlkm/lib/modules/*fastrpc* /vendor/lib/modules/*adsprpc* /vendor_dlkm/lib/modules/*adsprpc*"]),
            'fastrpc-nodes':('Which FastRPC node metadata is exposed?',
                ['shell',"ls -lZ /dev/fastrpc* /dev/adsprpc* /dev/cdsprpc*"]),
            'page-compat':('What maximum page size does the product declare?',
                ['shell','getprop','ro.product.cpu.pagesize.max']),
            'page-migration-enabled':('Is the identified page migration static key enabled?',
                ['shell','cat','/sys/kernel/mm/pgsize_migration/enabled']),
        }
    if scope != 'baseline':
        raise ValueError('Unknown diagnostic scope')
    result = {
        'kernel-release':('Which exact kernel is running?', ['shell','uname','-r']),
        'kernel-version':('Which compiler/build metadata is reported?', ['shell','uname','-v']),
        'config':('Which kernel features were compiled?', ['exec-out','cat','/proc/config.gz']),
        'features':('Which ARM64 capabilities are exposed?', ['shell',"grep '^Features' /proc/cpuinfo"]),
        'selinux':('Is SELinux enforcing?', ['shell','getenforce']),
        'shell-domain':('Which domain constrains this shell?', ['shell','cat','/proc/self/attr/current']),
        'shell-status':('Which credentials/capabilities/seccomp constrain this child?',
                        ['shell',"grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|NoNewPrivs|Seccomp):' /proc/self/status"]),
        'device-nodes':('Which selected driver nodes exist and with what metadata?',
                        ['shell','ls','-lZ','/dev/kgsl-3d0','/dev/dma_heap/system','/dev/ion',
                         '/dev/binder','/dev/hwbinder','/dev/vndbinder','/dev/qseecom','/dev/dri/renderD128']),
    }
    for prop in ['ro.build.version.security_patch','ro.vendor.build.security_patch',
                 'ro.build.version.incremental','ro.boot.verifiedbootstate','ro.boot.flash.locked',
                 'ro.boot.vbmeta.device_state','ro.boot.secureboot','ro.secure','ro.debuggable',
                 'ro.adb.secure','ro.build.type']:
        result[prop] = ('What is the declared build/security state for '+prop+'?', ['shell','getprop',prop])
    for path in ['kernel/randomize_va_space','kernel/kptr_restrict','kernel/dmesg_restrict',
                 'kernel/unprivileged_bpf_disabled','kernel/perf_event_paranoid',
                 'kernel/yama/ptrace_scope','kernel/unprivileged_userns_clone',
                 'user/max_user_namespaces','vm/mmap_rnd_bits','vm/mmap_rnd_compat_bits',
                 'kernel/modules_disabled','kernel/io_uring_disabled']:
        result[path.replace('/','-')] = ('Is '+path+' readable and what is its policy value?',
                                       ['shell','cat','/proc/sys/'+path])
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--scope',choices=['baseline','followup'],default='baseline',
                    help='Followup only asks the unresolved vendor/page-migration questions')
    args = ap.parse_args()
    os.umask(0o077)
    # Refuse ambiguous/missing device selection without printing identifiers.
    try:
        state = subprocess.run(['adb','get-state'],capture_output=True,timeout=20)
    except (OSError,subprocess.TimeoutExpired):
        raise SystemExit('ADB unavailable; continue offline') from None
    if state.returncode or state.stdout.strip() != b'device':
        raise SystemExit('No unique authorized device; continue offline')
    work = Path('work')
    if not work.is_dir() or work.is_symlink():
        raise SystemExit('Run from repository root with a real ignored work/ directory')
    ignored = subprocess.run(['git','check-ignore','-q','work/kernel-audit-check'],capture_output=True)
    if ignored.returncode:
        raise SystemExit('Private output must be ignored by Git')
    output = Path(tempfile.mkdtemp(prefix='kernel-audit-',dir=work))
    (output/'connection.bin').write_bytes(state.stdout)
    (output/'connection.err').write_bytes(state.stderr)
    metadata = {'connection':dict(command=['adb','get-state'],exit=state.returncode,bytes=len(state.stdout))}
    for name,(question,command) in queries(args.scope).items():
        print(question,flush=True)
        try:
            r = subprocess.run(['adb',*command],capture_output=True,timeout=25)
        except (OSError,subprocess.TimeoutExpired):
            metadata[name] = {'timeout':True}
            break
        (output/(name+'.bin')).write_bytes(r.stdout)
        (output/(name+'.err')).write_bytes(r.stderr)
        metadata[name] = dict(command=['adb',*command],exit=r.returncode,bytes=len(r.stdout))
        if b'no devices/emulators' in r.stderr:
            break
    (output/'commands.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print('Private capture directory:',output)
    print('Review with the offline inspector; do not publish raw files.')


if __name__ == '__main__':
    main()
