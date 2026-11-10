#!/usr/bin/env python3
"""Recheck pinned public source contracts and selected local vendor ELF metadata.

Offline only. Emits hashes, source lines and selected module build metadata;
never emits module addresses, binary contents, logs or device identifiers.
Text assertions anchor a manual code review, not a C verifier or CVE scanner.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_pinned(root, entry, limit=4*1024*1024):
    path=Path(entry['path'])
    if path.is_absolute() or '..' in path.parts:
        raise ValueError('Input must be relative to the private input root')
    with (root/path).open('rb') as f:
        data=f.read(limit+1)
    if len(data)>limit or sha(data)!=entry['sha256']:
        raise ValueError('Input does not match reviewed hash: '+path.name)
    return data


def function(text, name):
    # Selected Linux functions use a column-zero closing brace. Not general C.
    masked=re.sub(r'/\*.*?\*/|//[^\n]*',
                  lambda m:re.sub(r'[^\n]',' ',m.group()),text,flags=re.S)
    starts=list(re.finditer(r'\b'+re.escape(name)+r'\s*\([^;{}()]*\)\s*\{',masked))
    if len(starts)!=1:
        raise ValueError('Expected one definition: '+name)
    start=starts[0].start()
    end=text.find('\n}',starts[0].end())
    if end<0:
        raise ValueError('Missing function end')
    return text[start:end+2],text.count('\n',0,start)+1


def compact(text):
    text=re.sub(r'/\*.*?\*/','',text,flags=re.S)
    text=re.sub(r'//[^\n]*','',text)
    return re.sub(r'\s+','',text)


def contract_checks(src):
    def body(key,name):return compact(function(src[key],name)[0])
    old=body('redmi-rt','remove_waiter');new=body('fixed-rt','remove_waiter')
    before=body('redmi-rt','rt_mutex_start_proxy_lock')
    after=body('fixed-rt','rt_mutex_start_proxy_lock')
    block=body('redmi-rt','task_blocks_on_rt_mutex')
    timer=src['redmi-cpu-timers'];fixed=src['fixed-cpu-timers']
    checks={
      'rt_old_current_lock_clear_chain':all(t in old for t in (
          'raw_spin_lock(&current->pi_lock)','current->pi_blocked_on=NULL',
          'next_lock,NULL,current')),
      'rt_fixed_waiter_lock_clear_chain':all(t in new for t in (
          'waiter_task=waiter->task','raw_spin_lock(&waiter_task->pi_lock)',
          'waiter_task->pi_blocked_on=NULL','next_lock,NULL,waiter_task')),
      'rt_fixed_unarmed_guard':'if(!waiter_task)return;' in new,
      'rt_wrapper_nonzero_to_negative':('if(unlikely(ret))remove_waiter' in before and
                                       'if(unlikely(ret<0))remove_waiter' in after),
      'rt_early_deadlock_precedes_waiter_task':
          block.index('return-EDEADLK;') < block.index('waiter->task=task;'),
      'futex_proxy_targets_queued_task':
          'rt_mutex_start_proxy_lock(&pi_state->pi_mutex,this->rt_waiter,this->task)' in
          body('redmi-futex','futex_requeue'),
      'futex_waiter_is_stack_object':
          'structrt_mutex_waiterrt_waiter;' in body('redmi-futex','futex_wait_requeue_pi'),
      'futex_compile_gate_open':
          '#ifdefCONFIG_HAVE_FUTEX_CMPXCHG#definefutex_cmpxchg_enabled1' in compact(src['redmi-futex']),
      'timer_old_helper_absent':'timer_lock_sighand' not in timer,
      'timer_old_null_sighand_warns':
          'WARN_ON_ONCE(ctmr->head||timerqueue_node_queued(&ctmr->node))' in
          body('redmi-cpu-timers','posix_cpu_timer_del'),
      'timer_fixed_helper_retries_lookup':all(t in body('fixed-cpu-timers','timer_lock_sighand')
          for t in ('for(;;)','pid_task(timer->it.cpu.pid,type)',
                    'if(lock_task_sighand(t,flags))returnt;','smp_rmb();')),
      'timer_fixed_three_consumers':all('timer_lock_sighand(timer,&flags)' in
          body('fixed-cpu-timers',name) for name in
          ('posix_cpu_timer_del','posix_cpu_timer_set','posix_cpu_timer_rearm')),
      'exit_old_plain_new_release':
          'tsk->sighand=NULL;' in body('redmi-exit','__exit_signal') and
          'smp_store_release(&tsk->sighand,NULL)' in body('fixed-exit','__exit_signal'),
      'sighand_acquire_added':
          'smp_acquire__after_ctrl_dep' not in body('redmi-signal','__lock_task_sighand') and
          'smp_acquire__after_ctrl_dep' in body('fixed-signal','__lock_task_sighand'),
      'timer_release_waits_for_rcu':
          'call_rcu(&tmr->rcu,k_itimer_rcu_free)' in body('redmi-posix-timers','release_posix_timer'),
      'timer_owner_signal_checked':'timr->it_signal==current->signal' in
          body('redmi-posix-timers','__lock_timer'),
      'exec_changes_leader_and_releases_old':all(t in body('redmi-exec','de_thread') for t in
          ('tsk->group_leader=tsk;','leader->group_leader=tsk;','release_task(leader)')),
    }
    if not all(checks.values()):
        raise ValueError('Reviewed contracts changed: '+', '.join(k for k,v in checks.items() if not v))
    return checks


def elf_sections(data):
    if len(data)<64 or data[:7]!=b'\x7fELF\x02\x01\x01':
        raise ValueError('Expected ELF64 little endian')
    h=struct.unpack_from('<HHIQQQIHHHHHH',data,16)
    if h[0:2]!=(1,183) or h[7]!=64 or h[10]!=64 or not 0<h[11]<=4096 or h[12]>=h[11]:
        raise ValueError('Expected bounded AArch64 relocatable ELF')
    offset,count=h[5],h[11]
    if offset<64 or offset+count*64>len(data):raise ValueError('Section table out of bounds')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,offset+i*64) for i in range(count)]
    for s in sections:
        if s[1]!=8 and s[4]+s[5]>len(data):raise ValueError('Section out of bounds')
    def payload(s):
        if s[1]==8:raise ValueError('Section is not file backed')
        return data[s[4]:s[4]+s[5]]
    names=payload(sections[h[12]])
    def cstring(table,start):
        end=table.find(b'\0',start)
        if start<0 or end<start:raise ValueError('Invalid string table offset')
        return table[start:end].decode('ascii')
    named={}
    for s in sections:
        name=cstring(names,s[0])
        if name in named:raise ValueError('Duplicate section name')
        named[name]=s
    return sections,named,payload,cstring


def module_summary(data, names):
    sections,named,payload,cstring=elf_sections(data)
    fields={}
    for record in payload(named['.modinfo']).split(b'\0'):
        key,sep,value=record.partition(b'=')
        if key not in (b'name',b'vermagic',b'scmversion'):continue
        key=key.decode();value=value.decode('ascii').strip()
        if not sep or key in fields or not re.fullmatch(r'[A-Za-z0-9_.+ -]{1,150}',value):
            raise ValueError('Unexpected module metadata')
        fields[key]=value
    if set(fields)!={'name','vermagic','scmversion'}:raise ValueError('Missing module provenance')
    sym=named['.symtab']
    if sym[9]!=24 or sym[5]%24 or sym[6]>=len(sections):raise ValueError('Invalid symbol table')
    strings=payload(sections[sym[6]])
    functions={}
    for entry in struct.iter_unpack('<IBBHQQ',payload(sym)):
        name,info,_,index,start,size=entry
        label=cstring(strings,name)
        if label not in names:continue
        if info&15!=2 or index>=len(sections) or label in functions or size==0:
            raise ValueError('Ambiguous selected function')
        code=payload(sections[index])
        if start+size>len(code):raise ValueError('Function outside section')
        functions[label]={'bytes':size,'sha256':sha(code[start:start+size])}
    if set(functions)!=set(names):raise ValueError('Selected function missing')
    return dict(metadata=fields,functions=functions)


def inspect(root,manifest):
    texts={};spans={}
    for key,entry in manifest['sources'].items():
        text=read_pinned(root,entry).decode('utf-8');texts[key]=text
        spans[key]={}
        for name in entry.get('functions',[]):
            body,line=function(text,name)
            spans[key][name]={'line':line,'sha256':sha(body.encode())}
    checks=contract_checks(texts)
    config=read_pinned(root,manifest['config']).decode('ascii')
    gate='CONFIG_HAVE_FUTEX_CMPXCHG=y' in config.splitlines()
    if not gate:raise ValueError('Futex compile-time gate not established')
    modules={}
    for name,entry in manifest['modules'].items():
        result=module_summary(read_pinned(root,entry),entry['functions'])
        if result!=entry['reviewed_summary']:raise ValueError('Module summary changed')
        modules[name]=result
    return dict(contract_checks=checks,have_futex_cmpxchg=True,
                source_functions=spans,modules=modules)


def check_backports(root,manifest):
    """Apply official text patches to disposable source copies, never a kernel."""
    sources=manifest['sources']
    files={
        'rt':('kernel/locking/rtmutex.c',['remove_waiter','rt_mutex_start_proxy_lock']),
        'cpu-timers':('kernel/time/posix-cpu-timers.c',['timer_lock_sighand',
            'posix_cpu_timer_del','posix_cpu_timer_set','posix_cpu_timer_rearm']),
        'signal':('kernel/signal.c',['__lock_task_sighand']),
        'exit':('kernel/exit.c',['__exit_signal']),
    }
    matches={}
    with tempfile.TemporaryDirectory(prefix='kernel-backport-') as temp:
        directory=Path(temp)
        for key,(path,_) in files.items():
            target=directory/path;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(read_pinned(root,sources['redmi-'+key]))
        for key in ('rt-stable-fix','rt-stable-followup','timer-stable-fix'):
            patch=read_pinned(root,sources[key])
            result=subprocess.run(['patch','--batch','--forward','--fuzz=0','-p1'],
                input=patch,cwd=directory,capture_output=True,timeout=30)
            if result.returncode:raise ValueError('Backport failed: '+key)
        for key,(path,names) in files.items():
            patched=(directory/path).read_text()
            fixed=read_pinned(root,sources['fixed-'+key]).decode('utf-8')
            for name in names:
                matches[name]=compact(function(patched,name)[0])==compact(function(fixed,name)[0])
    if not all(matches.values()):raise ValueError('Patched functions differ from stable reference')
    rcu=compact(read_pinned(root,sources['redmi-rcupdate']).decode('utf-8'))
    cleanup=compact(read_pinned(root,sources['redmi-cleanup']).decode('utf-8'))
    dependencies=('#include<linux/cleanup.h>' in rcu and
        'DEFINE_LOCK_GUARD_0(rcu,rcu_read_lock(),rcu_read_unlock())' in rcu and
        '#defineguard(_name)' in cleanup)
    if not dependencies:raise ValueError('RCU guard dependency not established')
    return dict(official_patches_applied=3,fuzz_allowed=False,
                normalized_function_matches=matches,rcu_guard_headers_present=True,
                compiled=False,executed_kernel=False)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inputs',type=Path,default=Path('work'))
    ap.add_argument('--manifest',type=Path,default=Path('docs/kernel-directed-inputs.json'))
    ap.add_argument('--check-backports',action='store_true',
                    help='Apply pinned patches only to disposable source copies; requires host patch tool')
    args=ap.parse_args()
    manifest=json.loads(args.manifest.read_text())
    result=inspect(args.inputs,manifest)
    if args.check_backports:result['backport_application']=check_backports(args.inputs,manifest)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=='__main__':main()
