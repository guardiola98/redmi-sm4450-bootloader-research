#!/usr/bin/env python3
"""Host-only privacy/bounds regression; no Android, firmware or kernel stimulus."""
import gzip
import json
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('inspect-android-kernel.py')))
COLLECT = runpy.run_path(str(Path(__file__).with_name('collect-kernel-readonly.py')))


def boot():
    data = bytearray(8192)
    data[:8] = b'ANDROID!'
    struct.pack_into('<IIII',data,8,64,0,0,1584)
    struct.pack_into('<I',data,40,4)
    data[4096+56:4096+60] = b'ARM\x64'
    return data


class Audit(unittest.TestCase):
    def test_explicit_disabled_is_different_from_absent(self):
        c=API['selected_config'](b'# CONFIG_USER_NS is not set\nCONFIG_ARM64_PAN=y\n')
        self.assertEqual(c['CONFIG_USER_NS'],'n')
        self.assertEqual(c['CONFIG_ARM64_PAN'],'y')
        self.assertEqual(c['CONFIG_ARM64_MTE'],'unknown')

    def test_unknown_config_cannot_leak_strings(self):
        c=API['selected_config'](b'CONFIG_LOCALVERSION="SENSITIVE_SENTINEL"\n')
        self.assertNotIn('SENSITIVE_SENTINEL',json.dumps(c))

    def test_duplicate_and_invalid_selected_config_rejected(self):
        for data in [b'CONFIG_USER_NS=y\n# CONFIG_USER_NS is not set',b'CONFIG_USER_NS="private"']:
            with self.assertRaises(ValueError):API['selected_config'](data)

    def test_gzip_rejects_truncation_concatenation_and_bomb(self):
        g=gzip.compress(b'x'*100)
        for data,limit in [(g[:-1],200),(g+g,200),(g,50),(b'not gzip',200)]:
            with self.assertRaises(ValueError):API['gunzip'](data,limit)
        self.assertEqual(API['gunzip'](g,100),b'x'*100)

    def test_boot_layout(self):
        self.assertEqual(len(API['boot_kernel'](boot())),64)

    def test_boot_overflow_and_truncated_ramdisk(self):
        for offset,value in [(8,9000),(12,9000),(40,3),(20,4097)]:
            b=boot();struct.pack_into('<I',b,offset,value)
            with self.assertRaises(ValueError):API['boot_kernel'](b)
        with self.assertRaises(ValueError):API['boot_kernel'](boot()[:100])

    def test_ambiguous_config_markers_rejected(self):
        valid=b'IKCFG_ST'+gzip.compress(b'CONFIG_USER_NS=y\n')+b'IKCFG_ED'
        self.assertEqual(API['image_config'](valid),b'CONFIG_USER_NS=y\n')
        for data in [b'',valid+valid,valid[:-8]]:
            with self.assertRaises(ValueError):API['image_config'](data)

    def test_denied_stdout_with_zero_exit_is_not_data(self):
        result=API['scalar_status'](b'cat: SENSITIVE_SENTINEL: Permission denied',b'',0,r'.*')
        self.assertEqual(result,{'status':'denied'})
        self.assertNotIn('SENSITIVE_SENTINEL',json.dumps(result))

    def test_missing_and_unavailable_not_disabled(self):
        for message,status in [(b'No such file','missing'),(b'no devices/emulators','unavailable')]:
            self.assertEqual(API['scalar_status'](b'',message,1,r'[01]'),{'status':status})

    def test_invalid_values_are_never_echoed(self):
        self.assertEqual(API['scalar_status'](b'SENSITIVE_SENTINEL',b'',0,r'[01]'),{'status':'invalid'})
        self.assertEqual(API['scalar_status'](b'0',b'warning private',0,r'[01]'),{'status':'error'})
        self.assertEqual(API['scalar_status'](b'0',b'',0,r'[01]'),{'status':'observed','value':'0'})

    def test_probe_publishes_only_counts_not_addresses_or_extra_fields(self):
        r=dict(uid=2000,euid=2000,page_size=4096,seccomp=0,paca=0,pacg=0,bti=0,mte=0,
               image='deadbeef',stack='cafe1234',mapping='abc12345',serial='SENSITIVE_SENTINEL')
        result=API['probe_summary']([r,dict(r,image='deadbe00')])
        self.assertEqual(result['distinct_addresses'],dict(image=2,stack=1,mapping=1))
        for value in ['deadbeef','cafe1234','abc12345','SENSITIVE_SENTINEL']:
            self.assertNotIn(value,json.dumps(result))
        with self.assertRaises(ValueError):API['probe_summary']([dict(r,mte=2)])

    def test_unpinned_firmware_rejected(self):
        with self.assertRaises(ValueError):API['inspect'](boot(),b'',b'',b'')

    def test_collector_is_fixed_readonly_and_properties_individual(self):
        q=COLLECT['queries']()
        self.assertEqual(len(q),31)
        for question,args in (q | COLLECT['queries']('followup')).values():
            self.assertTrue(question.endswith('?'))
            self.assertIn(args[0],['shell','exec-out'])
            self.assertIn(args[1].split()[0],['uname','cat','grep','getenforce','ls','getprop'])
            if args[1]=='getprop':self.assertEqual(len(args),3)
            self.assertFalse(set(' '.join(args).split()) & {'setprop','reboot','fastboot','su','ioctl','logcat'})


if __name__=='__main__':unittest.main()
