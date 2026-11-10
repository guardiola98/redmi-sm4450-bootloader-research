#!/usr/bin/env python3
"""Offline input-integrity and privacy tests using synthetic ELF/source data."""
import json
from pathlib import Path
import runpy
import struct
import tempfile
import unittest

A=runpy.run_path(str(Path(__file__).with_name('inspect-kernel-directed.py')))
C=runpy.run_path(str(Path(__file__).with_name('collect-kernel-readonly.py')))


def module():
    names=b'\0.shstrtab\0.modinfo\0.symtab\0.strtab\0.text\0'
    fields=b'name=example\0vermagic=5.10 example\0scmversion=g123abc\0serial=PRIVATE_SENTINEL\0'
    symbols=bytes(24)+struct.pack('<IBBHQQ',1,2,0,5,0,4)
    blocks=[b'',names,fields,symbols,b'\0selected\0',b'CODE']
    data=bytearray(64);table=[]
    for i,block in enumerate(blocks):
        name=0 if i==0 else names.index([b'',b'.shstrtab',b'.modinfo',b'.symtab',b'.strtab',b'.text'][i])
        table.append((name,2 if i==3 else (0 if i==0 else 1),0,0,len(data),len(block),
                      4 if i==3 else 0,0,1,24 if i==3 else 0))
        data.extend(block)
    table_offset=len(data)
    for s in table:data.extend(struct.pack('<IIQQQQIIQQ',*s))
    data[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHIQQQIHHHHHH',data,16,1,183,1,0,0,table_offset,0,64,0,0,64,6,1)
    return data,table_offset


class Inputs(unittest.TestCase):
    def test_module_output_omits_unselected_metadata_and_addresses(self):
        result=A['module_summary'](module()[0],['selected'])
        self.assertEqual(result['functions']['selected']['bytes'],4)
        text=json.dumps(result)
        for word in ('PRIVATE_SENTINEL','serial','offset','address','CODE'):
            self.assertNotIn(word,text)

    def test_truncated_and_wrong_machine_rejected(self):
        data,_=module()
        for length in (0,16,63,len(data)-1):
            with self.assertRaises(ValueError):A['elf_sections'](data[:length])
        struct.pack_into('<H',data,18,62)
        with self.assertRaises(ValueError):A['elf_sections'](data)

    def test_section_and_symbol_bounds_rejected(self):
        data,offset=module();struct.pack_into('<Q',data,offset+5*64+32,len(data)+1)
        with self.assertRaises(ValueError):A['module_summary'](data,['selected'])
        data,offset=module();struct.pack_into('<I',data,offset+3*64+40,99)
        with self.assertRaises(ValueError):A['module_summary'](data,['selected'])

    def test_missing_selected_symbol_is_not_negative_vulnerability_evidence(self):
        with self.assertRaises(ValueError):A['module_summary'](module()[0],['missing'])

    def test_source_extractor_ignores_comment_and_declaration(self):
        text='/* example() is mentioned before another function. */\nint example(int);\nint example(int x)\n{\n return x;\n}\n'
        body,line=A['function'](text,'example')
        self.assertEqual(line,3)
        self.assertEqual(body,'example(int x)\n{\n return x;\n}')

    def test_duplicate_definition_rejected(self):
        with self.assertRaises(ValueError):
            A['function']('int f(void) {\n}\nint f(void) {\n}\n','f')

    def test_pin_size_and_path_checks_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'source').write_bytes(b'reviewed')
            entry=dict(path='source',sha256=A['sha'](b'reviewed'))
            self.assertEqual(A['read_pinned'](root,entry),b'reviewed')
            for bad,limit in [(dict(entry,sha256='0'*64),100),(entry,2),
                              (dict(entry,path='../source'),100)]:
                with self.assertRaises(ValueError):A['read_pinned'](root,bad,limit)

    def test_followup_filters_module_address_on_device_and_matches_actual_name(self):
        _,args=C['queries']('followup')['vendor-module-names']
        self.assertIn('frpc_adsprpc',args[1])
        self.assertTrue(args[1].endswith("| cut -d ' ' -f 1-5"))


if __name__=='__main__':unittest.main()
