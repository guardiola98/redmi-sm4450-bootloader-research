"""Offline GUID census of direct PE sections in uefi.elf GZIP volumes."""
import importlib.util, hashlib, json, struct, sys, uuid
from pathlib import Path
spec=importlib.util.spec_from_file_location('loc',Path(__file__).with_name('locate-uefi-protocol-modules.py'))
loc=importlib.util.module_from_spec(spec);spec.loader.exec_module(loc)
targets={'first-service':'b0760469-970c-487a-a4b5-28db7b45cef1','scm':'77ed108d-8524-4b8b-9d2e-34987aecb9c1','mitoken':'0c00a314-11a1-4d7a-a5c8-70bd5f88e7df'}
p=Path('work/uefi-provider-source.elf')
if p.exists():
 data=p.read_bytes()
 if hashlib.sha256(data).hexdigest()!=loc.EXPECTED_SHA256: raise ValueError('hash')
else:
 data=loc.read_uefi(Path(sys.argv[1]));p.write_bytes(data)
out=Path('work/provider-census');out.mkdir(exist_ok=True)
rows=[];count=0
start,stop,_=loc.parse_fv(data,0x1000,len(data))
for at,end,begin,guid,ft in loc.ffs_files(data,start,stop):
 if not any(t==2 and data[a+h:a+h+16]==loc.GZIP_GUID.bytes_le for a,b,t,h in loc.sections(data,begin,end)):continue
 loc.TARGET_FFS_GUID=guid
 dec=loc.decoded_first_fv(data)
 for a,b,t,h in loc.sections(dec,0,len(dec)):
  if t!=0x17:continue
  fs,fe,_=loc.parse_fv(dec,a+h,b)
  for fa,fb,body,fg,ft in loc.ffs_files(dec,fs,fe):
   secs=list(loc.sections(dec,body,fb))
   names=[dec[x+hh:y].decode('utf-16le').rstrip('\0') for x,y,tt,hh in secs if tt==0x15]
   for x,y,tt,hh in secs:
    if tt!=0x10:continue
    count+=1;pe=dec[x+hh:y];hits={}
    for key,value in targets.items():
     needle=uuid.UUID(value).bytes_le
     offsets=[i for i in range(len(pe)-15) if pe[i:i+16]==needle]
     if offsets:hits[key]=[hex(i) for i in offsets]
    if hits:
     name=names[0] if names else str(fg)
     if not all(c.isalnum() or c in '-_' for c in name):raise ValueError('name')
     (out/(name+'.pe')).write_bytes(pe)
     rows.append(dict(name=name,ffs=str(fg),outer=str(guid),sha256=hashlib.sha256(pe).hexdigest(),hits=hits))
report=dict(direct_pe_count=count,matches=rows,scope='Direct PE32 sections in both GZIP FV-image containers; not recursive compressed sections')
Path('docs/mitoken-provider-census.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
