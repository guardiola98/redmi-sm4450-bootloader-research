# Ferramentes existents per analitzar l'ABL / UEFI

**Data:** 2026-11-09. **Objectiu:** anàlisi offline del firmware `OS2.0.218.0.VMWEUXM` sense escriure al mòbil.

## Descobriment clau

`work/abl.elf` té una capçalera ELF32 ARM **contenidor**, però els bytes observats indiquen un volum UEFI: a offset `0x1028` apareix `_FVH`, i a `0x1010` el GUID de sistema de fitxers de firmware UEFI `8c8ce578-8a3d-4f1c-9935-896185c32dd3` (interpretant endianness GUID). La capçalera del volum sembla començar a `0x1000`, amb longitud declarada de `0x30000`; verificar amb un parser abans de donar-ho per definitiu.

**Correcció important:** no interpretar l'ELF32 ARM extern com si continguera directament el codi ARM de Fastboot. Dins de la imatge UEFI pot haver-hi una EFI PE32/PE32+ (habitualment `LinuxLoader.efi`) comprimida. Només analitzar el programa **després d'extraure'l**, amb l'arquitectura identificada del PE real.

## Eines trobades

| Prioritat | Projecte | Aplicació | Precaució |
| --- | --- | --- | --- |
| **1** | [theopolis/uefi-firmware-parser](https://github.com/theopolis/uefi-firmware-parser) | Identificar i descomprimir volums/FFS UEFI; compatible amb firmware Qualcomm | Fer-ho localment sobre còpia |
| **1** | [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) | Veure estructura de volums, seccions i exportar EFI amb UEFIExtract | No utilitzar funcions de modificar/reconstruir |
| **2** | [chkndrp/qualcomm-gbl-exploit-checker](https://github.com/chkndrp/qualcomm-gbl-exploit-checker) | Comprova patrons molt concrets de dos errors Qualcomm GBL en ABL | **No és prova general** que es puga desbloquejar el SM4450; resultats heurístics i potencials falsos negatius/positius |
| **2** | [linux-msm/xbltools](https://github.com/linux-msm/xbltools) | Desempaquetar determinats formats XBL per separat | Compatibilitat amb `xbl_s.melf` concret **no verificada** |
| 3 | [qualcomm/abl2esp](https://github.com/qualcomm/abl2esp) | Referència oficial sobre empaquetament ABL: EFI dins FV dins LZMA dins FV dins ELF | No intentar recompilar/flashejar un ABL no firmat en telèfon bloquejat |
| 3 | Ghidra | Enginyeria inversa del **PE EFI interior**, no de la capçalera ELF externa | Identificar arquitectura i base abans d'interpretar |

Una presentació tècnica de Qualcomm descriu explícitament l'extracció de l'EFI des d'ABL amb `uefi-firmware-parser`: https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf

## Prova immediata — lectura, sense flash

A Debian instal·lar UEFIExtract des de paquets, si està disponible:

```bash
sudo apt update
sudo apt install uefitool-cli
```

Per verificar la posició de la capçalera i crear una còpia del volum FV local:

```bash
cd ~/redmi-sm4450-bootloader-research
python3 - <<'PY'
from pathlib import Path
import struct
p = Path('work/abl.elf')
b = p.read_bytes()
offset = 0x1000
assert b[offset+0x28:offset+0x2c] == b'_FVH', 'No FVH marker at expected offset'
length = struct.unpack_from('<Q', b, offset+0x20)[0]
assert 0x40 <= length <= len(b)-offset, 'Inconsistent FV length'
out = Path('work/abl-fv.bin')
if out.exists():
    raise SystemExit('Output exists; refusing overwrite')
out.write_bytes(b[offset:offset+length])
print('FV offset:', hex(offset), 'length:', hex(length), 'local file:', out)
PY
```

L'opció `report` de `UEFIExtract`/ `uefiextract` genera informes i pot crear directoris locals. Utilitzar sobre `work/abl-fv.bin`, **no** executar ni carregar l'EFI en el telèfon. Si el parser retorna un error d'extracció, conservar el missatge complet i provar el parser Python, sense modificar el volum.

## Preguntes pendents

- El parser pot trobar un volum UEFI intern i la secció comprimida (LZMA o altra)?
- Quina arquitectura té la imatge `LinuxLoader.efi` real?
- Hi ha un conjunt d'opcions `fastboot` i verificacions de signatura identificables?
- El checker GBL és aplicable al SM4450 i al build exacte, o és només un fals indici?
- El firmware `abl.elf` del paquet coincidix amb la partició `abl_b` activa? **No verificat.**

**Seguretat:** no pujar PE/ELF propietaris, no flashejar ABL/XBL, no executar un exploit de tercers sense auditoria del codi i recuperació documentada.
