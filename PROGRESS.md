# PROGRESS.md — Investigació del bootloader Redmi 12 5G (SM4450)

**Última actualització:** 2026-11-09  
**Estat:** investigació / anàlisi estàtica, **sense mètode de desbloqueig verificat**  
**Repositori:** [guardiola98/redmi-sm4450-bootloader-research](https://github.com/guardiola98/redmi-sm4450-bootloader-research)

> **Regla de manteniment:** actualitzar este fitxer en cada canvi rellevant del projecte: què s'ha fet, resultats verificats, limitacions, riscos i el següent pas. Les modificacions a GitHub es faran durant les sessions de treball; el document no s'actualitza automàticament quan es canvia un fitxer fora d'estes sessions. No pujar dades personals, tokens, logcat complet ni firmware propietari.

## Objectiu

Investigar de manera reproduïble el bloqueig del bootloader del Redmi 12 5G amb Qualcomm SM4450, sense dependre del procediment oficial de Xiaomi. L'objectiu final seria identificar una vulnerabilitat real i, si escau, documentar-la per a la comunitat amb precaucions i divulgació responsable. **No s'ha demostrat cap exploit, root ni desbloqueig.**

## Equip investigat — dades verificades per ADB

| Camp | Valor |
| --- | --- |
| Model | `23076RN8DY` |
| Identificador ADB | `river` |
| Família firmware | `sky` |
| Sistema | Android 15, HyperOS `OS2.0.218.0.VMWEUXM` EEA |
| SoC / plataforma | Qualcomm `SM4450` / `parrot` |
| Kernel | `5.10.246-android12-9-00012-g730d06ec05ff-ab15159037` |
| Compilació kernel | 2026-04-07 |
| Pegat Android / vendor | `2026-10-01` / `2026-04-05` |
| SELinux | `Enforcing` |
| Verified Boot / bloqueig | `green` / `locked` |
| Slot actiu | `_b` |
| Opcions kernel detectades | `CONFIG_BPF=y`, `CONFIG_KALLSYMS=y`, `CONFIG_KPROBES=y`, `CONFIG_SECURITY_SELINUX=y` |

La diferència entre pegats Android i vendor **no demostra una vulnerabilitat**; els fabricants poden incorporar correccions sense canviar números de versió.

## Progrés confirmat

- [x] Creat repositori públic i documentació inicial: `README.md`, `docs/baseline.md`, `docs/references.md`.
- [x] Creat i executat satisfactòriament `scripts/collect-device-info.sh` (només lectura).
- [x] Documentat problema de `Xiaomi-HyperOS-BootLoader-Bypass`: `args` capturat de 1292 caràcters amb dos segments Base64 (344 i 940 caràcters); tots dos desxifrats AES-128-CBC amb la rutina original fallen. Vegeu [incidència #155](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass/issues/155). **No implica bypass aconseguit.**
- [x] Identificat el Fastboot EEA corresponent a `OS2.0.218.0.VMWEUXM`.
- [x] Verificat localment l'arxiu `sky_eea_global_images_OS2.0.218.0.VMWEUXM_20261021.0000.00_15.0_eea_330e013f7f.tgz`:
  - MD5: `330e013f7fc6acc15e7f17e8edb4d6a8` (coincidix amb l'índex de firmware).
  - SHA-256: `d2d44b39440d4915a10b3198d0075a32253c6058405ba67be1fc5667a067eac9`.
  - La coincidència del MD5 amb un índex **no és per si sola una prova criptogràfica d'autenticitat d'origen**.
- [x] Creat i executat `scripts/inventory-fastboot.py`: arxiu amb 114 fitxers; identificats ABL, XBL, TrustZone i imatges AVB.
- [x] Creat i executat `scripts/analyze-bootchain.py`: hashes de components i relació amb `rawprogram*.xml`.
- [x] Creat i executat `scripts/check-slot-coverage.py`: manifests de particions A/B; el paquet assigna fitxers a particions `*_a` i deixa el camp `filename` buit en moltes entrades `*_b`. Això **no prova** que les particions B estiguen buides ni quin binari està executant el dispositiu.
- [x] Confirmada per ADB l'existència de `abl_a`, `abl_b`, `xbl_a`, `xbl_b`, `xbl_config_a`, `xbl_config_b`, amb slot `_b` actiu.
- [x] Publicat `scripts/extract-abl.py` per extraure de manera local l'ABL del paquet, comprovant SHA-256; el fitxer `work/abl.elf` existeix al Debian de l'investigador i s'ha inspeccionat amb `file` i `readelf`. No s'ha tornat a comunicar el missatge exacte de l'extractor. 
- [x] Inspecció ELF inicial de `work/abl.elf`: **ELF32 little-endian ARM, EXEC, enllaçat estàticament, sense taula de seccions**, punt d'entrada `0x9fa00000`, tres program headers (`NULL`, `LOAD`, `NULL`), un segment `LOAD` RWE a offset `0x1000`, adreça `0x9fa00000`, grandària fitxer/memòria `0x30000`. Una capçalera `NULL` addicional apareix a offset `0x31000` amb `0x0f38` bytes de mida declarada; **no està confirmat** què conté eixa regió. L'ELF no presenta taula de seccions ni símbols segons la capçalera; això no prova ofuscació, xifrat o vulnerabilitat.
- [x] Primera cerca `strings -a -n 6` filtrada per `unlock|lockstate|verifiedboot|fastboot|device state|avb|oem`: **cap coincidència**. És només una cerca de text ASCII; no descarta rutines de desbloqueig o verificació al binari.

### Hashes útils del paquet Fastboot

| Component | SHA-256 |
| --- | --- |
| `abl.elf` | `f1c1f9ffbfa596cc352bf13aaa8e751eaee5168ab0344c641a70f0aa5f1607eb` |
| `xbl_s.melf` | `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1` |
| `xbl_config.elf` | `97e8e3a4b0422e064f3df3282d6b1569364b603d4b9497f6827cace14ceaf9cc` |
| `tz.mbn` | `f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76` |
| `vbmeta.img` | `4b303d89ac0d8961fe57949148f86cfcf4fcee14799acaef5093455c52763db8` |

- [x] Investigades ferramentes de GitHub per inspeccionar Qualcomm ABL: `theopolis/uefi-firmware-parser`, `LongSoft/UEFITool`, `linux-msm/xbltools`, `qualcomm/abl2esp` i `chkndrp/qualcomm-gbl-exploit-checker`. Documentació i cauteles a [docs/uefi-tools.md](docs/uefi-tools.md).
- [x] Detectada **signatura `_FVH` a l'offset 0x1028** dins d'`abl.elf`, amb probable volum UEFI a `0x1000`. La capçalera ELF32 ARM **és un contenidor**; la implementació real d'ABL/Fastboot probablement és una EFI PE/COFF comprimida dins del firmware volume, pendent d'extracció i confirmació. Això explica la manca de cadenes ASCII directes sense demostrar cap vulnerabilitat.

- [x] Confirmat al Debian que l'extracció de FV des de `work/abl.elf` funciona: offset `0x1000`, longitud `0x30000` (196.608 bytes), destí local `work/abl-fv.bin`. Encara no s'ha analitzat la jerarquia FFS ni extret `LinuxLoader.efi`.
- [x] Endurit `.gitignore`: `work/`, `*.efi`, `*.fd`, `*.rom` per evitar publicar per error binaris extrets.

## Següent pas immediat

**Analitzar el volum UEFI extret amb ferramentes existents**, en lloc de crear un parser nou abans de provar-ne un de fiable. Primer usar `uefi-firmware-parser` en un entorn virtual de Debian, sense privilegis de root i només amb el fitxer `work/abl-fv.bin`.

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 -m venv .venv
. .venv/bin/activate
python -m pip install uefi_firmware
python - <<'PY'
from uefi_firmware import AutoParser
from pathlib import Path
data = Path("work/abl-fv.bin").read_bytes()
parser = AutoParser(data)
print("Parser:", type(parser).__name__)
parsed = parser.parse()
print("Parse success:", bool(parsed))
if parsed:
    print("Firmware volume object:", type(parsed).__name__)
    print("Object summary:", repr(parsed)[:1200])
PY
```

Si l'API de la versió instal·lada diferix, documentar l'error i ajustar el programa a l'API real, **sense assumir que `parse()` retorna dades o extraure contingut no revisat**. Després, si s'identifiquen mòduls PE32/PE32+, fer una extracció limitada a `work/`, identificar arquitectura i preparar anàlisi Ghidra. Avaluar eines de tercers abans d'integrar-les, comprovant llicència, manteniment i confiança; preferir dependència instal·lable o adaptador propi a copiar-ne codi.

## Pendent després d'eixe pas

1. Fer inventari de versions Fastboot anteriors del model `sky`, anotant origen i hashes, i comparar ABL/XBL.
2. Comprovar aplicabilitat de vulnerabilitats de Qualcomm/kernel a **versions i components exactes**, no només al número de kernel.
3. Estudiar separadament les restriccions AVB, ABL, XBL i autorització de desbloqueig.
4. Preparar un procediment de recuperació verificat **abans** de qualsevol prova destructiva.
5. Si hi ha troballes reals, documentar proves reproduïbles i divulgació responsable.

## Restriccions de seguretat

- No fer `fastboot flash`, `fastboot erase`, canvis de slot, EDL o modificacions de particions com a part de les proves de base.
- No publicar IMEI, serial, tokens, cookies, cadenes `args`, logs sensibles o binaris propietaris.
- No confondre accés root a Android amb desbloqueig persistent del bootloader.

## Registre de canvis

| Data | Canvi | Resultat |
| --- | --- | --- |
| 2026-11-09 | Creació del registre de progrés i pròxim pas | Estat inicial consolidat; següent prova definida: extracció i inspecció estàtica d'ABL |
| 2026-11-09 | Anàlisi inicial de `abl.elf` amb `file`, `readelf` i `strings` | ELF32 ARM, tres program headers, un LOAD RWE de 0x30000 bytes i sense seccions; cap cadena coincident amb el filtre de desbloqueig. |
| 2026-11-09 | Cerca de ferramentes UEFI i nova interpretació del binari | Signatura `_FVH` a `0x1028`, possible FV a `0x1000`. Documentades eines UEFITool, uefi-firmware-parser, xbltools i GBL checker. |
| 2026-11-09 | Extracció local confirmada del volum UEFI | `work/abl-fv.bin`, offset `0x1000`, mida `0x30000`; `.gitignore` ampliat per protegir els extrets. Següent prova: parser UEFI en entorn virtual. |

