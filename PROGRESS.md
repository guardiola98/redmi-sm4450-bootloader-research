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

- [x] Instal·lat `uefi_firmware` **1.16** en l'entorn virtual local `.venv`. `uefi-firmware-parser --test work/abl-fv.bin` retorna `UEFIFirmwareVolume`.
- [x] **Confirmada la jerarquia real ABL/UEFI** amb el parser (sense extraure encara el PE): volum exterior FFS2 de `0x30000` (196.608 bytes); fitxer firmware volume image de 168.965 bytes; secció GUID-defined `ee4e5898-3914-4259-9d6e-dc7bd79403cf` amb processament requerit; volum interior FFS2 `0xce0c0` (843.968 bytes); fitxer aplicació `f536d559-459f-48fa-8bbc-43b554ecae8d`, nom **`LinuxLoader`**; secció **PE32 image**, 843.780 bytes (inclou capçalera de secció, no necessàriament mida exacta del PE). El parser ha descomprimit la secció GUID-defined i ha presentat el volum interior. **Encara no s'ha inspeccionat l'arquitectura del PE extret ni s'ha trobat cap vulnerabilitat.**

- [x] **Extracció confirmada de `LinuxLoader`:** `uefi-firmware-parser -e -o work/uefi-extracted work/abl-fv.bin` ha exportat la secció `section1.pe` de **843.776 bytes**; `file` la identifica com **PE32+ executable EFI, ARM64, 3 seccions**. La ruta està dins del volum interior de la FFS application `f536d559-459f-48fa-8bbc-43b554ecae8d`. El fitxer `section0.guid` s'ha identificat com `OpenPGP Public Key` per `file`, però això no prova que siga cap clau OpenPGP; el parser UEFI l'ha reconegut com a secció GUID-defined. El PE no s'ha executat.
- [x] Afegit `scripts/inspect-linuxloader.py`: inspecció PE offline sense dependències externes (màquina ARM64, seccions, entry point, base i hash). **Pendent executar-lo al Debian.**

- [x] **Inspecció PE completada** amb `scripts/inspect-linuxloader.py`: `LinuxLoader` és PE32+ ARM64 (`0xaa64`), subsistema EFI Application (10), 843.776 bytes, SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`. Punt d'entrada RVA `0x1000`, ImageBase `0x0`, mida d'imatge `0xce000`; 3 seccions: `.text` RVA `0x1000` mida `0xb1000`, flags `0x60000020` (codi executable/llegible); `.data` RVA `0xb2000` mida `0x1b000`, flags `0xc0000040` (dades llegibles/escrivibles); `.reloc` RVA `0xcd000` mida `0x1000`, flags `0x42000040` (dades/descartable). Alineació secció i fitxer `0x1000`. **No és una prova de vulnerabilitat.**
- [x] Afegit `scripts/scan-linuxloader-strings.py` per localitzar cadenes ASCII i UTF-16LE de Fastboot, bloqueig i AVB amb offsets de fitxer, **pendent executar**. Les cadenes són pistes, no proves de bypass.

- [x] **Scanner de cadenes executat** sobre el PE ARM64 de 843.776 bytes: 259 coincidències totals; categories `fastboot=119`, `lock=33`, `avb=118`, `security=12` (les categories se solapen). L'eixida mostra missatges reals d'AVB i bloqueig, entre ells `read_is_device_unlocked` a offset de fitxer `0x0a110d`, `the Unlock status is : %d` a `0x0a1983`, `Error getting device state` a `0x0a1ef2` i `androidboot.vbmeta.device_state` a `0x0a1f0f`. També hi ha moltes rutes del codi EDK2 que causen falsos positius de la categoria Fastboot. **No s'ha demostrat vulnerabilitat ni bypass.**

- [x] **Comandes reals de Fastboot identificades en LinuxLoader**: `flashing get_unlock_ability` (offset fitxer `0x0add1d`), `oem unlock` (`0x0add49`), `oem lock` (`0x0add54`), `oem device-info` (`0x0adda6`), `oem edl` (`0x0addc3`), `oem getlog` (`0x0addcb`), entre altres. Estat i política de desbloqueig: `IsAllowUnlock is %d` (`0x0ae085`), `get_unlock_ability: %d` (`0x0aeac7`), `Error Set Device Unlock: %r` (`0x0aeb8d`), `Failed to update the unlock status` (`0x0aebaa`), `Flashing is not allowed in Lock State` (`0x0ae1c4`), `Fastboot boot command is not available in locked device` (`0x0aec16`). La presència de comandes, errors o estat no indica cap bypass.
- [x] Revisat el codi públic `chkndrp/qualcomm-gbl-exploit-checker`: comprova dos casos vinculats a `set-gpu-preemption` i `set-hw-fence-value` amb cadenes de pegat i una signatura d'opcodes; **no és una prova general** de vulnerabilitat, ni de desbloqueig, i l'absència de cadenes no equival a un estat vulnerable. El seu fitxer `check.py` és GPLv3; no se n'ha copiat codi al projecte. Creat `scripts/check-gbl-markers.py` com a inventari propi de marcadors, amb resultat sempre inconcloent quant a explotabilitat, pendent d'executar.

- [x] **Inventari de marcadors GBL executat** en el PE `LinuxLoader` SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`: `gpu-command=not found`, `fence-command=not found`, `gpu-rejection-text=not found`, `fence-rejection-text=not found`, `generic-fastboot=present at 0xaceb2`. **Conclusió estricta:** no s'han trobat les cadenes relatives a `set-gpu-preemption` i `set-hw-fence-value` en este PE, però això no indica si hi ha o no una vulnerabilitat GBL; no hi ha prova que eixes comandes existisquen en esta compilació. No s'ha executat cap exploit.

- [x] **Ghidra (anàlisi estàtica) — primera referència a `IsAllowUnlock is %d`**: el CodeBrowser mostra la cadena definida a l'adreça `0x000ae085`; `Show References to Address` mostra **una referència de codi**, amb el context desassemblat `add x1, =>s_IsAllowUnlock_is_%d` i adreça de la instrucció parcialment oculta a la captura. No s'ha verificat encara la funció contenidora ni la font del valor, i no s'ha descobert cap bypass.

- [x] **Ghidra — referència d'`IsAllowUnlock` resolta a codi**: funció contenidora `FUN_00054980`; al voltant de `0x00055aac` es veu `ldr x2, [x28, #0x18]`, seguida de `adrp x1, 0xa0000` (`0x00055ab0`), `add x1, x1, #0xe085` (`0x00055ab4`, adreça del text `IsAllowUnlock is %d`) i `bl FUN_00059e4c` (`0x00055ab8`). **Hipòtesi:** `FUN_00059e4c` és una rutina de logging i `x2` transporta el valor imprés; encara no confirmada ni la signatura de la funció ni la procedència de `x28`. Cal distingir el log de la comprovació d'autorització real.

- [x] **Ghidra — origen de x28 identificat** a l'entrada de `FUN_00054980`: `0x000549a8: adrp x28,0xcb000` i `0x000549b0: add x28,x28,#0x5a8`; per tant, `x28=0x000cb5a8` (adreça virtual en la base carregada per Ghidra). La instrucció `0x00055aa8: ldr w2,[x28,#0x18]` llig un valor de 32 bits a `0x000cb5c0` (`DAT_000cb5c0`) i el transmet a una crida de registre junt amb `IsAllowUnlock is %d`. Això identifica una **lectura d'una posició global**, no l'origen o la política de l'autorització. No hi ha cap bug demostrat.

- [x] **Ghidra — localitzada escriptura a `DAT_000cb5c0` a `0x00055b40`**. Les instruccions exactes són `ldr x8,[x22,#0x8]` (`0x55b2c`), `ldr w8,[x8,#0xc]` (`0x55b30`), `sub w8,w8,#1` (`0x55b34`), `ldrb w8,[x23,w8,UXTW]` (`0x55b38`), `and w8,w8,#1` (`0x55b3c`) i `str w8,[x28,#0x18]` (`0x55b40`). L'indicador guardat és el bit 0 d'un byte d'un búfer referenciat per `x23`, amb índex derivat d'una estructura apuntada indirectament per `x22`. La crida virtual `blr x9` anterior i `cbnz x0` condicionen el camí. **Encara no sabem què és el búfer, ni si representa informació d'autorització; no hi ha vulnerabilitat confirmada.**

- [x] **Nova captura Ghidra**: `0x00055ae8: ldur x22,[x29,#-0x90]` recupera el punter `x22` de la pila; `0x00055b04: mov x23,x0` copia a `x23` el valor de `x0` després d'una crida i abans del camí que extrau el bit d'autorització. Encara falta identificar la funció i les dades origen de `x0`, i l'escriptura prèvia del local `-0x90`.

- [x] **Anàlisi directa del PE ARM64 adjunt** `LinuxLoader.pe` (SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`) amb `llvm-objdump`: la funció `FUN_00054980` consulta explícitament la partició **`frp`** (cadena UTF-16LE a `0xAF508`) via `0x59fc8 → 0x56148`, obté un descriptor en `[x29,#-0x90]`, usa un búfer a `x23` i un callback `blr x9`, i després d'èxit extrau el bit menys significatiu del byte indexat per `N-1` a `0x55b2c..0x55b40` per guardar-lo en `DAT_000cb5c0`. També hi ha missatges `Error Reading FRP partition` i `Error Locate MiToken Protocol`. **No s'ha demostrat** que el bit siga suficient per desbloquejar, que siga editable, ni com intervé MiToken. Informe complet a [docs/linuxloader-frp-analysis.md](docs/linuxloader-frp-analysis.md).

- [x] **Nova revisió estàtica directa del PE adjunt (2026-11-09)**: SHA-256 verificat; desassemblatge LLVM de `FUN_00054980` i funcions auxiliars. `0x55a74..0x55a84` passa el nom UTF-16 `frp` a un helper de localització; `0x55ae8` recupera el descriptor `x22`. `0x55af8` crida `0x5950` per obtindre búfer; `0x55b20` crida callback de lectura; **només si retorna zero** `0x55b2c..0x55b40` emmagatzema el bit `buf[N-1] & 1` a `DAT_000cb5c0`. Es confirma que el missatge `IsAllowUnlock` a `0x55aa8` apareix **abans** del camí de lectura i pot tornar a executar-se per un bucle des de `0x55b4c` fins `0x55a90`. A `0x57c50`, una altra funció llig `DAT_000cb5c0` per passar-lo a una rutina de format amb text proper a `get_unlock_ability`; encara **no és evidència que el bit siga l'únic control d'autorització**.
- [x] **Ruta MiToken separada confirmada estructuralment**: `0x55b50..0x55b60` intenta localitzar una interfície UEFI per GUID (`0xb1800`) amb `0x59f48` (veneer cap a crida indirecta), i `0x55be0..0x55bf0` invoca un callback via `0x59fe0` per consultar la longitud d'un token; després hi ha una segona invocació i missatge `Error Get Token`. Identitat completa del protocol i relació causal amb desbloqueig **encara no demostrades**. Vegeu [docs/linuxloader-frp-analysis.md](docs/linuxloader-frp-analysis.md).

- [x] **Anàlisi directa dels handlers Fastboot al PE adjunt (2026-11-09)**: `0x57c50` llig el flag global `[0xCB5A8+0x18]` i el passa junt amb el format `get_unlock_ability: %d` (`0xAEAC7`) a la rutina `0x4488`, compatible amb un **handler informatiu**. Per separat, `0x57e34..0x57f1c` conté una ruta de canvi d'estat amb crida `0x43d88` i comprovació d'errors; la funció `0x43d88` ramifica cap a `0x440b0` i `0x44188` i no és una simple escriptura del flag FRP. No està comprovat encara com s'autoritzen estes transicions ni quina ruta exacta les invoca. Vegeu [docs/linuxloader-fastboot-handlers.md](docs/linuxloader-fastboot-handlers.md). **No s'ha descobert cap vulnerabilitat.**

- [x] **Inspecció ampliada de persistència del canvi d'estat**: les subrutines `0x440B0`/`0x44188` comproven valors actuals via `0x43B60`/`0x43B70`, escriuen bytes diferents a `0xC294D` / `0xC294E` i, si cal un canvi, invoquen `0x2D728` amb el búfer de configuració i longitud `0x998` (2.456 bytes). `0x2D728` localitza un protocol per GUID a `0xB1790` i delega la persistència a una crida indirecta (`0x2D840`); la identitat d'eixe protocol encara no s'ha confirmat. **No es pot afirmar que el flag FRP permeta escriure estes dades ni que hi haja una vulnerabilitat.** Documentat a [docs/linuxloader-fastboot-handlers.md](docs/linuxloader-fastboot-handlers.md).

- [x] **Identificat el GUID del protocol de persistència mitjançant lectura directa del PE adjunt**: bytes a `0xB1790` = `91 ff 5e 8e b6 21 d3 47 af 2b c1 5a 01 e0 20 ec`; GUID UEFI `8e5eff91-21b6-47d3-af2b-c15a01e020ec`, relacionat en referències públiques amb **Qualcomm VerifiedBoot Protocol**. A `0x2D7A4..0x2D7B0`, `0x2D728` localitza eixe protocol, i `0x2D82C..0x2D840` invoca un callback del protocol a offset `+8` amb operació, búfer i longitud. Això concreta la interfície de persistència utilitzada per `0x440B0` i `0x44188`, però **no demostra cap accés no autoritzat ni desbloqueig**. El segon GUID `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df` a `0xB1800` continua sense identificar. Vegeu [docs/linuxloader-fastboot-handlers.md](docs/linuxloader-fastboot-handlers.md).

- [x] **Revisió directa del handler de desbloqueig amb LLVM (2026-11-09)**: el camí que arriba a `0x57E90` (escriptura de l'estat per `0x43D88`) està protegit per **dues comprovacions indirectes de retorn zero**: callback a `0x57DE0` (fallada amb missatges `Error Verify Token` i `Token Verify Failed, Reboot the device`) i callback via `0x5A1FC` a `0x57E48` (ramifica a `0x57E90` només amb `x0=0`). La seqüència conté els missatges `Error Locate Token Protocol`, `Error Get Token Length`, `Error Get Token`. Això dona evidència d'un *flux de validació de token abans de modificar l'estat*, però no determina l'algorisme criptogràfic ni identifica la implementació de les interfícies. `0x57F24` és una ruta alternativa de canvi d'estat amb arguments zero, potencialment bloqueig, encara no tipada al despatx. **No hi ha bug confirmat**. Vegeu [docs/linuxloader-fastboot-handlers.md](docs/linuxloader-fastboot-handlers.md).

## Següent pas immediat

**Tipar les dues crides indirectes de verificació de token i identificar la implementació del protocol en fonts de Qualcomm/Xiaomi**, sense tocar el dispositiu. El desassemblatge ja demostra que no n'hi ha prou a canviar un bit de FRP per afirmar que es podrà invocar VerifiedBoot: el handler del PE inclou comprovacions de token abans de la transició.

1. Traçar el GUID i la taula de callbacks usats per `0x57D1C`, `0x57DE0` i `0x57E48`, amb confirmació de signatures i errors; no anomenar MiToken el GUID desconegut sense font.
2. Relacionar les condicions d'eixida del handler amb els dos camps de VerifiedBoot i determinar què es valida en el mateix ABL versus serveis de firmware.
3. Revisar la compatibilitat de recerques GBL amb la versió/SoC concret: absència de marcadors no implica invulnerabilitat.
4. Preparar un inventari de diferències amb una versió anterior de firmware `sky` EEA de procedència verificable; comparar primer comportament estàtic.

**Cap prova de modificació sobre FRP, particions, tokens o estat de bloqueig.** No s'ha identificat un desbloqueig no autoritzat.

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
| 2026-11-09 | Validacions de token verificades al handler | Dos callbacks condicionen el camí que invoca `0x43D88`; nou informe en `docs/linuxloader-fastboot-handlers.md`. El format i validesa del token continuen desconeguts. |
| 2026-11-09 | Identificació del protocol Qualcomm VerifiedBoot | GUID `8e5eff91-21b6-47d3-af2b-c15a01e020ec` a `0xB1790`; wrapper de protocol `0x2D728`, callback a `0x2D840`. Següent: autorització dels handlers i identificació de MiToken. |
| 2026-11-09 | Persistència de l'estat de bloqueig analitzada | Dos bytes de configuració, escriptura via `0x2D728` i protocol UEFI indirecte no identificat; no s'ha descobert bypass. |
| 2026-11-09 | Anàlisi separada de handlers Fastboot | `get_unlock_ability` llig un flag FRP per mostrar-lo (`0x57c50`); la transició d'estat utilitza `0x43d88` i funcions auxiliars amb controls d'error. Sense bypass confirmat. |
| 2026-11-09 | PE ARM64 analitzat directament | Hash verificat; cadena `frp` trobada i lectura indirecta seguida d'extracció d'un bit a `DAT_000cb5c0`. Informe a `docs/linuxloader-frp-analysis.md`. Següent pas: distingir MiToken i seguir consumidors del flag. |
| 2026-11-09 | Creació del registre de progrés i pròxim pas | Estat inicial consolidat; següent prova definida: extracció i inspecció estàtica d'ABL |
| 2026-11-09 | Anàlisi inicial de `abl.elf` amb `file`, `readelf` i `strings` | ELF32 ARM, tres program headers, un LOAD RWE de 0x30000 bytes i sense seccions; cap cadena coincident amb el filtre de desbloqueig. |
| 2026-11-09 | Cerca de ferramentes UEFI i nova interpretació del binari | Signatura `_FVH` a `0x1028`, possible FV a `0x1000`. Documentades eines UEFITool, uefi-firmware-parser, xbltools i GBL checker. |
| 2026-11-09 | Extracció local confirmada del volum UEFI | `work/abl-fv.bin`, offset `0x1000`, mida `0x30000`; `.gitignore` ampliat per protegir els extrets. Següent prova: parser UEFI en entorn virtual. |
| 2026-11-09 | Parser UEFI confirma LinuxLoader | `uefi_firmware` 1.16 ha trobat FV intern de 843.968 bytes i aplicació `LinuxLoader` amb secció PE32. |
| 2026-11-09 | LinuxLoader extret i arquitectura confirmada | Secció `section1.pe` de 843.776 bytes, PE32+ EFI ARM64 amb 3 seccions; publicat `inspect-linuxloader.py`. |
| 2026-11-09 | Inspecció detallada del PE i scanner de cadenes | RVA `0x1000`, base `0x0`, seccions `.text`, `.data`, `.reloc`; SHA-256 del PE registrat. Scanner ASCII/UTF-16 creat. |
| 2026-11-09 | Primera cerca de cadenes Fastboot/AVB/bloqueig | 259 coincidències; localitzades referències a estat de desbloqueig i verificació AVB. |
| 2026-11-09 | Comandes Fastboot localitzades i revisió del checker GBL | Identificades `oem unlock`, `flashing get_unlock_ability`, `IsAllowUnlock` i errors de restricció; afegit inventari conservador de marcadors GBL per la pròxima prova. |
| 2026-11-09 | Prova dels marcadors GBL executada | Cap dels quatre marcadors específics de GPU/fence detectat; cadena genèrica Fastboot sí. Resultat inconcloent. Següent pas: referències de les funcions de bloqueig en Ghidra. |
| 2026-11-09 | Primera referència a IsAllowUnlock en Ghidra | Una XREF confirmada a la cadena `IsAllowUnlock is %d`. |
| 2026-11-09 | Referència resolta en codi ARM64 | `FUN_00054980`: `ldr x2,[x28,#0x18]` abans de `bl FUN_00059e4c`; possible logging del valor d'autorització. Següent pas: origen de `x28` i comprovació de la rutina de logging. |
| 2026-11-09 | Localitzat x28 i lectura global d'IsAllowUnlock | `adrp/add` fixen `x28` a `0xCB5A8`; `ldr w2,[x28,#0x18]` llig `DAT_000cb5c0`. Següent pas: trobar referències d'escriptura al camp. |
| 2026-11-09 | Càlcul del camp IsAllowUnlock localitzat | `0x55b2c..0x55b40`: bit 0 d'un byte del búfer `x23` indexat per dades obtingudes via `x22`; següent pas: identificar origen dels dos registres. |
| 2026-11-09 | Rastres addicionals x22/x23 en Ghidra | `ldur x22,[x29,#-0x90]` a `0x55ae8`; `mov x23,x0` a `0x55b04`. Següent pas: anàlisi directa del PE adjunt per reconstruir el flux de dades. |
| 2026-11-09 | Revisió offline FRP i MiToken | Verificat control d'èxit de lectura FRP, bucle de registre del bit, crides indirectes de MiToken i consumidor del flag per a format de get_unlock_ability. La decisió final d'autorització continua pendent. |

## Actualització important — 2026-11-09: token retrieval vs verification

He revisat de nou `LinuxLoader.pe` amb `llvm-objdump` i he afinat la interpretació del handler; la descripció anterior de «dues comprovacions de verificació de token» era massa forta:

- `0x57D64` crida el callback del protocol a `+0x08` amb búfer nul per demanar la longitud del token.
- `0x57DE0` crida **el mateix callback a `+0x08`** amb un búfer reservat: **obtenció del token**, condicionada a retorn zero, no una segona verificació criptogràfica.
- `0x57E48` crida el callback a `+0x10` amb el token obtingut, un payload i la seua longitud: **verificació del token/signatura**, condicionada a retorn zero abans d'arribar a `0x43D88`.
- `0x5A214` conserva `x22=x1` i `w21=w2` (paràmetres d'entrada), que després es passen al verificador.
- GUID del protocol token a `0xB1800`: `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df`. **No s'ha trobat una definició pública concloent d'este GUID**. No afirmar encara que la interfície siga necessàriament MiToken, encara que el flux siga compatible.
- [Investigació històrica Xiaomi-bootloader](https://github.com/lrh2000/Xiaomi-bootloader): precedent que situa la implementació del protocol Mi-Token en **XBL** en un model antic (Redmi Note 8T, 2020); no es pot extrapolar automàticament al Redmi 12 5G.

**Següent pas verificable:** examinar l'`xbl_s.melf` del mateix arxiu Fastboot (SHA-256 ja conegut `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1`) i determinar si conté o registra el GUID del protocol token, i en quin mòdul es troba el callback a `+0x10`. Fer-ho **offline**, sense flashejar res. El PE ABL és insuficient per demostrar el funcionament criptogràfic intern.

**Estat:** encara cap vulnerabilitat demostrada ni via de desbloqueig independent.

### Nova eina (2026-11-09)

- [x] Creat `scripts/scan-xbl-protocol-guid.py`: llig exclusivament `images/xbl_s.melf` des del Fastboot `.tgz`, comprova el SHA-256 conegut i busca els GUID del protocol candidat de token i de Qualcomm VerifiedBoot en format UEFI little-endian o network-order. **És una cerca de bytes literal: no trobar coincidències no demostra l'absència del protocol**, perquè podria estar comprimit, dividit o implementat en un altre component.
- [ ] Executar la prova local en Debian:

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/scan-xbl-protocol-guid.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Si no hi ha coincidències, estudiar offline l'estructura real de l'XBL abans de descartar res. No flashejar ni enviar dades del mòbil.

### Resultat real de l'escàner XBL (2026-11-09)

El propietari ha executat `scripts/scan-xbl-protocol-guid.py` sobre la ROM EEA local. **Confirmat:** `xbl_s.melf`, 1.170.244 bytes, SHA-256 `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1`. No hi ha coincidència **literal** del GUID token candidat `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df` ni del GUID VerifiedBoot `8e5eff91-21b6-47d3-af2b-c15a01e020ec`, en cap dels dos ordres de bytes examinats. Este resultat **no demostra** absència d'eixos protocols: podrien estar en una imatge distinta, en una capa comprimida o representats d'una altra manera.

He afegit `scripts/inspect-xbl-structure.py` (només lectura) per caracteritzar l'ELF verificat i buscar possibles signatures de volums UEFI (`_FVH`) **amb comprovació de límits**, sense confiar en desplaçaments aleatoris. L'eina limita la comprovació a `xbl_s.melf`, l'únic component amb hash verificat en esta fase.

**Següent ordre segura a Debian:**

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/inspect-xbl-structure.py \\
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Interpretar segments ELF i les possibles capçaleres FV abans d'intentar descomprimir res. **No connectar el telèfon ni modificar particions.**

## Investigació comparada de repositoris i nou rumb (2026-11-09)

L'usuari ha executat `scripts/inspect-xbl-structure.py` sobre el firmware EEA propi: `xbl_s.melf`, 1.170.244 bytes, SHA-256 verificat `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1`; ELF32, e_machine `0x1`, entrada `0x2211c000`, dos segments declarats (`0x74/0x1c000`, `0x1c074/0x280`), **sense** coincidències literals `_FVH`. Els segments no abasten tot el fitxer; no sabem encara l'ús de les dades sobrants. No s'han trobat GUIDs de token/VerifiedBoot de forma literal, però això no prova absència.

Comparats els projectes recents i de referència [OpenABL](https://github.com/OpenHandheldCollective/OpenABL) (suport SM4450 en ABL Qualcomm), [linux-msm/xbltools](https://github.com/linux-msm/xbltools) (diferència entre càrrega inicial i nucli UEFI), [qualcomm-linux/qcom-ptool](https://github.com/qualcomm-linux/qcom-ptool) (particions UEFI separades en altres SoC), [lrh2000/Xiaomi-bootloader](https://github.com/lrh2000/Xiaomi-bootloader) (Mi-Token al XBL d'un Xiaomi antic), [kasnria001/qualcomm_gbl_exploit_poc](https://github.com/kasnria001/qualcomm_gbl_exploit_poc) (GBL no confirmat en sky), i [Jz8Root/xiaomi-hyperos-bootloader-unlock](https://github.com/Jz8Root/xiaomi-hyperos-bootloader-unlock) (**MediaTek**, no aplicable a SM4450). Conclusions i limitacions detallades a [docs/research-directions-2026-11.md](docs/research-directions-2026-11.md).

**Canvi de prioritat:** deixar de buscar literalment GUIDs en `xbl_s.melf` i localitzar primer la imatge UEFI real del paquet Fastboot `sky`. Ja existeix `scripts/analyze-bootchain.py`, que inventaria imatges i mapatges `rawprogram*.xml` **sense extraure ni escriure res**; no s'ha creat un script duplicat.

**Prova següent:**

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/analyze-bootchain.py \\
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Amb l'eixida, estudiar el `xbl.elf` / `uefi.elf` / equivalents si hi apareixen i comprovar quin mòdul allotja la interfície del token. No importar firmwares, payloads o claus d'altres dispositius; **cap vulnerabilitat demostrada**.

## Inventari real de la ROM Fastboot sky EEA — 2026-11-09

L'investigador ha executat `scripts/analyze-bootchain.py` i ha obtingut **114 fitxers regulars**. Mapatges confirmats del manifest:

| Partició en rawprogram | Fitxer | SHA-256 |
| --- | --- | --- |
| `abl_a` | `abl.elf` | `f1c1f9ffbfa596cc352bf13aaa8e751eaee5168ab0344c641a70f0aa5f1607eb` |
| `xbl_a` | `xbl_s.melf` | `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1` |
| `xbl_config_a` | `xbl_config.elf` | `97e8e3a4b0422e064f3df3282d6b1569364b603d4b9497f6827cace14ceaf9cc` |
| `tz_a` | `tz.mbn` | `f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76` |
| `xbl_ramdump_a` | `XblRamdump.elf` | `912caf467639bb15935b66f5ebfddef00d8a85965af3788166242c0cb54c766b` |
| `xbl_sc_test_mode` | `xbl_sc_test_mode.bin` | `f28e157b99098d300b47743888da372f0a7f7e1fe01f148162648bd0d1e4fd69` |

`xbl_s_devprg_ns.melf` també està al paquet (1.747.908 bytes, SHA-256 `99dc96ace498f99911f110e750fc941cce5f4cc580f7de6329824a055a98baf4`), però **no apareix als mapatges de rawprogram retornats per este script**; no s'ha d'assumir que el telèfon l'arranque.

**Conclusió:** `xbl_s.melf` és l'única imatge del paquet identificada explícitament com a destí `xbl_a`. Els escàners previs no van trobar GUID ni `_FVH` literals, però no han examinat mòduls o possibles capes de contenidor. La manca de `uefi.elf` a l'eixida filtrada **no prova l'absència del fitxer**, perquè el regex de l'script no inclou este nom.

**Següent prova segura:**

```bash
cd ~/redmi-sm4450-bootloader-research
python3 scripts/inventory-fastboot.py --all --skip-hash \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz \
  | grep -Ei 'uefi|xbl|fv|firmware|imagefv|core|bootchain'
```

Després, si no hi ha cap component UEFI separat, caracteritzar les dades de `xbl_s.melf` fora dels segments ELF (incloent capçaleres Qualcomm), amb anàlisi local read-only i referències a `linux-msm/xbltools`. No considerar `xbl_s_devprg_ns.melf` una drecera ni executar/flashejar cap fitxer.

**Estat:** cap vulnerabilitat ni desbloqueig no autoritzat confirmat.

## Imatges UEFI localitzades al paquet sky — 2026-11-09

**Resultat aportat per l'investigador de `inventory-fastboot.py --all`:** la ROM inclou `uefi.elf` (3.739.448 bytes), `imagefv.elf` (1.056.568 bytes), `tools.fv` (393.216 bytes) i `uefi_sec.mbn` (172.120 bytes), a més de `xbl_s.melf` i `xbl_config.elf`. Açò corregix la deducció anterior basada en `analyze-bootchain.py`, que filtrava `uefi.elf` i `imagefv.elf` i no els mostrava: **l'absència en l'inventari anterior era un fals negatiu de l'eina, no una absència en el firmware**.

**Canvis aplicats:**
- [x] `scripts/analyze-bootchain.py` ara inclou `uefi.elf`, `uefi_sec.mbn`, `imagefv.elf` i `tools.fv` al filtre d'imatges de firmware, per a inventaris futurs.
- [x] Nou `scripts/scan-uefi-images.py`: inspecció **offline, de només lectura**, de les quatre imatges. Mostra mida, SHA-256, coincidències literals dels GUID de token candidat (`0c00a314-11a1-4d7a-a5c8-70bd5f88e7df`) i VerifiedBoot (`8e5eff91-21b6-47d3-af2b-c15a01e020ec`) en les dues codificacions, i possibles capçaleres `_FVH` amb validació de límits. No executa ni extrau firmware; no accedix al mòbil.
- [ ] Executar la nova prova sobre el paquet original (l'usuari el conserva al seu Debian):

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/scan-uefi-images.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

**Interpretació pendent:** veure si els GUID apareixen en `uefi.elf` o `imagefv.elf`; si no, una implementació comprimida/indirecta continua sent possible. No deduir compatibilitat de vulnerabilitats de firmwares aliens ni intentar flash. **Encara no hi ha bypass confirmat.**

## Resultats de l'escàner UEFI i següent fase — 2026-11-09

Resultat executat i aportat per l'investigador sobre el paquet original (no s'ha modificat el mòbil):

| Component | Mida | SHA-256 | Volum FV |
| --- | ---: | --- | --- |
| `uefi.elf` | 3.739.448 | `0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50` | `_FVH` a `0x1028`, inici `0x1000`, llargària `0x38f000` |
| `imagefv.elf` | 1.056.568 | `51220103d9d5f2c8e11f3bfe8a221db9cba2bd0478902037175067e182c94332` | `_FVH` a `0x1028`, inici `0x1000`, llargària `0x100000` |
| `tools.fv` | 393.216 | `d7f0c4034bb3236e3878dfd56116217dc34afd5b3d41e7a1f1e71fddbf77a002` | `_FVH` a `0x28`, inici `0x0`, llargària `0x60000` |
| `uefi_sec.mbn` | 172.120 | `091a04fc255056660612f72c550505ccdc7c4be97bcff653f201f26486892d64` | No hi ha `_FVH` literal |

En cap dels quatre fitxers apareix **literalment** el GUID token candidat `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df` ni el GUID VerifiedBoot `8e5eff91-21b6-47d3-af2b-c15a01e020ec`, en els dos ordres de bytes. **No es poden descartar protocols empaquetats/comprimits.** Els FV confirmats per `_FVH` i mida dins de límits proporcionen un punt d'entrada vàlid per a inspecció FFS.

- [x] Creat `scripts/inventory-uefi-ffs.py`, lector offline només de capçaleres FFS i seccions de primer nivell, verificació SHA-256 dels tres components; no descomprimix ni executa res.
- [ ] Executar:

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/inventory-uefi-ffs.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

**Objectiu:** determinar quants FFS hi ha, els GUID de fitxer, els noms UI i si les seccions estan comprimides o definides per GUID. Una vegada identificats, extreure/analitzar només el contingut offline dels mòduls pertinents; no tocar les particions ni fer flash.

**Limitació:** l'inventari FFS és un analitzador simple de primer nivell, no un validador complet del format PI/UEFI; un fitxer FFS inesperat o capçalera estesa pot requerir un parser més complet. Cap vulnerabilitat ni bypass confirmat.

## Inventari FFS real i GUID de compressió — 2026-11-09

Eixida de `scripts/inventory-uefi-ffs.py` executat localment per l'investigador (SHA-256 dels 3 FV confirmats):

- `uefi.elf`: 5 entrades FFS de primer nivell; primer fitxer de farciment, un fitxer amb seccions `raw` + `TE`, `uefiplat.cfg`, i **dues seccions GUID-defined** en fitxers FFS a offsets `0x04ae08` i `0x19c948`. GUID de secció `1d301fe9-be79-4353-91c2-d23bc959ae0c`, identificat en fonts UEFI/Qualcomm com a variant de **GZIP de Qualcomm**.
- `imagefv.elf`: 1 FFS, offset `0x001048`, amb secció GUID-defined `ee4e5898-3914-4259-9d6e-dc7bd79403cf`, associada a **LZMA d'UEFI**.
- `tools.fv`: 1 FFS, offset `0x000048`, amb secció GUID-defined `ee4e5898-3914-4259-9d6e-dc7bd79403cf`.
- Els GUID de secció **identifiquen el format exterior de les dades**, no identifiquen cap protocol token ni VerifiedBoot. Encara no s'ha comprovat descomprimint si contenen mòduls relacionats amb el token.

**Nova eina pujada:** `scripts/inspect-compressed-uefi.py`, parseja les seccions de primer nivell, intenta GZIP i LZMA **amb límits de memòria i grandària**, busca els GUID de protocol en les dades descomprimides i mostra tipus de seccions interns. No escriu fitxers, no connecta amb el telèfon, no executa binaris. L'anàlisi de seccions internes és preliminar; un FV anidat o formats específics requeriran un lector complet.

**Següent acció al Debian:**

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/inspect-compressed-uefi.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Passar l'eixida completa, incloent errors de descompressió si apareixen; un error d'esta ferramenta **no demostra xifrat ni absència del protocol**. Si els GUID apareixen, localitzar el PE/TE corresponent per a anàlisi estàtica. **Sense bypass ni vulnerabilitat confirmats.**

## Troballa important: protocols visibles dins d'UEFI descomprimit (2026-11-09)

**Resultat real executat pel propietari de `scripts/inspect-compressed-uefi.py`:**
- `uefi.elf`, FFS `9e21fd93-9c72-4c15-8c4b-e77f1db2d792` a `0x04ae08`, secció **Qualcomm GZIP** GUID `1d301fe9-be79-4353-91c2-d23bc959ae0c`: 1.383.181 bytes comprimits → **3.985.416 bytes descomprimits**. Dins apareixen els GUID `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df` (token candidat; offset relatiu `0x8f8ec`) i `8e5eff91-21b6-47d3-af2b-c15a01e020ec` (Qualcomm VerifiedBoot; `0x848b4`), en format little-endian UEFI. **És evidència de presència de les identificacions, no de quina funció exacta les implementa ni de vulnerabilitat.**
- Segon FFS Qualcomm GZIP de `uefi.elf` (`0x19c948`) descomprimit: **10.715.144 bytes**, FV intern; sense coincidències de GUID reportades per l'script.
- `imagefv.elf`: GUID-defined LZMA; l'eina ha indicat `decompressed size exceeds limit`. **No interpretar-ho com una grandària real del FV ni com corrupció**; cal tractar el cas per separat si interessa.
- `tools.fv`: LZMA descomprimit correctament a **1.904.648 bytes**, FV intern, sense coincidències reportades.

**Canvi de prioritat:** aprofundir **en el primer FV intern de `uefi.elf`**, on tenim coincidències directes dels dos GUID. No fa falta augmentar de moment els límits LZMA per a `imagefv.elf`.

**Nou script:** `scripts/locate-uefi-protocol-modules.py` (només lectura), verifica SHA-256, descomprimix en memòria el primer FFS GZIP, valida el FV intern i informa de quin **FFS** i secció conté cada GUID, inclosos possibles noms UI. No atribuïx el GUID automàticament a una implementació de protocol.

**Següent prova Debian:**

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/locate-uefi-protocol-modules.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Revisar el mòdul FFS concret i la seua relació amb registres `InstallProtocolInterface` i les crides d'ABL. **Encara no hi ha prova de bug explotable, ni mètode de desbloqueig.**

## Incidència del localitzador FFS (2026-11-09)

L'usuari ha executat `scripts/locate-uefi-protocol-modules.py`: SHA-256 de l'entrada acceptat i **descompressió GZIP correcta de 3.985.416 bytes**, però el script acaba amb `ValueError: Expected decoded FV-image section not found` a la línia 140. Per tant, **la descompressió no ha fallat** i cap conclusió sobre presència/absència de mòduls és possible a partir d'esta excepció.

La versió anterior assumia que `content[3] == 0x17` i que el volum interior començava a l'offset 4/8. S'ha modificat `scripts/locate-uefi-protocol-modules.py` per imprimir els **primers 16 bytes**, enumerar les seccions de primer nivell amb el parser existent i localitzar una secció de tipus `0x17` amb capçalera FV comprovada. **Correcció encara no provada amb eixe firmware**: si el nou resultat diu que no ha trobat FV, no deduir corrupció del firmware; caldrà examinar el prefix i el format exacte de l'embolcall descomprimit.

Següent prova read-only:

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/locate-uefi-protocol-modules.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

**Encara no hi ha vulnerabilitat demostrada.**

## Extracció reproduïble dels protocols — sessió local 2026-11-09

Creat `scripts/extract-protocol-pe.py`: reutilitza el lector amb SHA-256 fixat,
identifica les seccions FV-image i selecciona exclusivament els GUID FFS de
MiTokenDxe i VerifiedBootDxe, exigint coincidència del nom UI i un únic PE32.
Valida MZ, PE, PE32+ i ARM64; escriu només en `work/protocols/`.
Tres proves inicials de límits/entrades truncades passen amb
`python3 scripts/test-extract-protocol-pe.py`. La lectura integral del TGZ està
en curs. Disponibles Python, uefi_firmware 1.16 i Ghidra 12.2/Java 25;
llvm-objdump no està en PATH. Cap operació sobre el dispositiu.

**Extracció completada i comprovada:** MiTokenDxe = 45.056 bytes, SHA-256
`5960ae5e4b2ae712f8ef1e854cb37e3fcaf0ecb1427aa40eeebd733829be68b9`;
VerifiedBootDxe = 61.440 bytes, SHA-256
`cb1f1861c84d2aecc6f01ffcd84ea39dff406106053ed389acdd7b045da47fc6`.
Els dos són PE32+ ARM64, EFI Boot Service Driver, ImageBase zero, entry RVA
`0x1000`. Manifest publicable en `docs/protocol-pe-manifest.json`.
Els payloads PE comencen a `0x86844` i `0x777fc` del descomprimit:
els offsets facilitats `0x86840`/`0x777f8` inclouen la capçalera de secció.
Iniciada anàlisi Ghidra offline de MiTokenDxe. Cadenes observades sobre RNG,
ChipInfo, QFPROM, Base64 i SCM són pistes; no demostren algoritme ni bypass.

**Primera reconstrucció MiToken:** Ghidra completat. Taula a RVA 0x9648:
`1, 0x1784, 0x1a58, 0x1ac0`; callbacks +8/+0x10 relacionats amb ABL.
Verificació 0x1a58 → 0x1b0c → 0x1e84; firma exigida de 256 bytes,
missatge 1..245, clau a 0x9668 amb exponent 65537. Inferència forta RSA-2048,
padding tipus 1 amb missatge literal segons pseudocodi, pendent corroboració
instrucció a instrucció. Informe i límits en `docs/protocol-modules.md`.
VerifiedBoot encara pendent d'anàlisi funcional; no declarar fase d'auditoria
completada ni desbloqueig. Pròxim experiment: definir 0x1784 i verificar
branches de 0x1e84, després taula VerifiedBoot i persistència.

## Continuació MiToken i VerifiedBoot — 2026-11-09

- Exportacions Ghidra de codi i instruccions completades per als dos PE.
  Scripts reproduïbles a `scripts/ghidra/`, resultats propietaris en `work/`.
- MiToken 0x1784 confirmat: consulta 128, RNG 16 bytes, camps placa/ChipInfo,
  Base64 URL-safe i cache. No cal redefinir funció per veure les instruccions.
- Padding corroborat: 256 bytes, missatge 1..245, 00 01 FF…00 + missatge cru.
  Tres tests de model sintètic passen (inclouen 256 mutacions); no equivalen
  a provar RSA ni a executar el firmware.
- VerifiedBoot taula 0xd180, +8 → 0x15ac: connectat a persistència d'ABL.
  Lectura/escriptura QSEE keymaster 0x202/0x203; fallback devinfo condicionat
  per SCM, màscares 0x8703/0x8723. No és bypass per si mateix.
- Defecte estàtic: reserva nul·la en 0x17bc/0x185c acaba en retorn zero
  (0x1950, 0x1640) sense operació. Accessibilitat/explotabilitat no demostrades.
  Informe ampliat en docs/protocol-modules.md. Cap desbloqueig funcional.
- Pendent: model CFG amb fallades injectades com a dades, efectes en caller
  ABL, mapeig complet de callbacks, integritat interna keymaster/RPMB i
  comparació pública detallada. No s'ha executat cap payload ni tocat mòbil.

## Fals èxit VerifiedBoot: efectes en ABL — 2026-11-09

- Completada anàlisi Ghidra independent de LinuxLoader (SHA-256 verificat),
  exportacions locals C/ASM; cap execució de firmware ni operació al mòbil.
- Corroborat que els setters modifiquen RAM abans de persistir i no restauren
  el byte dins del setter. La funció superior pot intentar reversió si falla
  el reset posterior; altres passos poden fallar. Èxit final no garantit.
- Lectura inicial 0x44640: èxit fals neteja el flag i conserva búfer o inicia
  defaults segons capçalera i byte retornat per 0x2e4c0. No assumir desbloqueig.
- MiToken continua sent requisit previ en la ruta 0x57e48 → 0x57e94.
- Nou informe docs/verifiedboot-failure-analysis.md amb taula de camins,
  evidència RVA, límits i següent comprovació. Model offline en
  scripts/test-verifiedboot-failure-model.py: 7 tests passen.
- Una escriptura posterior correcta pot persistir tot el búfer, inclosos
  canvis anteriors: distingir absència d'escriptura actual de persistència futura.
- Següent: 0x10284, callers de 0x44640 i callback VerifiedBoot +0x30.
  Accessibilitat de reserva nul·la i bypass no demostrats.

## Consulta segura i caller inicial — continuació 2026-11-09

- Verificat en ASM: `0x10284` transforma sentinella `0xffffffff` en
  `0x8000000000000001`; byte baix 1, no activa defaults desbloquejats.
- Una sola crida directa a `0x44640`, RVA `0x173c`; dues ocurrències en C
  són codi solapat. Retorn no zero abandona la continuació normal.
- Documentat en `docs/verifiedboot-failure-analysis.md`. El retorn intern
  de `0x100b4` necessita reconstrucció ASM pels helpers compartits;
  callback VerifiedBoot +0x30 també pendent. Sense bypass demostrat.

## Retorn SCM reconstruït — 2026-11-09

- `0x100b4`: localització fallida, punter nul, error SCM i resposta[0] != 1
  convergixen en `0xffffffff`; l'epíleg compartit conserva w0.
- Èxit: retorna 32 bits de resposta[1]. Els errors locals enumerats
  es transformen en byte 1 i defaults bloquejats en `0x44640`.
- Model ampliat a 9 tests, tots passen. Informe amb branques i RVA en
  `docs/verifiedboot-failure-analysis.md`. No s'ha executat firmware.
- Pendent: callback VerifiedBoot +0x30 i semàntica interna TZ dels bits;
  no hi ha desbloqueig ni accessibilitat de reserva nul·la demostrats.


## Callback de restabliment VerifiedBoot — 2026-11-09

- Taula PE verificada: +0x30 → 0x1c44. Anàlisi ASM fins a 0x1d88.
- Delega en keymaster, comanda 0x10e, petició/resposta de 4 bytes.
  Èxit només amb transport i resposta zero; errors de comanda → 0x50.
  Errors de localització/inici es propaguen. Sense reserva de pàgina local.
- Informe ampliat en docs/verifiedboot-failure-analysis.md; 9 tests existents
  passen, sense emular el callback nou. Cap operació sobre el mòbil.
- Pendent: condicions ABL 0x9dbc/0x9db4 i contracte QSEE/keymaster.
  No hi ha bypass ni efecte intern de reset demostrat.


## Condicions ABL resoltes — 2026-11-09

- PE LinuxLoader verificat per SHA-256 i bytes: `0x9dbc` retorna sempre 1;
  `0x9db4` retorna sempre 2 (`mov w0,imm; ret`).
- En `0x2e5f0`, la condició d'omissió `(1 == 0) || (2 == 3)` és falsa:
  es localitza VerifiedBoot i, si té èxit, s'invoca +0x30; els errors es propaguen.
- Documentada evidència RVA/bytes en `docs/verifiedboot-failure-analysis.md`.
  No s'atribuïx un nom original ni semàntica a l'enumeració sense evidència.
- Pendent: contracte del transport QSEE i efecte intern keymaster 0x10e.
  Cap operació al mòbil, vulnerabilitat explotable ni desbloqueig demostrats.

- [x] **Contracte QSEE al caller (2026-11-09):** dos canals, x0 de
  transport i word de resposta keymaster; Reset_State exigix tots dos zero
  i convertix qualsevol error d'enviament/resposta en 0x50. La resposta
  es carrega abans de comprovar transport i no està inicialitzada: el log
  en fallada no prova un estat retornat per l'aplicació. El servei +0x48
  previ usa un global diferent del protocol QSEE. Detalls i contrast amb
  fonts primàries Linux en `docs/verifiedboot-failure-analysis.md`.
  Pendent: garantia de còpia i codis del proveïdor QSEE concret, i 0x10e intern.

- [x] **Precondicions de reserva 0x17bc/0x185c reconstruïdes:** búfer i
  mida no nuls, selecció SCM `(S & 0x8703)==0`, preparació devinfo,
  QSEE i identificador disponibles, op=1/0. Ambdues reserven una pàgina
  via 0x5620 → 0x5364. **Correcció material:** els errors ordinaris del
  helper passen per ASSERT i bucles d'aturada abans del retorn nul;
  esgotament de memòria no demostra arribar al fals èxit del caller.
  El model existent només injecta nul. Detalls en l'anàlisi VerifiedBoot.
