# PROGRESS.md — Investigació del bootloader Redmi 12 5G (SM4450)

**Última actualització:** 2026-11-10
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

- [x] **MiToken 0x1784: longitud i capacitat reconstruïdes amb ASM.**
  No llig capacitat del caller ni valida L nul; 0x2508 comprova solapament.
  Encoder intern exigix 4*ceil(N/3)+1 <= 128; amb B<=15, N<=49,
  eixida <=66 caràcters + NUL. Error de capacitat no accessible sota
  estes precondicions. Corregida reserva ABL: 128, no longitud+1.
  Evidència i límits en `docs/mitoken-length-capacity.md`.

## MiToken +0x18 i contractes ABL — continuació offline 2026-11-09

- Informe nou: [contractes i errors](docs/mitoken-interface-errors.md).
  Contrast de RVA amb bytes dels PE originals i hashes verificats.
- +0x18 → 0x1b4c: eixida de 64 bits sense validació de nul; errors de
  localització/SCM/resposta ometen alliberament del bloc reservat.
  Defecte potencial de recursos, sense repetibilitat ni impacte demostrats.
- Recompte de 32 bits comparat amb índex efectiu de 8 bits: >=256 sense
  match produïx cicle en el model. 250..255 excedixen el rang declarat de
  0x4c4, però no necessàriament la reserva física arredonida a pàgina.
  Valors accessibles del proveïdor encara no confirmats.
- Word local sp+0xc no inicialitzat explícitament; retorn del servici que
  l'ompli ignorat. Ús indeterminat potencial si no l'escriu; pendent proveïdor.
- +0x10 transforma errors interns en 0x50, no en èxit. Correcció històrica:
  ABL 0x57de0 obté token (+8); 0x57e48 verifica (+0x10).
  La reserva d'esta ruta és 128+1; NUL a índex 128 hi cap. Candidat
  descartat sota reserva reeixida, diferent del caller inicial de 128 bytes.
- Quatre proves sintètiques passen; cap execució de firmware ni accés al
  dispositiu. Següent: callers de +0x18, contracte del recompte SCM i
  garantia d'escriptura del word local. Cap explotabilitat demostrada.

## Contractes MiToken +0x18 — revisió des de 2cd75e2

- Verificada taula i GUID amb script reproduïble de lectura de PE:
  `scripts/inspect-mitoken-contract-evidence.py`.
- Tres localitzacions MiToken identificades en ABL: 0x55b60, 0x57d1c,
  0x58550; usen +8/+0x10. Cap caller +0x18 identificat en els tres
  mòduls analitzats; no és prova de codi mort ni absència en altres mòduls.
- Separada resposta SCM local (32 bytes inicialitzats, primer word exigit
  a 1) del búfer extern de política. Resposta local no escrita no implica
  èxit; candidat descartat. No hi ha validació local del recompte ni de
  completitud del búfer. La mida passada 0x4c4 no acota el valor del camp.
- Neteja omesa confirmada al CFG després de reserva reeixida i tres errors;
  activació/acumulació no demostrades. Cicle, lectura fora del rang declarat
  i word indeterminat continuen condicionals a garanties encara desconegudes.
- Informe ampliat: `docs/mitoken-interface-errors.md`. Cinc proves
  sintètiques passen. Fonts dels proveïdors no presents al corpus inspeccionat;
  comparació pública pendent, sense xarxa per mantindre offline.
- Següent: proveïdors GUID 0x9078/0x9098, servei 0x02001401 i límits del
  format de política; ampliar callers en altres mòduls disponibles.
  Cap execució de firmware, token real ni accés al dispositiu.

## Cens ampliat de proveïdors — sessió des de 6b099c0

- `scripts/scan-mitoken-providers.py` verifica el hash conegut d'uefi.elf
  i recorre les seccions PE directes dels dos FV GZIP: 93 PE examinats.
  Manifest públic: `docs/mitoken-provider-census.json`; binaris només en work/.
- GUID 0x9078 present en ChipInfo i altres clients; GUID 0x9098 present
  en ScmDxeLA i altres clients. Proveïdors candidats pendents de confirmar
  amb instal·lació i taules. Cap nou PE amb GUID MiToken excepte MiTokenDxe.
- Límit: cens de seccions PE directes, no tots els formats/volums del paquet;
  absència de GUID literal no prova absència de crides via àlies.
- Següent: reconstrucció Ghidra ChipInfo/ScmDxeLA, sense executar firmware.

## Proveïdors confirmats i contracte SCM parcial

- ChipInfo registra GUID b0760469… amb taula 0xa0e0: +0x48 → 0x16b4,
  delegat DAL +0x88. No inicialitza l'eixida en errors; instal·lació
  condicionada a inicialització DAL correcta. Consum indeterminat continua
  condicional; no assumir handle nul accessible després del registre.
- ScmDxeLA registra GUID 77ed108d… amb dues taules segons consulta segura:
  +0x38 → 0x1858 o 0x3cb4. Variant ARMv8 0x3cb4 → 0x3880 → 0x46b4.
  0x22 declara dos arguments; control <=10 no limita el comptador de política.
- Troballa significativa: el marcador resposta[0]=1 l'escriu ScmDxeLA
  després d'èxit SMC. No acredita per si sol la inicialització/validació
  de la política. Servei efectiu ARMv8 0x42001401; contracte intern TZ pendent.
- Informe MiToken ampliat; hashes, cens i bytes puntuals documentats.
  Dos tests nous de model passen i cinc anteriors també. Sense firmware executat.
- Neteja omesa continua defecte local; altres anomalies condicionals, sense
  nou consumidor +0x18 en el cens de 93 PE. Següent: DAL, variant 0x1858
  i productor TZ; no s'ha establit accessibilitat ni explotabilitat.

## Continuació des de 5b87a841: contracte SCM alternatiu

- 0x1858 comprova punters, llig deu slots de 64 bits i els empaqueta en
  deu words de 32 bits; no usa 0x22 per limitar esta còpia. MiToken prepara
  deu slots en sp+0x38..sp+0x87: lectura fixa dins del descriptor, candidat
  de desbordament del descriptor descartat en este caller.
- Resposta alternativa: quatre words zero-extended després de retorn zero
  de 0x17e8; marcador 1 no sintetitzat com en ARMv8. Cota i completitud de
  política continuen dependents de TZ. Detalls en l'informe de proveïdors.
- DAL: ChipInfo sol·licita device ID 0x0200006f via servei +0xc8;
  protocol de bootstrap ae37b942-457f-4c91-a196-d9669fd347a3 localitzat
  en DALSys i clients. Anàlisi DALSys iniciada; cap execució del firmware.

## DAL resolt i cobertura delimitada

- DALSys bootstrap +8 → 0x1430 retorna taula 0x1e0d0; +0xc8 → 0x22b8
  resol ID 0x0200006f. Factory ChipInfo 0x3208 instal·la handle 0xa390
  amb taula 0x7d78; DAL +0x88 → 0x345c → 0x5248.
- Troballa: getter escriu sempre el word de destí i retorna zero. Descartat
  ús de pila no inicialitzada en la ruta normal amb protocol/handle vàlids.
  Fallada de localització ignorada continua condicional, sense activació.
- Informe `docs/mitoken-provider-contracts.md`: comparació SCM, errors DAL,
  evidència RVA/bytes, reclassificació i cobertura. Els 93 PE són cens GUID,
  no 93 auditories funcionals. LinuxLoader és separat; TZ, altres imatges,
  seccions anidades i imagefv queden fora d'esta cobertura funcional.
- Fonts públiques del servei TZ no disponibles localment; no s'ha fet xarxa.
  Productor TZ i límits del comptador continuen bloquejats per falta de fonts.
- Següents: productor TZ; cobertura pendent; consumidors +0x18. Cap execució
  de firmware, identificador privat llegit ni canvi sobre el dispositiu.

## Cobertura addicional des de main ce7e4f0

- Extractor hash-pinned de tz.mbn, imagefv.elf i tools.fv; originals intactes,
  còpies només en work/. Manifest recursiu en docs/additional-fv-census.json.
- imagefv LZMA resolt amb límit acotat 128 MiB: 64.716.808 bytes, 17 UI/RAW
  de recursos gràfics, cap PE/TE. L'error anterior era límit d'eina.
- tools.fv: 17 PE addicionals, cap GUID MiToken literal en ells; 8 RAW
  sense anàlisi semàntica. Total 110 ocurrències PE censades, no auditories
  funcionals ni necessàriament mòduls únics. ABL separat.
- TZ ara disponible localment i verificat: ELF64 ARM64, 35 program headers.
  Cap literal little-endian 0x02001401/0x42001401; no prova absència del servei.
  Pendent dispatcher i productor real, no continuar atribuint el bloqueig
  a absència del binari. Cap garantia nova sobre comptador o búfer.
- Informe docs/audit-coverage-update.md consolida estat, límits i candidats.
  Notes de vigència afegides als informes històrics per evitar contradiccions.
- 25 proves passen (sis scripts), incloses tres noves de límits LZMA.
  Cap firmware executat, connexió al dispositiu, token ni push.
- Següent: reconstrucció TZ, cobertura restant, consumidors +0x18.
  Fase conservada; auditoria no completa, continuació útil pendent.

## Fase RAW des de 1b03a74

- Pregunta: les 25 seccions RAW excloses del cens executable contenen el
  GUID MiToken? Resultat: cap coincidència literal little-endian.
- 17 RAW d'imagefv tenen signatura BMP; tools conté 7 prefixos textuals
  de comentaris i un RAW buit. No s'han executat ni interpretat com a codi.
- Manifest ampliat amb mida/hash/ruta/prefix de RAW. No es deduïx absència
  global de consumidors +0x18. Cap canvi de classificació de defectes.
- Proves del codec LZMA passen; següent: mapatge i referències TZ en Ghidra.

## Fase TrustZone: lookup del servei SCM

- Hash TZ verificat i mapatge ELF reproduïble: 35 headers, 33 LOAD;
  manifest docs/tz-structure.json. Ghidra import/export completats amb
  advertiments de funcions solapades documentats, sense execució del firmware.
- Ruta 0x1c07798c normalitza 0x42001401 a 0x02001401 i consulta
  0x1c099c20. Traça ARM64/bytes: índex 0x100 supera 0x11 a 0x1c099e2c;
  retorna 1 sense callback. Rebuig verificat en esta consulta concreta.
- No s'ha provat la connexió de l'entrada UEFI amb esta ruta ni descartat
  dispatch alternatiu: indisponibilitat global del servei NO demostrada.
  No es modifiquen encara els candidats MiToken/VerifiedBoot per accessibilitat.
- Informe docs/tz-dispatch-analysis.md, bytes VA/offset i sis tests sintètics
  nous d'ELF/branques. Coincidència immediata 0x1401 en altra funció tracta
  una mida; descartada com identificació automàtica del servei.
- Represa: owner zero 0x1c077840; callers de 0x1c07798c; traducció d'error
  des de 0x1c077bc8. Política i garanties internes continuen desconegudes.

## Fase dispatcher/retorn TZ des de 8a35afa

- 0x1c077840 resolt: consultes owner zero amb low16 0/1 i subconsultes
  acotades; no és fallback MiToken ni usa el lookup de política.
- Caller directe de 0x1c07798c: 0x1c0387fc, precedit de validació/context;
  stub 0x1c1368a0 desa x0..x13. Publicació de l'entrada a 0x1c038288,
  però consumidor EL3 del paquet encara pendent.
- Rebuig 0x02001401 → error local -1 (no -3), resultats netejats,
  retorn de control 0x100. Missatge eixint TZ [1,0x83,-1,0…] →
  SMC 0x1c136914. No confondre x2 d'este missatge amb w0 retornat a UEFI.
- Contracte ScmDxeLA: si rep -1, ARMv8 retorna EFI error 3 i antiga error 7;
  connexió monitor→UEFI encara condicional. Cap impacte sobre autenticació.
- Informe tz-dispatch-analysis.md ampliat, bytes originals i cinc tests nous.
  Següent: registre/consum de l'entrada en monitor i consultes de disponibilitat.

## Fase consulta SCM i reavaluació

- Taula original 0x1c13fb00: 0x02000601 → consulta 0x1c0777b8;
  0x02000602 → retorn 1 sense descriptor. Script hash-pinned i manifest
  docs/tz-scm-probe.json, sense executar ni emular firmware.
- Selector ScmDxeLA 0x4534 comprova només bit 63 de l'estat EFI, no el
  bool de disponibilitat. Descartada inferència ARMv8→servei 0x602 registrat.
  Pot ser sonda de transport deliberada; no es declara bug del selector.
- Corregida adreça d'inicialitzador en informe: 0x1c038154, no 0x1c038114
  (getter de flag). Constructor publica stub i bootstrap envia paquet via
  SMC 0x14690118. Consumidor EL3 dels missatges encara no identificat.
- Informes MiToken/VerifiedBoot reavaluats: cap conseqüència nova demostrada
  sobre autenticació, política, persistència o bloqueig. Candidats condicionals
  conservats; no confondre resultats de lookup, retorn de control i EFI.
- Punt de represa: consumidor monitor de 0x81/0x83 i connexió UEFI↔stub;
  després contracte de política si una ruta real el fa accessible. No repetir
  censos ni atribuir absència global a una consulta concreta que rebutja ID.

## Fase monitor EL3: consumidor identificat

- Els vectors 0x14680800, publicats per dos MSR VBAR_EL3, apunten
  a 0x1c00ec78 per les entrades síncrones inferiors. L'exportació inicial
  no havia desassemblat estes entrades indirectes; s'han descodificat
  explícitament a Ghidra sense executar ni modificar el firmware.
- El dispatcher EL3 0x1c00f9ec distingix SCR_EL3.NS. En món segur,
  0x1c00feec interpreta comandament 1 i subtipus `word1 & 0x7f`.
  Subtipus 1 (0x81) registra entrada +0x58 a 0x1c01c078 i pila +0x60;
  subtipus 3 (0x83) passa per 0x1c00f870. Este copia words2..5 del paquet
  als quatre primers registres del context no segur.
- Error TZ -1 en x2 → x0 guardat no segur; restauració a 0x1c00fd0c
  i ERET a 0x1c00edf0. Resol la frontera del consumidor del paquet,
  sota inicialització/context vàlids i ús d'este monitor. Encara no és
  una observació runtime ni prova d'indisponibilitat global.
- En eixe punt quedaven bytes/taules, encaminament d'entrada i proves;
  resolts en el tancament següent.

### Tancament de la fase EL3

- Enllaç d'entrada reconstruït: NS=1 i ID 0x42001401 passa casos especials
  EL3 → C0/entrada publicada via 0x1c0111a4/0x1c010df0. Contextos
  inicialitzats i condicions del stub continuen precondicions explícites.
- Retorn [1,0x83,-1,0…] → C3.x0=-1 → ERET → ScmDxeLA EFI error 3.
  Neteja condicional de x4..x17 no toca els quatre resultats. La variant
  antiga w0=1 té namespace/petició distinta i no s'ha equiparat.
- Informe docs/tz-monitor-analysis.md i manifest tz-monitor.json amb hash,
  offsets, vectors i 80 entrades estructurals. No són 80 serveis auditats.
  Resoltes les fronteres històriques del consumidor EL3; notes de vigència
  en dispatcher, cobertura i informes MiToken.
- Reavaluació: neteja MiToken omesa continua defecte local confirmat amb
  productor concret d'error condicional; caller +0x18 i acumulació pendents.
  Lectures/bucle de política no s'activen en la ruta rebutjada; altres
  productors continuen desconeguts. VerifiedBoot no canvia.
- Cinc tests sintètics nous de registres/namespace/neteja, sense emulació.
  Següents: caller indirecte MiToken; convenció SCM antiga; altres
  productors carregables locals. No repetir escàners ni inferir absència
  global d'un rebuig local. **41 proves en 10 scripts passen**; extractor
  de dades EL3 validat contra el hash original; git diff --check net.
  Fase documentada per al commit, sense push ni binaris afegits.

## Fase convenció antiga: frontera local acotada

- Pregunta: es traduïx el paquet antic de ScmDxeLA al mateix servei SCM?
  0x45d4..0x45dc envia x2=paquet, w0=1 i w1=SP32. El monitor, amb NS=1,
  conserva els arguments per la ruta normal; ID1 arriba a owner zero.
- 0x1c077840 no llig el paquet: decidix amb ID/x1, i neteja el word x2.
  Si SP32 no satisfà els controls de subconsulta, -1 → retorn al monitor
  → EFI error 7. No s'ha assumit SP real ni selecció efectiva del transport.
- Descartada conversió transparent a 0x02001401 en esta ruta; presència
  de variant antiga no prova un fallback funcional. No és un defecte nou
  demostrat: altres rutes/configuracions i activació continuen pendents.
- Bytes verificats amb hashes PE/TZ en tz-scm-probe.json; ampliats informe
  monitor i contractes. Reutilitzats models owner zero/monitor: 10 casos.
- Punt de represa: consumidor indirecte MiToken +0x18; altres components
  locals/taules carregables; condicions d'inicialització i selecció de
  transport. El productor de política continua sense identificació provada.

## Consumidors +0x18: revisió des de f6672cc

- Pregunta: dependències o obtenció indirecta d'interfícies aporten un caller?
  71 DEPEX vàlides, cap referència MiToken; la del proveïdor és TRUE/END.
  Cens reutilitzat sense repetir cerca GUID als PE. Manifest nou amb traça.
- Nou límit de cobertura corregit: 110 ocurrències PE + 1 TE exterior
  (286.920 bytes, hash 064e33de…); ABL separat. No és auditoria funcional
  de tots els mòduls. Cap consumidor verificat addicional.
- Ebl/QcomBds importats a Ghidra, hashes verificats: accessos +0x18
  seleccionats resolts a ChipInfo/altres GUID; enumeracions genèriques
  desemboquen en ConnectController, no invocació MiToken. Referències de
  la taula del proveïdor confirmen registre, no un segon canal de consum.
- Informe mitoken-consumer-review.md i reviewed-pe-evidence.json: abast,
  bytes, falsos candidats i límits. La cobertura funcional és parcial;
  no es deduïx codi mort ni inaccessibilitat global.
- Decisió: impacte dels candidats +0x18 en espera fins caller/productor nou.
  Neteja local continua defecte confirmat; repetir models no resol l'activació.
- 4 proves DEPEX noves passen. Següent: TE exterior i contractes TzDxeLA,
  després precondicions/inicialització de ScmDxeLA. Sense execució ni xarxa.

## Components pendents: TE i TzDxeLA

- TE exterior: ARM64, tres seccions; mapatge reproduïble amb delta 0xf38,
  entrada VA preferida 0xa700e0b8 / offset 0xc180. Hash/origen verificats.
  Import Ghidra sense loader TE compatible: límit documentat, no semàntica
  inventada. Quatre proves de bounds/mapatge passen; cap GUID MiToken literal.
- Troballa significativa: TzDxeLA 0x3454 consulta el mateix 0x02001401
  sense passar per MiToken; dos búfers 0x4c4 netejats abans de la crida.
  Byte +0xc &0x0a, cap lectura del recompte +0xdc. No és garantia del
  productor ni caller de MiToken +0x18. Model d'inicialització separat.
- Caller directe: 0x1d08 → 0x1e50 només amb error de càrrega SCM +0x28.
  Taula de protocol TzDxeLA +0x18=0x1e74 permet seguir una entrada local.
  Estat de seguretat i consulta de logs condicionen arribar a política.
- Nova neteja omesa: reserva de política no alliberada en error/retorn;
  el free del caller correspon a una petició distinta de 0x38 bytes.
  Defecte local confirmat, repetibilitat/impacte condicionals. Mereix una
  revisió acotada dels callers; no afirmar explotabilitat ni equivalència TZ.
- Informe tzdxe-policy-consumer.md, bytes originals i cobertura actualitzats.
  Següent: inicialització ScmDxeLA i criteris de reobertura dels candidats.

## Inicialització SCM i ShmBridge

- Pregunta: fallar un inicialitzador provoca fallback o impedix publicar SCM?
  CBNZ 0x1508/0x1528 propaga estat no zero abans d'instal·lar protocol;
  cap segon transport. Error d'instal·lació també es propaga. Registre
  auxiliar de logs posterior pot fallar sense revocar el protocol publicat.
- Sonda amb un argument usa registres abans de reservar memòria global;
  descartada dependència circular d'eixe buffer. Error LocateProtocol
  ShmBridge arriba a ASSERT amb espera, no a un retorn ordinari demostrat.
- ShmBridgeDxe revisat funcionalment: +8 neteja la mida demanada inclús
  en reutilització, +0x10 només marca disponible. No traslladar el zero-fill
  a la política MiToken, que usa un allocator diferent. Hash/bytes contrastats.
- SmcInvokeConfig: camps 11/11/10, mida de taules <=81.920 bytes, independent
  del recompte de política. Recurs uefiplat.cfg té SecurityFlag=0xC4 i no
  SmcInvokeConfig; valor efectiu de biblioteca/sobreescriptures no demostrat.
- Neteja tardana de 0x3744: fallada d'objectes o CreateEventEx deixa dues
  reserves ShmBridge sense recuperació local. Callback que les allibera
  encara no registrat; impacte/repetició condicionals, no vulnerabilitat provada.
- Troballa addicional: AllocatePool falla normalment → 0x6b08 retorna NULL
  → 0x4774 prepara EFI error 9 però crida 0x4b7c amb globals encara zero.
  0x57fc accepta índex zero amb nombre de remots per defecte 256 i intenta
  escriure a adreça zero; també hi ha lectura posterior de base nul·la+8.
  Defecte de neteja amb inicialització parcial confirmat sota error ordinari;
  activació real/mapatge/impacte desconeguts. No traslladar-hi l'ASSERT de VB.
  Referències Ghidra i bytes originals comproven estat inicial i salts.
- Informe scm-initialization-analysis.md i manifest de configuració; cap
  reconstrucció EL3 repetida. Següent: consolidar classificació i criteris
  de reobertura; validar proves i conservar la fase en Git.

## Reavaluació i punt de represa

- Classificació consolidada en docs/candidate-triage.md; informes MiToken,
  VerifiedBoot i README apunten a l'estat vigent sense esborrar l'històric.
- MiToken +0x18: cap caller nou després de revisió acotada; en espera
  l'impacte de fuga/cicle/lectures/resposta parcial. Neteja local confirmada.
  ChipInfo normal continua descartat com a productor de word indeterminat.
- VerifiedBoot: l'allocator SCM que retorna NULL no és el seu; es manté
  la barrera ASSERT per error ordinari i el fals èxit condicional.
- Candidats amb més evidència per continuar: neteja SCM amb globals nuls
  després d'AllocatePool error; retenció TzDxeLA amb caller directe; reserves
  ShmBridge no recuperades en errors tardans normals de l'inicialitzador.
  Cap impacte d'autenticació, explotabilitat ni canvi de bloqueig demostrat.
- Cobertura actual: 110 PE + 1 TE, ABL separat; 71 DEPEX; revisió funcional
  parcial i traça de configuració. No equival a auditar tots els executables.
- Següents tres preguntes: conseqüència UEFI de l'accés nul SCM; reentrada
  dels callers TzDxeLA; origen efectiu/sobreescriptures UEFI Config Lib.
  MiToken només es reobri amb caller/productor concret. No repetir EL3.
- Validació final: **54 proves en 13 scripts passen** (13 noves en esta
  continuació). Inspectors de bytes PE i configuració verifiquen hashes;
  git diff --check net. No s'ha executat firmware ni accedit al dispositiu.
- Fases conservades: d432814 (consumidors/DEPEX), ed38433 (TE/TzDxeLA),
  e37b001 (SCM/ShmBridge i neteja parcial); classificació en el commit següent.
  Sense push. Aturada després de les quatre fases acotades, amb preguntes
  concretes per a la represa; no es declaren esgotades totes les fonts locals.

## Auditoria autònoma des d'a566643 — fase 1, contractes SCM

- Punt inicial verificat: `main` net en `a566643`. Abast d'esta sessió:
  seguretat/robustesa estàtica sobre firmware local, sense dispositiu,
  execució de firmware, fallades de memòria induïdes ni mecanismes de bypass.
- DxeCore nou en la revisió funcional: taula Boot Services identifica
  AllocatePool i FreePool. Per a SCM, el primer retorna error 9/out=NULL
  en fallades ordinàries; FreePool(NULL) retorna error 2. El wrapper SCM
  de FreePool faria ASSERT, però la neteja parcial falla abans del seu guard.
- Precisats zero-fill de taules, diferències amb ShmBridge i absència
  d'idempotència garantida. Underflow del comptador remot només si els
  stores nuls finalitzen; no es presenta com execució observada.
- Nou cas concret de recursos: error CreateEventEx posterior a inicialitzar
  objectes omet també FreePool de les taules, a més de les dues reserves
  ShmBridge. No s'afirma acumulació, esgotament ni recuperació global absent.
- ArmCpuDxe: ruta de diagnòstic per defecte acaba en ASSERT/bucle. Mapatge
  de VA zero, CurrentEL i handlers efectius no establits; cap crash concret
  ni canvi de política inferit. No s'ha revisitat el monitor EL3.
- Extractor dirigit reutilitza metadades i hashes existents, sense cens nou;
  evidència ampliada en reviewed-pe-evidence.json i informe SCM.
- Validació d'esta fase: inspector de 8 PE, 5 proves del model SCM i 3
  d'extracció correctes; `git diff --check` net. Següent: diagnòstic/reentrada
  TzDxeLA.

## Auditoria autònoma — fase 2, TzDxeLA

- Fase 1 publicada: `b9aa80f` a origin/main, sense binaris ni dades privades.
- Reconstruïdes portes de diagnòstic: flags de cache no impedixen repetir
  la reserva de política; hi ha quatre BL locals al helper de càrrega,
  però cap freqüència/seqüència real de consumidors provada.
- Errors de càrrega es reduïxen a ID zero i error EFI 1 en el caller
  revisat; el diagnòstic no repara l'estat. Branca xifrada té free lògic;
  política no. Destructor de l'allocator propi omet nodes ocupats.
- Retenció de política: almenys una pàgina de capacitat per reserva reeixida,
  possiblement reutilitzada d'un bloc major. No és prova de noves pàgines
  físiques en cada entrada ni d'una fuga acumulativa observada.
- Nova inconsistència entre components: cache TzDxeLA de 0x82000 conserva
  punter/capacitat després de ShmBridge +0x10. Segona entrada compatible
  no readquirix el node; free repetit duplica comptabilitat i un altre
  client podria rebre el bloc. Defecte local confirmat; alias/corrupció
  efectiva i callers repetits continuen condicionals.
- Quatre proves sintètiques noves passen; models existents SCM i bytes
  verificats. Següent: origen i sobreescriptures de UEFI Config Lib.

## Auditoria autònoma — fase 3, procedència de configuració

- Fase 2 publicada: `91fa1cd`. TE exterior importat estàticament amb
  mapatge de seccions verificat, sense executar ni reubicar firmware.
  Superat el límit històric del loader TE natiu, només per a la ruta config.
- Cadena: FFS `uefiplat.cfg` → parser/taula → biblioteca revisió 0x10002
  → HOB compartit → callback +0x18 SCM. Taules, GUID i 43 instruccions
  seleccionades verificats contra hash/offset originals.
- Recurs: 43 paràmetres per a capacitat 64, SecurityFlag=0xC4,
  SmcInvokeConfig absent també sense distingir majúscules. Ni ChipIDConfig
  ni ChipID_RegAddr locals; la sobreescriptura per chip no crea claus.
- PlatConfigFileName="uefiplatLA.cfg" apareix en informació de versió,
  sense substituir el nom del carregador reconstruït. Nom absent en FFS
  inventariades; no s'afirma absència en tot el paquet o dispositiu.
- Getter de 32 bits usa temporal no inicialitzat si falla la consulta:
  pot escriure un out-word indeterminat o emmascarar l'error original amb
  error 2. Guards de SCM mantenen defaults/omissió de logs, sense fals èxit.
- Frontera del parser errònia amb count==capacitat: una entrada fora de
  taula declarada. Recurs 43/64 no l'activa; no hi ha configuració efectiva
  alternativa ni corrupció física demostrada. Model només d'índexs.
- Informe uefi-configuration-provenance.md, inspector amb hashes i 6
  proves noves; més 4 proves TE i 5 SCM afectades correctes. Següent:
  consolidar classificació/cobertura i revisar evidència de les noves rutes.

## Auditoria autònoma — fase 4, consolidació

- Fase 3 publicada: `d1d8d72`. Matriu vigent actualitzada amb contractes
  DxeCore/ArmCpuDxe, cache TzDxeLA, retenció diagnòstica, procedència de
  configuració i els dos defectes del getter/parser.
- MiToken i VerifiedBoot mantenen els límits anteriors; no hi ha nova
  evidència que active els seus candidats condicionals. No es traslladen
  garanties de zero-fill ni comportament d'errors entre assignadors.
- Cobertura/README i informes històrics enllacen les conclusions actuals.
  TE importat correctament en ConfigTeLayout; ConfigTeAudit/ConfigTe són
  l'intent anterior fallit i no constituïxen evidència funcional.
- Regressió completa: **64 proves en 15 scripts**, totes correctes;
  `git diff --check` net. Només documentació, scripts i metadades
  seleccionades en Git; cap binari propietari ni dada privada afegida.
- Següent tasca factible: seguir la seqüència interna de càrregues de
  TzDxeLA i els callers ja coneguts, motivada pel defecte nou de cache.
  No repetir censos GUID, EL3 ni models criptogràfics.

## Continuació dirigida — callers i propietat TzDxeLA

- Consolidació publicada: `2f67b93`. Nova evidència seguida sense escàners:
  protocol QSEE f148/f2d0 i caller VerifiedBoot 0x1740, GUID coincident.
- 0x2fb0 pot fer dues càrregues de serveis i una d'aplicació dins d'una
  sola entrada; totes poden alliberar la mateixa cache. Flags f558/f55c
  limiten la inicialització diferida; són diferents dels flags diagnòstics.
  Seqüència estàtica demostrada; mides/retorns/activació runtime no provats.
- El comptador ShmBridge inflat no té ús de selecció identificat; el
  problema de propietat es manté independent de la seua comptabilitat.
- Nou defecte concret: 0x2b18 reserva keystore en ShmBridge i passa el
  punter al free privat TzDxeLA, que ignora nodes d'una altra llista.
  També reté el node en camí reeixit; no prova acumulació. No s'ha llegit
  contingut de partició ni extret secrets, només codi de gestió de recursos.
- Inspector de 9 PE i 7 tests TzDxeLA correctes; 9 tests VerifiedBoot i
  6 config continuen correctes (67 proves totals conegudes); diff check net.
- Següent: revisar usos locals ja identificats del getter de configuració
  per delimitar consum de valors indeterminats i documentar rutes protegides.

## Continuació dirigida — consumidors de configuració

- Fase de callers publicada: `7b1fa3f`. Revisats 25 callsites dirigits:
  2 SCM, 5 TzDxeLA, 3 EnvDxe i 15 del TE. No és un cens global.
- SCM/TzDxeLA/EnvDxe comproven estat abans d'usar out; 13/15 consultes
  TE també. Una ignora estat, però EnableMultiThreading=1 existeix en el
  recurs local; el seu consum indeterminat continua condicional.
- Cas DecompressionRequired absent resolt: amb error 14 original, tant
  la branca que escriu out com la que emmascara l'error mantenen default1.
  Descartada eixa cadena concreta de desactivació de descompressió.
- Nou límit numèric: overflow decimal es detecta però el getter ampli
  perd error i retorna zero amb UINT64_MAX; l'estret el rebutja. Claus
  seleccionades no l'activen; falta consumidor efectiu ampli. Sense payload.
- Inspector TE: 75 instruccions; PE: 10 mòduls. 9 proves config correctes,
  més models SCM/TzDxeLA afectats; total conegut 70 en 15 scripts.
- Següent pregunta nova: seguir operació SCM 0x12 que condiciona la
  seqüència QSEE, sense tornar al monitor EL3. Si no aporta estat decidible,
  documentar el límit i passar al mapatge de memòria nul·la UEFI.

## Continuació dirigida — mapa nul i porta SCM de càrrega

- Configuració publicada: `eb5d2d0`. Operació Tz 0x12 resolta al switch
  ARMv8 SCM: índex17, SMC0x3200010a i descriptor0. Estat depén de resposta
  segura; no permet fixar activació de càrregues. No s'ha repetit EL3.
- RAW: 39 rangs alineats, cap cobreix zero; 36 elegibles abans de mescla,
  base mínima0x400000. Constructor usa identitat PA=VA i taules noves
  netejades, i activa SCTLR.M al final reeixit.
- El TE mescla descriptors de RAM abans de MMU; font concreta SMEM0x192.
  Fallback local 0x80000000/0x60000000 no inclou zero, però la selecció i
  dades efectives no són conegudes. Crash SCM continua condicional.
- Inspector TE93 llocs, models inventari/config11 i SCM5 correctes;
  diff check net. Total vigent72 proves en15 scripts.
- En seguir la frontera han aparegut operacions d'índex/capacitat del
  conversor RAM 0xa7023300. Pròxima revisió acotada: contrastar-les amb
  instruccions i models d'índexs; cap generació ni lectura de SMEM real.

## Continuació dirigida — conversió de descriptors RAM

- Mapa/porta SCM publicats: `032dcdf`. Confirmats dos defectes en el TE,
  sense dades runtime: v1 usa índex d'entrada per a tres atributs i índex
  filtrat per al cos; amb entrades prèvies no seleccionades els separa.
  La via alternativa no té eixe desacord concret.
- Les dues vies copien l'entrada33 abans d'aplicar el límit32. Primer
  destí fora de taula comprovat; ASSERT posterior no desfà l'escriptura.
  Cap ordre/recompte/versió SMEM efectiu observat, cap explotabilitat inferida.
- Informe uefi-ram-table-analysis.md, bytes131 llocs TE, quatre proves
  noves d'índexs. No s'han generat descriptors ni payloads.
- Models config11, RAM4 i SCM5 correctes; diff check net. Total conegut
  **76 proves en16 scripts**. Següent: estat parcial de publicació de
  protocols TzDxeLA i si els errors posteriors disposen de rollback local.

## Continuació dirigida — publicació parcial TzDxeLA

- Conversió RAM publicada: `c78744a`. L'última instal·lació de protocol
  Tz 0x1c0c pot retornar EFI_ERROR sense retirar publicacions prèvies.
  Destructor només tracta llista privada; primera fallada reté cache;
  fallada QSEE intermèdia arriba a ASSERT i no implica descàrrega normal.
- DxeCore permet error ordinari de reserva del node de protocol. El
  rollback d'InstallMultiple només cobrix una invocació. StartImage amb
  retorn d'error demana FreePages de la imatge i no retira protocols Tz.
- Callback PE/COFF de descàrrega resolt al TE mitjançant HOB específic;
  tracta atributs/depuració. Referències a imatge alliberada condicionades
  a eixa ruta i èxit de neteja; cap ús posterior o fallada real observats.
- Quatre proves simbòliques de vida de publicació, 11 TzDxeLA totals;
  inspectors ampliats amb bytes i taula/HOB, sense binaris en Git.
  Regressió completa: **80 proves en16 scripts**, totes correctes;
  `git diff --check` net. Següent: revisió de coherència dels informes i
  un punt de represa que separe els límits resolts dels runtime pendents.

## Continuació dirigida — cache i recursos de fitxers

- Publicació parcial publicada: `332be4f`. Creixement de cache fallit
  sí posa punter/capacitat a zero; descartada conservació de cache antiga.
- Caller 0x2630 perd el temporal pool si la cache falla. Lector 0x4a00
  omet Close arrel i Close fitxer en dues eixides de reserva. Fat crea
  arrel de0xb8 per invocació; FV reutilitza arrel. No extrapolar acumulació.
- Errors GetInfo anteriors a dades passen NULL a FreePool i activen
  ASSERT/espera local. Read amb error sí neteja pool vàlid. Recompte de
  lectura curta es perd, però falta condició efectiva que la produïsca.
- Proveïdors Fat/FvSimpleFileSystem extrets pel manifest existent;
  cap cens GUID nou. Set proves de contractes i onze TzDxeLA correctes;
  inspector12 PE correcte i diff check net. Total conegut87 en17 scripts.
- Falta caller concret QSEE+0x20 de fitxers; VerifiedBoot+8 de partició
  no és eixa evidència. Informe tzdxe-file-resource-contracts.md conserva
  punts exactes; continuar amb coherència/validació final dels informes.

## Continuació dirigida — reentrada de notificació TzDxeLA

- Recursos de fitxers publicats: `69cc878`. La primera interfície Tz es
  publica abans de LocateProtocol SCM que emplena f428; +0x18 usa eixe
  global sense guard si arriben els seus arguments/reserves vàlids.
- DxeCore pot despatxar notificacions pendents en RestoreTPL abans que
  retorne InstallMultiple. Reentrada síncrona condicionada a subscriptor
  i TPL; cap subscriptor concret identificat ni concurrència observada.
- 14 proves recursos Tz correctes (3 noves d'ordre/TPL), inspector12 PE
  correcte, diff check net. Total conegut90 en17 scripts. Següent:
  comprovar que els informes no confonguen NULL local amb retorn ordinari
  dels proveïdors, i tancar validació/consolidació amb represa exacta.

## Restricció de contracte — retorns ShmBridge

- Reentrada publicada: `1a1c1fa`. Comprovats tots els errors de reserva
  i configuració de0x2890: ASSERT/espera, no retorn NULL ordinari.
- La pèrdua del temporal de0x2630 és una omissió del CFG, però no hi ha
  productor NULL demostrat per a creixement no nul; la cadena d'esgotament
  queda descartada amb el proveïdor local ordinari. Models/docs corregits.
  El pool SCM0x6acc sí retorna NULL en error: la seua conclusió no canvia.
- Huit proves de fitxers correctes i inspector12 PE ampliat; diff check
  net. Total conegut91 en17 scripts. Resta consolidació final de cobertura,
  verificació completa i publicació del punt de represa exacte.

## Restricció de contingut — ompliment del pool DxeCore

- Contracte ShmBridge publicat: `f9ead78`. En seguir el pool del lector,
  DxeCore0xfb44 aplica ompliment: flag24f71=0x2b, byte24f70=0xAF.
  Bit0x08 actiu i crida0xfe8c cobreixen el payload de reserva. Referències
  locals de les constants només de lectura; cap escriptura identificada.
- La lectura curta continua perdent recompte, però sota estes constants
  la cua copiada és0xAF; retirada inferència de dades antigues indeterminades.
  No generalitzar a caches privades reutilitzades. Nou proves de fitxers
  correctes, inspector12 PE correcte, diff check net. Total92 en17 scripts.

## Tancament verificat — quatre fases i continuació dirigida

- Última fase d'anàlisi publicada: `641b99f`. Les quatre fases inicials
  i les continuacions tenen commits separats, tots publicats sense force-push.
  Registre complet i límits en docs/audit-session-2026-11-10.md.
- Regressió completa final: **92 proves en 17 scripts**, totes correctes
  (54 anteriors +38 afegides). Inspectors:12 PE,137 llocs TE, recurs RAW;
  regeneració sense canvis. `git diff --check a566643 HEAD` net.
- Revisió dels canvis: només Markdown, Python, Java i JSON textuals;
  cap binari, clau privada, token o dada de dispositiu afegits. JSON vàlid
  i enllaços locals resolts. Firmware/exportacions romanen en work/ ignorat.
- No s'ha executat firmware, accedit al mòbil, provocat fallades reals,
  generat payloads o fet recerca externa. Només xarxa Git autoritzada.
- Represa1: subscriptor Tz f108/f250 amb TPL, o caller QSEE+0x20
  31dc→279c→2414→2630; VerifiedBoot+8 no prova ruta de fitxers.
- Represa2: productor local SMEM0x192 per a TE a70230c4, ordre/versió/
  recompte dels conversors a7023300/a70234d4 i conseqüència de mapa SCM.
- Represa3: consumidor biblioteca Config+0x20 a701d728→a701d5b8 o
  escriptura posterior a taula a703c428. No repetir defaults ni censos.
- Projectes/callers/exports exactes en l'informe de tancament. ConfigTeLayout
  és el TE vàlid; ConfigTeAudit és l'intent antic incorrecte. Les preguntes
  pendents no justifiquen afirmar impacte runtime o autenticació eludida.

## Contrast ADB autoritzat — origen i freqüència QSEE, 2026-11-10

- `git pull --ff-only`: base actualitzada de `b24a24f` a `1cfd6cd`.
  Dispositiu USB autoritzat disponible després de superar la restricció
  del socket ADB del sandbox Debian; cap elevació en Android.
- `river`, OS2.0.218.0.VMWEUXM, `green/locked/enforcing`, slot `_b`.
  Init/VINTF identifiquen mtdservice1.3/IMTService; PID/TID correlacionen
  MTService-TEE i QSEECOMAPI dins de mtd. Executable/biblioteca denegats
  a shell; sense circumval·lació ni accés a particions.
- Tres captures main durant207,92s retenen els mateixos30 registres,
  24 de mtd: dos cicles, dues respostes32, dos errors nuls. Cada cicle té
  dealloc abans i després de shutdown; retard shutdown→NULL d'1 o3ms.
  Cap fallada prèvia visible en els tags del cicle. Dos altres E només
  imprimixen identificadors: contingut privat omés, no comptat com fallada.
- Zero registres nous entre captures; no taxa sostinguda de dos errors
  per1,34s. La segona validació real del col·lector, tres captures durant
  62,735s, també té zero registres nous i estat de bloqueig sense canvis.
- Prova addicional només lectura: oem_lock consta en dumpsys-l però
  el seu dump és buit; sys.oem_unlock_allowed=1 no equival a unlocked,
  get_unlock_ability ni autorització Xiaomi. Cap ordre fastboot o reinici.
- Neteja Android redundant compatible, sense caller/ownership confirmats.
  Cap demostració de double-free efectiu, fuga, corrupció, lligam UEFI ni
  desbloqueig. El contracte públic AOSP de shutdown és context separat,
  no prova de la implementació instal·lada. No s'usen logs aliens.
- Analitzador offline i col·lector passiu amb eixida d'agregats per llista
  permesa. Correlació per PID/TID/app-id intern; solapament amb multiconjunts;
  cap identificador, timestamp absolut o missatge cru en la sortida.
- Validació:92 proves anteriors i22 noves correctes,114 en18 scripts.
  Reanàlisi de les captures amb el parser final conserva els agregats.
  JSON, enllaços locals, diff check i revisió d'identificadors correctes;
  captures privades ignorades per Git. Només text documental/codi sintètic.
- Informe: docs/device-qsee-validation-2026-11-10.md; agregats revisats:
  docs/device-qsee-aggregate-2026-11-10.json. La classificació UEFI no canvia.
  Prioritat següent: subscriptor/caller Tz i productor SMEM0x192. Reobrir
  Android QSEE amb caller/retorns o error previ nou, no més còpies del buffer.

## Continuació autònoma — consumidor QSEE i correcció de reachability

- Base `3ec36af`, main net i `git pull --ff-only` sense novetats.
- FeatureEnablerDxe ja inventariat: referència QSEE6058, caller255c
  a+0x20 després de dos intents+8 per etiqueta amb retorn no zero.
  Portes de família116/127/123/130, context i LocateProtocol verificades;
  no s'ha demostrat activació real de la branca en este telèfon.
- Correcció important: Tz3228 força x2=0;2438 selecciona partició.
  La cadena31dc→279c→2414 no arriba a2630 amb eixos arguments.
  Retirada la seua atribució com a caller de fitxers dels informes vigents.
- Per a fitxers cal primera taula f250+20 amb x2 no nul o f250+38=27a8.
  Cap consumidor exterior ni subscriptor f250/TPL verificat. FeatureEnabler
  usa QSEE, publicat després de preparar SCM; no prova reentrada prematura.
- Inspector13 PE ampliat amb bytes/taules;18 tests de recursos i9 de fitxers
  correctes. Quatre tests nous de routing/portes; total conegut118 en18 scripts.
  `git diff --check` net; només documentació, bytes seleccionats i model simbòlic.
- ADB inicial de plataforma (captura privada): SoC568, SM4450/parrot,
  build coincident, green/locked. soc_id no és el ChipFamily UEFI.
  Seguiment SMEM/diagnòstic de memòria en la fase següent; cap estímul QSEE.

## Continuació autònoma — productor XBL de SMEM0x192

- Fase Tz publicada: `a0f2df0`. Productor RAM trobat en el tercer ELF
  consecutiu de xbl_s.melf local, hash verificat. Reutilitzat Providers;
  cap reconstrucció FV ni cens global repetits. Extractor existent ampliat
  amb selecció explícita XBL; CLI real executada correctament.
- `1481bf6c → 1485c584`, fase boot_update_ram_partition_table. Interfície
  0x52+8 governa entrada; taula/getter/global/inicialitzador identificats.
  Selectorzero depén de consulta0x51 i bits MMIO; cap lectura MMIO al telèfon.
- Reserva SMEM0x192 de0x918: header0x18, stride0x48,32 descriptors.
  Constructor completat escriu versió3 i signatures esperades pel TE.
  DDR en ordre de getter, després tres appends; cadascun comprova capacitat
  abans dels stores. Construcció reeixida requerix <=29 entrades DDR.
- Actualitzador1485c938 retalla/elimina/dividix exclusions; amb count
  intacte0..32 el guard exterior conserva límit32. El guard interior tardà
  no prova desbordament sota eixa precondició. Altres aritmètics no auditats.
- Hipòtesis RAM restringides: esta cadena ordinària no activa v1 ni entrada33
  del TE. Defectes locals del consumidor conservats, activació per altres
  writers/estat corrupte no provada. Mapa nul/impacte SCM continuen condicionals.
- ADB real: soc_id568/familySnapdragon, SM4450/parrot i build coincident,
  green/locked. Nodes memory i driver qcom-smem presents; lectura dels cells
  i memory/reg denegada. exec-out retorna estat host0 amb text d’error:
  descartat com a dades. Debugfs smem/qcom_smem no disponibles. Cap bypass,
  reinici, fastboot, escriptura o nova captura repetitiva QSEE.
- Inspector nou:3 ELF,72 instruccions seleccionades i literals. Cinc tests
  nous de layout ELF i cinc de comptes RAM. Regressió completa **128 proves
  en19 scripts**, totes correctes; inspector13 PE correcte; diff check net.
- Informe/evidència: docs/xbl-ram-producer-analysis.md i JSON associat.
  Originals ADB exclusivament en work/platform-diagnostics-2026-11-10/,
  ignorat i privat. Revisió de publicació limitada a text/codi/metadades.
- Cap evidència nova de desbloqueig. Següent treball útil: caller/subscriptor
  f250/TPL concret, DDR/exclusions efectives o un consumidor de configuració
  ampli encara no revisat. No repetir QSEE Android sense esdeveniment nou.

## Contrast final — ChipFamily observat i porta FeatureEnabler

- Fase productor XBL publicada: `0439f35`. Nova pregunta concreta:
  la família que governa FeatureEnabler es pot contrastar en Android?
- Cadena local resolta: ChipInfo+30→162c→DAL+70→33e4→51f8→a41c;
  inicialitzador copia SMEM0x89+6c. XBL productor del camp també identificat,
  amb taula de8 famílies i fila (11,16,141,568) compatible amb SM_CLARENCE.
- soc_id568 per si sol no demostra família141: inicialitzador usa cerques
  distintes per família i part-id. No s’han llegit MMIO ni fusibles al mòbil.
- ADB només lectura de /sys/devices/soc0/chip_family retorna0x8d=141.
  Una consulta; interpretació hexadecimal corregida offline sense repetir-la.
  Original privat ignorat. No és el family=Snapdragon genèric ni un serial.
- 141 no està entre116/127/123/130: si ChipInfo UEFI veu el mateix camp
  intacte, no entra a la branca QSEE FeatureEnabler. No es declara traça
  UEFI real; driver vendor Android i imatges arrancades no atestats.
- Informe: docs/featureenabler-chip-family.md. Inspector14 PE; XBL afig28
  llocs ChipInfo als72 RAM/mode.19 tests Tz i5 layout correctes; total129
  en19 scripts (regressió completa128 prèvia més el cas nou). Diff check net.
- No hi ha evidència nova de desbloqueig. Esta dada restringix activació,
  no justifica fastboot. Continuar amb caller/subscriptor f250 real, fonts
  DDR/exclusions o consumidor Config+20. QSEE Android continua sense
  pregunta nova per a repetir captures. Contrast web primari intentat
  sense contingut accessible; cap conclusió depén d’una font no verificada.

## Fonts DDR i porta d'exclusions XBL — continuació des de7257cbc

- Resoltes les taules locals de les interfícies0x1c i0x1b, reutilitzant
  Providers i el mateix ELF. L'inspector afig50 instruccions i12 paraules
  seleccionades; no s'han repetit censos ni reconstruccions.
- Getter0x1c+20 exigeix global/context i flag d'inicialització. El setter
  publica count/punters; la construcció SMEM pressuposa eixa inicialització.
  No hi ha un error runtime o ownership complet demostrat.
- Font DDR identificada: estructura148ee6f0, count+c8, rangs stride28,
  base+f8 i mida+100 convertida aMiB. Llista intermèdia conserva ordre;
  falten tots els writers, límit de count i valors efectius.
- Exclusions0x1b+d8: bit2 del byte+250 de metadades DDR governa entrada.
  Via ordinària sense eixe bit retorna count0; amb les condicions normals
  de rang/contigüitat torna count1. El nom MTE del firmware no prova el
  valor del camp a partir dels HWCAP d'Android.
- Es mantenen les restriccions de v1/entrada33. Cap prova malformada,
  lectura MMIO, activació UEFI, root o desbloqueig. Informe i manifest:
  docs/xbl-ram-producer-analysis.md i docs/xbl-ram-producer-evidence.json.
- Inspector ampliat correcte i cinc tests de layout dins de la regressió
  completa de la sessió,142 proves en20 scripts; diff check net. La nova
  fase kernel aporta13 proves de límits/privacitat, documentada a continuació.

## Root temporal i kernel Android — evidència concreta de compilació

- Base7257cbc actualitzada i neta; fonts públiques consultades a2026-11-10.
  Informe nou: [viabilitat de root temporal](docs/android-temporary-root-feasibility.md),
  amb19 CVE, precondicions, correccions, riscos i límits. Cap exploit executat.
- Identitat forta: boot.img del paquet amb hash conegut conté exactament
  l'Image GKI oficial del build15159037. Commit ACK complet730d06ec05ff5dc34389ff99ea4009411efba5e6,
  tagandroid12-5.10-2025-12_r3; IKCONFIG igual al /proc/config.gz real.
  System.map oficial i hashes de funcions seleccionades contrastats.
  No és atestació de memòria viva, partició activa o mòduls vendor.
- CVE-2026-43499: remove_waiter continua usant current; font exacta i
  desassemblatge del paquet ho confirmen. CVE-2026-64560: codi timer antic
  i absència del retry/ordenació de la correcció. Defectes estàtics
  prioritzables, sense reproducció de corrupció, explotabilitat o root.
- Descartats per codi/config: Dirty Pipe, CVE-2023-20938/2163,
  CVE-2024-1086, CVE-2025-38352, CVE-2026-31431/58825/23184.
  No descartar58942 només per ser5.10/4K: hi ha backport de migració de
  pàgina; equivalència del defecte i flag runtime encara pendents.
- Qualcomm57545/57554: plataforma inclosa, però mòdul/camí i pegats Xiaomi
  pendents. FixKGSL llegit; FastRPC limitat perHTTP429. Els altres candidats
  vendor no tenen evidència suficient. SPLvendor antic no és prova de bug.
- ADB real:32 consultes passives, propietats seleccionades, config,
  domini/capacitats, Features i sysctls. Enforcing, green/locked; UID2000
  sense capacitats efectives. BPFsysctl0/perf−1 no proven accessibilitat.
  Sysctls denegats queden desconeguts, no interpretats com desactivats.
- Probe propi ARM64/PIE amb NDKr30:4 execucions benignes, sense fallades,
  una pàgina RW; ASLR variable en imatge/pila/mmap, HWCAP PAC/BTI/MTE zero.
  Config confirma CFI/SCS/PAN/KASLR compilats, no tots els modes runtime.
  Executable temporal propi eliminat; adreces només en originals privats.
- Sis consultes addicionals no completades per desconnexió ADB. Treball
  continuat offline. Col·lector --scope followup preparat per als nodes
  GPU/FastRPC, mòduls i flag pgsize_migration; versió final no executada.
- Inspector offline fixa identitat i11 comprovacions de codi; rebutja
  fonts/hashes inesperats.13 tests nous de privacitat, límits i parsers.
  Regressió completa: **142 proves en20 scripts**, totes correctes.
  Inspectors kernel/XBL, JSON, enllaços i git diff --check correctes.
  Revisió sense secrets, UUID o adreces runtime en fitxers publicables;
  captures originals només en work/kernel-audit-2026-11-10/, privat/ignorat.
- La línia root mereix seguiment estàtic; cap camí operatiu de root o
  desbloqueig demostrat. No s'ha usat fastboot, reinici, instrumentació
  invasiva, canvis de seguretat o particions. Prioritats: completar
  contrast dels dos fixes GKI; identificar mòduls/portes vendor només
  lectura; seguir writers DDR o un caller Tz/Config concret amb dada nova.
