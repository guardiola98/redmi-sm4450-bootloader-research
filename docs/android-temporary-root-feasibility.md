# Viabilitat de root temporal Android — Redmi 12 5G

Data de tall: **2026-11-10**. Firmware `OS2.0.218.0.VMWEUXM`,
`river`, SM4450/parrot. Base de treball `7257cbc`, `main` net i
`git pull --ff-only` actualitzat abans de començar.

**La línia mereix seguiment estàtic:** hi ha evidència concreta de codi
sense corregir per a **CVE-2026-43499** i **CVE-2026-64560** en el kernel
del paquet identificat. No s'ha obtingut root, reproduït una corrupció
ni demostrat una cadena d'elevació funcional. Cap resultat aporta una
via verificada de desbloqueig del bootloader.

La revisió cobrix 19 CVE seleccionades per mecanisme, precondicions i
proximitat al dispositiu, els butlletins actuals i els pegats accessibles.
No és una certificació d'absència de la resta de vulnerabilitats del
firmware. Els [agregats i hashes](android-kernel-evidence.json) són
reproduïbles amb l'[inspector offline](../scripts/inspect-android-kernel.py).
No s'han descarregat ni executat exploits. Les captures, fonts completes,
firmware i desassemblatges queden exclusivament en `work/`, ignorat.

## Identitat del kernel: més enllà de la cadena de versió

ADB ha retornat exactament:

`5.10.246-android12-9-00012-g730d06ec05ff-ab15159037`

El [commit ACK complet](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6)
és `730d06ec05ff5dc34389ff99ea4009411efba5e6`, del 7 d'abril de2026.
El [tag oficial](https://android.googlesource.com/kernel/common/+/refs/tags/android12-5.10-2025-12_r3)
resol al mateix commit. La [publicació GKI Android12/5.10](https://source.android.com/docs/core/architecture/kernel/gki-android12-5_10-release-builds)
identifica la branca de manteniment `android12-5.10-2025-12`, el tag
`android12-5.10-2025-12_r3` i el build **15159037**.
El nom android12 és la cohort GKI/ABI, no una lectura de la versió Android
que executa el telèfon. La configuració indica Clang12.0.5/r416183b.
El NDKr30 emprat per al nostre probe és una eina diferent.

S'ha extret únicament `boot.img` del paquet local ja inventariat, amb
hash verificat contra `bootchain-local.json`. Cap lectura de particions.
La capçalera bootv4 situa un Image ARM64 sense compressió de46.927.500
bytes a offset4096. El seu contingut és **idèntic byte a byte** a
l'[Image oficial del build](https://ci.android.com/builds/submitted/15159037/kernel_aarch64/latest/raw/Image),
SHA-256 `ab8958caf17a31b0a532aac0ecff2dda021ea4cfd6bbf0070098d04fd58569e7`.

L'IKCONFIG incorporat és també idèntic a `/proc/config.gz` descomprimit
del dispositiu. El [System.map del mateix build](https://ci.android.com/builds/submitted/15159037/kernel_aarch64/latest/raw/System.map)
permet localitzar les funcions seleccionades; els seus hashes consten
al manifest. El desassemblatge de `remove_waiter` confirma l'ús de
`current` obtingut de SP_EL0 en els accessos revisats. No s'ha deduït el
pegat absent simplement del sufix `5.10.246`.

**Límit:** identitat del paquet i coincidència de configuració/versió en
Android no són una atestació de memòria viva, de cada mòdul vendor ni de
la partició activa. No s'ha llegit memòria kernel o el codi carregat en
runtime. El codi comú correspon al GKI oficial; la procedència/revisió
exacta dels mòduls Qualcomm continua pendent i no s'ha substituït per
una branca MiCode d'una altra compilació.

## Què s'ha consultat realment en Android

Una passada de **32 consultes fixes**: connexió, `uname -r/-v`,
`/proc/config.gz`, només les línies Features de cpuinfo, SELinux,
domini i camps seleccionats de l'estat del procés shell, metadades de
nodes concrets, 11 propietats individuals i 12 sysctls. El
[col·lector reproduïble](../scripts/collect-kernel-readonly.py) formula
la pregunta abans de cada consulta i guarda originals en un directori
nou privat, ignorat. No recopila números de sèrie ni logs.

| Pregunta | Resultat real | Límit de la conclusió |
| --- | --- | --- |
| Estat d'arrancada declarat | `green`, flash.locked1, vbmeta `locked`, secureboot1 | Propietats declarades; no lectura de fusibles ni atestació independent. |
| Estat SELinux i credencials | Enforcing, `u:r:shell:s0`, UID/EUID2000; CapEff/CapPrm/CapInh zero | El domini shell no és el sandbox de qualsevol app. |
| Seccomp | Zero en el fill shell i el nostre executable | No implica seccomp desactivat en zygote/apps/serveis. CONFIG_SECCOMP/FILTER=y. |
| Configuració kernel | `/proc/config.gz` accessible i igual a IKCONFIG del paquet | Confirma compilació, no totes les decisions runtime. |
| Polítiques BPF/perf | unprivileged_bpf_disabled=0, perf_event_paranoid=-1 | No prova autorització SELinux, disponibilitat de cada operació ni una vulnerabilitat. Cap programa BPF o event perf carregat. |
| ASLR/kptr/dmesg i altres sysctls | randomize_va_space, kptr_restrict, dmesg_restrict, modules_disabled, max_user_namespaces i mmap_rnd_bits/compat: denegats | Valor desconegut; una denegació no és un zero. |
| Yama/userns/io_uring switches | Els paths consultats no existixen | Absència del node no equival a desactivar el subsistema; IO_URING=y i USER_NS=n es coneixen per config. |
| Nodes de drivers | kgsl-3d0/renderD128 presents amb mode0666; qseecom0660; dma_heap/system0444; ion absent | Només `ls -lZ`: cap open/ioctl. Mode DAC no implica permís del domini SELinux. |

A més, s'ha compilat [un executable ARM64 propi](../scripts/android-mitigation-probe.c)
amb NDKr30, PIE, `-Wall -Wextra -Werror`, i s'ha executat **quatre vegades**.
Només consulta auxv/prctl/UID, reserva una pàgina anònima RW i l'allibera.
No hi ha carrera, accés a servei privilegiat, controlador o fallada
provocada. El binari temporal propi s'ha eliminat després de les proves.
Cada classe d'adreça observada —imatge, pila i mmap— varia en les quatre
execucions; només se'n publiquen els recomptes. No és una estimació de
bits d'entropia ni un test de KASLR. Pàgina4096; PACA/PACG/BTI/MTE=0
als HWCAP consultats en els quatre processos.

Les sis consultes posteriors de model GPU, revisió, noms/fitxers de
mòduls, nodes FastRPC i propietat de pàgina **no s'han pogut executar en
el dispositiu**: ADB ja retornava absència de dispositiu. No són resultats
negatius d'eixos components. S'ha continuat offline sense repetir
captures QSEE ni intentar reconnectar per reinici. No s'han repetit els
laboratoris SIGSEGV/ASan anteriors.

## Proteccions: compilació, observació i incògnites

| Mecanisme | Evidència en esta compilació | Què falta |
| --- | --- | --- |
| ASLR d'usuari | Variació de PIE/pila/mmap observada en4 execucions pròpies | Entropia, valor de randomize_va_space i tots els altres processos. |
| KASLR | CONFIG_RANDOMIZE_BASE=y | Base runtime, entropia i possibles opcions d'arrancada no llegides. |
| PAN / SW PAN / UAO | CONFIG_ARM64_PAN, SW_TTBR0_PAN i UAO=y | Selecció hardware/software i estat efectiu dels registres no observats. |
| PXN/UXN i W^X | STRICT_KERNEL_RWX/STRICT_MODULE_RWX=y; separació EL0/EL1 prevista pel codi ARM64 | No s'han inspeccionat PTE ni registres de control; no s'etiqueta PXN runtime com confirmat. |
| CFI i SCS | CFI_CLANG=y, CFI_PERMISSIVE=n, SHADOW_CALL_STACK=y; instrumentació SCS visible en funció revisada | No es certifica cada mòdul vendor o cobertura total. És CFI de Clang d'este arbre, no una inferència de KCFI modern. |
| PAC / BTI / MTE | Configuracions ARM64 corresponents=y; HWCAPs corresponents zero en EL0 | No disponibles per als processos provats; no és una lectura directa dels registres hardware ni prova de cada mode kernel/firmware. Una instrucció PAC al binari pot actuar com NOP. |
| Enduriment de memòria | STACKPROTECTOR_STRONG, VMAP_STACK, SLAB_FREELIST_RANDOM/HARDENED, HARDENED_USERCOPY=y | No s'ha intentat eludir cap mecanisme. FORTIFY_SOURCE no figura com a valor: desconegut. |
| Càrrega de mòduls | MODULE_SIG=n; procés provat sense capacitats efectives | No implica poder carregar mòduls: intervenen permisos, SELinux i particions verificades. |
| Namespaces i nftables | USER_NS=n, NF_TABLES=n | NET_NS=y no dona CAP_NET_ADMIN al shell. |

La semàntica dels [HWCAP ARM64](https://www.kernel.org/doc/html/v5.16/arm64/elf_hwcaps.html)
és disponibilitat anunciada a EL0; no s'ha substituït per una fitxa
comercial de CPU. Les garanties i abast de
[CFI al kernel Android](https://source.android.com/docs/security/test/kcfi)
no impliquen que tota corrupció de dades quede impedida.

## Pegats Android i vendor

Lectures independents: Android **2026-10-01**, vendor **2026-04-05**.
Són declaracions de nivell de pegats de capes diferents, no llistes de
commits ni proves de la presència de cada fix. El
[butlletí Android d'octubre](https://source.android.com/docs/security/bulletin/2026/2026-10-01)
definix què exigix eixe SPL i distingix els avisos addicionals dels
fabricants. No es pot inferir que qualsevol CVE posterior a abril afecte
el dispositiu, ni que l'SPL Android d'octubre cobrisca totes les correccions
Qualcomm publicades després. Els dos candidats prioritaris apareixen al
[butlletí Android de novembre](https://source.android.com/docs/security/bulletin/2026/2026-11-01),
posterior a l'SPL Android declarat.

## Taula de candidats del kernel comú

Estats referits a la viabilitat d'una via de root temporal **en este
Redmi**: **Compatible confirmat**, **Potencialment compatible, pendent
de verificar**, **No compatible**, **Informació insuficient**.
No hi ha cap entrada Compatible confirmat com a via de root. Els dos
primers sí tenen **defecte confirmat estàticament en el paquet**;
l'elevació real és una qüestió diferent. «No compatible» descarta eixa
CVE concreta sota la identitat/configuració establides, no tot el component.

Els rangs són upstream/CNA, subjectes a backports; la columna de codi i
configuració governa la classificació. Totes les proves executades ací
són passives o de procés propi benigne. El risc indicat és el d'intentar
activar el defecte, cosa que no s'ha fet.

| CVE / component | Versions o fix de referència | Precondicions locals | Evidència del Redmi i estat | Risc d'activació |
| --- | --- | --- | --- | --- |
| [CVE-2026-43499](https://www.cve.org/CVERecord?id=CVE-2026-43499), rtmutex/futex PI | Introduït2.6.39; branca5.10 corregida en5.10.261; fix `f3fa3424bceb` | Futex PI/proxy rollback, tasca del waiter diferent de current; operacions sobre sincronització pròpia, sense privilegi especial de configuració | FUTEX/PI/RT_MUTEXES=y; `remove_waiter` encara opera sobre current en font i binari. **Potencialment compatible, pendent de verificar**, prioritat1. No carrera/root provats. | UAF kernel, panic/bloqueig i pèrdua de dades no guardades; fiabilitat desconeguda. |
| [CVE-2026-64560](https://www.cve.org/CVERecord?id=CVE-2026-64560), POSIX CPU timers | CNA: des de5.7, corregit5.10.262; família de fix `920f893f735e` | Timers de procés i canvi de líder per exec concurrent; procés local sense privilegis especials, temporització específica | POSIX_TIMERS=y; es conserva lookup/lock antic i falten retry/ordenació de la correcció. **Potencialment compatible, pendent de verificar**, prioritat2. | UAF kernel, carrera no determinista, crash i possible pèrdua de dades. |
| [CVE-2026-58942](https://www.cve.org/CVERecord?id=CVE-2026-58942), fault-around/ELF padding | CNA «Android kernel», sense rang5.10 precís; fix `27d9c79c71ce` i `019d909caeb8` | VMA amb padding, fault-around i funcionalitat de migració de pàgina activa | Hi ha backport pgsize_migration fins i tot en4K; algoritme antic diferent del diff publicat. **Informació insuficient**: no s'ha demostrat equivalència del defecte ni flag runtime. No descartar pel número5.10 o pàgina4K. | Corrupció/UAF o crash kernel segons avís; no provar mappings límit al mòbil. |
| [CVE-2026-43284](https://www.cve.org/CVERecord?id=CVE-2026-43284), XFRM/ESP | Des de4.11, branca5.10 corregida5.10.255 | Camí ESP amb fragments compartits; cal estat/política IPsec i accés al flux pertinent | XFRM_USER/INET_ESP=y, però USER_NS=n i CapEff0. Sense prova de configuració accessible o SA aplicable, ni verificació completa del fix. **Informació insuficient**, baixa prioritat per a shell sense privilegis. | Corrupció de memòria/dades i interrupció de xarxa; no configurar SA ni generar estímuls. |
| [CVE-2025-38352](https://www.cve.org/CVERecord?id=CVE-2025-38352), CPU timers/exit | Des de2.6.36; corregit5.10.239 | Carrera de timers amb eixida en implementació afectada | `run_posix_cpu_timers` conté el guard `tsk->exit_state` de la correcció. **No compatible**. No confondre amb64560. | Carrera kernel si faltara el pegat; cap valor de repetir-la ací. |
| [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431), AF_ALG AEAD | Des de4.14; corregit5.10.254, reversió del camí in-place | Interface crypto d'usuari AEAD compilada i accessible | CONFIG_CRYPTO_USER_API_AEAD=n en live/package. **No compatible**: component requerit no compilat; el rang5.10.246 és insuficient. | Pot alterar pàgines/dades en sistemes afectats; cap socket AF_ALG creat. |
| [CVE-2024-1086](https://www.cve.org/CVERecord?id=CVE-2024-1086), nf_tables | CNA3.15..<6.8 abans del fix `f342de4e2f33`; no usar el rang sense backports | nftables i capacitat de configurar regles; userns és una ruta habitual per obtindre eixe context | NF_TABLES=n i USER_NS=n. **No compatible** en este kernel. | Double-free/corrupció kernel; no configurar xarxes ni regles. |
| [CVE-2023-2163](https://www.cve.org/CVERecord?id=CVE-2023-2163), verificador eBPF | Linux>=5.4 abans del fix `71b547f56124` o backport equivalent | Poder carregar un programa BPF en el verificador afectat | Correcció de propagació de precisió per als dos registres present en `backtrack_insn`. **No compatible**. sysctl0 no desfà el pegat ni prova accés SELinux. | Corrupció kernel si vulnerable; cap programa BPF carregat. |
| [CVE-2023-20938](https://www.cve.org/CVERecord?id=CVE-2023-20938), Binder | Android kernel abans de la sèrie publicada en ASB2023-02 | Transaccions Binder amb objectes/buffers i lifecycle afectats, subjectes a política d'accés | Arquitectura de còpia diferida, lectures des del sender i guards FDA de la sèrie presents. **No compatible** amb eixa implementació anterior. | UAF/kernel crash; no transaccions malformades ni serveis privilegiats. |
| [CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847), Dirty Pipe | Via coneguda des de5.8; corregit5.10.102 | Pipe/splice amb flags heretats incorrectament i pàgina de fitxer | `buf->flags=0` en les dues funcions rellevants, `copy_page_to_iter_pipe` i `push_pipe`. **No compatible** per codi, no per data. | Modificació de dades/page cache; no executar cap variant. |
| [CVE-2026-58825](https://www.cve.org/CVERecord?id=CVE-2026-58825), comptabilitat DMA-BUF en fork | Android kernel amb la funcionalitat afectada; fix `efe16a3021b9` / `009c5006c969` | Compartició/desassociació de files_struct i comptabilitat dmabuf_info específica | `kernel/fork.c` d'este ACK no conté dmabuf_info; no confondre amb DMABUF_SYSFS_STATS. **No compatible** amb esta ruta concreta. | UAF kernel si la funcionalitat existira; cap unshare/fuzzing. |
| [CVE-2026-23184](https://www.cve.org/CVERecord?id=CVE-2026-23184), Binder netlink | Introduït6.18; corregit6.18.10/6.19 | Implementació binder_netlink_report | Funció absent del Binder concret, no sols rang més nou. **No compatible**; avís DoS, no prova de root. | DoS en versions afectades. |

### Evidència més forta: dues correccions absents

**43499:** el [backport5.10](https://git.kernel.org/stable/c/f3fa3424bceb128d2be4b3745506b22844b87db7)
canvia la tasca sobre la qual es bloqueja i neteja l'estat del waiter.
En l'[arbre exacte](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/locking/rtmutex.c),
`remove_waiter` seguix usant current; la propagació final usa també
current. El binari del paquet concorda. L'avís i la
[fitxa NVD consultada](https://nvd.nist.gov/vuln/detail/CVE-2026-43499)
descriuen el desajust de tasca i el punter pendent; l'SPL sol no ha sigut
la prova. La sèrie Android de novembre inclou també el
[guard de waiter encolat](https://android.googlesource.com/kernel/common/+/5339d13d8b945cd5841d0e70728ee67474ea74f7):
cal revisar la correcció completa, no una substitució textual aïllada.

**64560:** contrast amb la
[correcció ACK](https://android.googlesource.com/kernel/common/+/585f2c9c9560f7e0dadafbba251183cea83d9dc4)
en tres fitxers: `posix_cpu_timer_del` conserva el camí antic davant
sighand nul, no hi ha `timer_lock_sighand`, i `__exit_signal` conserva
l'assignació sense release. El canvi requerix reintentar el lookup i
l'ordenació corresponent; el guard de38352 és una correcció diferent.
Les funcions timer_set/rearm i el camí complet d'exec necessiten una
revisió de reachability més extensa abans d'una afirmació d'explotabilitat.

No s'ha mesurat una taxa d'èxit ni creat un primitiu de lectura/escriptura
kernel. CFI, freelist hardening, KASLR, SELinux i el context de syscall
poden afectar el pas d'un defecte a root. No es proposa una seqüència
per eludir-los ni s'assumix que UID0 anul·le totes eixes fronteres.

### Dos descartaments que exigixen mirar el codi

La [sèrie Binder publicada](https://source.android.com/docs/security/bulletin/2023-02-01)
inclou sis commits. S'han inspeccionat les correccions de còpia des de
l'usuari, còpia diferida i FDA, no sols un guard d'alineació amb nom
semblant. El verificador registra els trets seleccionats de la sèrie.

Per contra, no es descarta58942 amb «és5.10 i4K»: l'[arbre de migració](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/mm/pgsize_migration.c)
activa per defecte una static key en4K/64bit i té gates de context/linker.
El `do_fault_around` concret usa un càlcul anterior, diferent del patch
publicat. Falta comparar semànticament els límits i observar el flag
`/sys/kernel/mm/pgsize_migration/enabled`. No s'ha llegit eixe node encara.

## Candidats Qualcomm: plataforma compatible no és driver vulnerable

S'han consultat els registres CNA de Qualcomm i els butlletins de
[juny2025](https://docs.qualcomm.com/securitybulletin/june-2025-bulletin.html),
[març2026](https://docs.qualcomm.com/securitybulletin/march-2026-bulletin.html)
i [octubre2026](https://docs.qualcomm.com/securitybulletin/october-2026-bulletin.html).
Les llistes usen **Snapdragon 4 Gen 2 Mobile Platform**, no sempre el
literal SM4450. No proporcionen una versió de mòdul Xiaomi corregida
per a este build; els rangs numèrics de firmware continuen desconeguts.

| CVE / component | Abast i precondicions | Correcció/build concret | Estat i risc |
| --- | --- | --- | --- |
| [2026-57545](https://www.cve.org/CVERecord?id=CVE-2026-57545), KGSL/hwsched LPAC | 4Gen2 consta en CNA. Requerix camí LPAC i tipus drawobj afectat; node accessible segons política | [Fix msm5.10](https://git.codelinaro.org/clo/la/kernel/msm-5.10/-/commit/874311dc075047c51c9231e3de1bae0a7677b3b7) llegit: falta comprovació `is_cmdobj` en `get_active_cmdobj_lpac`. No s'ha identificat esta funció ni suport LPAC en el mòdul instal·lat | **Potencialment compatible, pendent de verificar**. Llista de plataforma i node existent són insuficients. Risc de GPU hang/kernel panic/corrupció; cap ioctl. |
| [2026-57554](https://www.cve.org/CVERecord?id=CVE-2026-57554), FastRPC/DSP | 4Gen2 consta. Invocacions asíncrones amb dades de comptadors compartides; cal accés al domini/node pertinent | Qualcomm enllaça fix msm5.10 `a065d4bacdae`; descàrrega del diff i alternativaDSP limitades per HTTP429. Nodes/mòdul del Redmi encara desconeguts per desconnexió | **Potencialment compatible, pendent de verificar**, confiança inferior als dos bugs GKI. Risc UAF, crash kernel/DSP i pèrdua de dades; no invocacions. |
| [2026-21385](https://www.cve.org/CVERecord?id=CVE-2026-21385), Graphics/alineació de reserva | 4Gen2 consta; operacions del controlador amb aritmètic afectat, accés local | Butlletí març2026 anterior a SPLvendor; revisió/correcció del binari Xiaomi no verificades | **Informació insuficient**; prioritat baixa fins a disposar del driver. Risc corrupció/crash; no prova d'alineacions límit. |
| [2025-27038](https://www.cve.org/CVERecord?id=CVE-2025-27038), Adreno/renderització | 4Gen2 consta; camí gràfic descrit en Chrome, versió de driver determinant | Avís juny2025 anterior als SPL declarats; no s'ha demostrat absència del fix | **Informació insuficient**. No equival a una LPE kernel ni root; crash/corrupció GPU possibles en component vulnerable. |
| [2025-21479](https://www.cve.org/CVERecord?id=CVE-2025-21479) i [21480](https://www.cve.org/CVERecord?id=CVE-2025-21480), GPU micronode | 4Gen2 no figura en les llistes CNA consultades; comandos i firmware específics | Cap correspondència de micronode/revisió amb este Redmi; no extrapolar d'un altre Adreno | **Informació insuficient**, sense evidència positiva per prioritzar. Risc alt d'estímuls GPU; cap prova. |
| [2026-25291](https://www.cve.org/CVERecord?id=CVE-2026-25291), Graphics/page lists | 4Gen2 no figura en la llista CNA; concurrència i controlador afectat necessaris | Mòdul concret desconegut; ni número5.10 ni SPL establixen compatibilitat | **Informació insuficient**, baixa prioritat. Risc corrupció/panic; no carrera. |

## Fronteres i utilitat per al desbloqueig

Un procés Android opera a EL0, limitat per UID, capacitats, SELinux i
possiblement seccomp. El kernel normal a EL1 arbitra memòria i drivers;
TrustZone pertany a un domini de seguretat distint, amb transport SCM i
validacions pròpies. El bootloader verifica la cadena d'arrancada abans
d'Android. El repositori ja documenta els contractes UEFI/SCM; no s'han
traslladat els defectes d'assignació Android a l'assignador UEFI.

Root temporal podria facilitar, **si s'obtinguera i amb autorització
adequada**, diagnòstic de nodes avui denegats i identificació de mòduls.
UID0 encara pot estar limitat per SELinux, i no prova accés a memòria
segura, claus, autorització Xiaomi o canvi d'estat persistent d'AVB.
Una corrupció del kernel tampoc prova que es puga arrancar LineageOS.
No s'ha modificat cap estat ni investigat una cadena d'elusió de
l'autorització del bootloader.

## Continuació de la investigació principal

Hi ha evidència nova de **fonts DDR i porta d'exclusions XBL** en
[l'informe del productor](xbl-ram-producer-analysis.md#continuació-proveïdors-ddr-i-exclusions-resolts-estàticament):
interfícies0x1c/0x1b resoltes, getter condicionat per inicialització,
estructura DDR font, ordre dels rangs i camp que habilita exclusions.
La via ordinària estudiada retorna zero o una exclusió. No s'ha llegit
la taula runtime ni reobert v1/entrada33 sense dades.

No ha aparegut un consumidor nou de Tz f250 o Config+0x20 en esta fase.
Es mantenen les restriccions de FeatureEnabler/família141 i de QSEE
Android. Les captures QSEE anteriors no han passat a ser evidència
kernel, i no s'han repetit. Les noves troballes XBL concreten
precondicions; no aporten una ruta de root temporal o desbloqueig.

## Validació reproduïble i pròximes proves amb valor

```sh
python3 scripts/inspect-android-kernel.py
python3 scripts/test-android-kernel-audit.py
python3 scripts/inspect-xbl-ram-producer.py
python3 scripts/test-xbl-component-layout.py
```

L'inspector usa `work/audit-images/boot.img`, fonts ACK i els dos
artefactes CI en `work/kernel-audit-2026-11-10/sources/`; els URLs i hashes
de les fonts estan al manifest. Les respostes Gitiles `?format=TEXT`
s'han desxifrat de base64. Els inputs de dispositiu són privats;
`--inputs` permet un altre directori. El hash de config/firmware
ha de coincidir, o l'inspector rebutja la comparació. No es fa una
actualització silenciosa dels pins per a un altre firmware.

El probe es compila amb `aarch64-linux-android30-clang -std=c11 -O2
-Wall -Wextra -Werror -fPIE -pie scripts/android-mitigation-probe.c`.
L'eixida completa conté adreces del procés i s'ha de guardar privada;
`probe_summary` només publica recomptes i bits de capacitat. Les13
proves noves exerciten privacitat, distinció denegat/absent/desactivat,
inputs truncats, gzip limitat i capçaleres sintètiques. No simulen una
explotació ni accedixen al mòbil. La regressió completa i la revisió de
publicació queden registrades en `PROGRESS.md`.

| Pròxima pregunta | Prova amb valor | Risc i decisió |
| --- | --- | --- |
| Es manté el codi afectat en un kernel corregit equivalent? | Comparar estàticament els canvis complets de43499/64560 i build GKI corregit amb la mateixa ABI; completar callers/guards | Sense risc per al telèfon; prioritat1. No cal activar la carrera. |
| Quin driver Qualcomm i quines portes runtime té este Redmi? | Quan torne ADB: `ls -lZ` dels nodes i mòduls concrets, lectura de metadades públiques i del flag pgsize_migration; comparar mòduls accessibles amb fonts/fixes | Baix, només lectura; prioritat2. No inspeccionar dades privades o obrir serveis/drivers. Denegacions es documenten. |
| Es poden validar regressions del fix de forma aïllada? | Preparar kernel ARM64 de laboratori amb correcció i comparar invariants/diagnòstic en VM descartable, fora del telèfon | Cost de preparació; un test de carrera pot bloquejar el guest. No s'ha executat ni es proposa traslladar-lo al mòbil. |
| Què falta en bootloader? | Completar writers de la font DDR i despatx de publicació; alternativament un caller/subscriptor f250 real o consumidor Config+0x20 concret | Anàlisi estàtica sense risc per al dispositiu; prioritat3 del projecte. |

No cal fastboot per a estes proves. Una futura prova que intentara root,
provocara una carrera kernel o modificara l'estat requeriria definir
prèviament objectiu, precondicions i risc, i autorització específica;
no forma part del treball executat ni dels scripts publicats.

Les consultes passives pendents estan preparades, separades de la captura
inicial: `python3 scripts/collect-kernel-readonly.py --scope followup`.
Inclouen el flag de migració identificat després de la desconnexió;
no s'ha executat esta versió final del col·lector sobre el dispositiu.
