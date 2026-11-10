# Seguiment dirigit: contractes de vida, mòduls i portes d'accés

2026-11-10; base `316669e`, `main` net i `git pull --ff-only` sense novetats.
Esta fase amplia [l'avaluació de root temporal](android-temporary-root-feasibility.md).
**Cap carrera kernel, exploit, ioctl de driver o prova de root executada.**
Els models són estats abstractes offline, no reproduccions del defecte.

## Identitat i correccions completes

Es reutilitza la identitat establida: Image del paquet igual al GKI oficial,
ACK `730d06ec05ff5dc34389ff99ea4009411efba5e6`, build15159037, i configuració
igual a la capturada en Android. `uname -r` i incremental del firmware
s'han tornat a confirmar. No s'han repetit extracció de boot, ASan o probes.

La comparació nova usa **fitxers complets de Linux5.10.262**, tag resolt al
commit `065a677fad98698de04279ba2cb152a472ab8b1f`, i els backports específics
de5.10. Els commits ACK del butlletí també són útils per entendre el canvi,
però diversos són de6.x: no es presenten com un diff directament aplicable
al Redmi. Fonts, URLs, hashes i funcions seleccionades estan als
[inputs fixats](kernel-directed-inputs.json) i als
[resultats revisats](kernel-directed-evidence.json).

| Cas | Correcció principal 5.10 | Complement que també s'ha revisat |
| --- | --- | --- |
| CVE-2026-43499 | [`f3fa3424bceb`](https://github.com/gregkh/linux/commit/f3fa3424bceb128d2be4b3745506b22844b87db7), upstream3bfdc63936dd; CNA situa el primer fix en5.10.261 | [`bfbc047ceb42`](https://github.com/gregkh/linux/commit/bfbc047ceb42c0e1fac8f3a155d4548a8bbe76b1), upstream40a25d59e85b: waiter no inicialitzat i retorn d'adquisició. Ambdós presents en el5.10.262 revisat. |
| CVE-2026-64560 | [`67aa823e3e8c`](https://github.com/gregkh/linux/commit/67aa823e3e8c229c6d374df79c804f6721cb83b6), upstream920f893f735e; CNA5.10.262 | Tres fitxers: CPU timers, exit i signal; retry de lookup, release/acquire i barrera per al cas PID desaparegut. |

**Validació de backport executada:** els tres pegats s'apliquen amb
`patch --fuzz=0` sobre còpies descartables dels quatre fitxers ACK exactes.
Les huit funcions afectades resultants coincidixen amb les de5.10.262
després d'eliminar comentaris/espais. Les capçaleres ACK `cleanup.h` i
`rcupdate.h` contenen les dependències de `guard(rcu)` que usa el fix.
No s'ha compilat un kernel, comprovat tota l'ABI o arrancat cap build;
aplicació textual correcta i igualtat de funcions no substituïxen eixes proves.

## 43499: propietat del waiter i contracte del rollback

En el [rtmutex exacte](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/locking/rtmutex.c),
`remove_waiter` requerix `wait_lock` i interrupcions desactivades.
`task_blocks_on_rt_mutex` establix `waiter->task`, encola el waiter i posa
`task->pi_blocked_on` sota **el pi_lock d'eixa tasca**. Una detecció inicial
de deadlock pot eixir abans d'inicialitzar `waiter->task`.

La neteja antiga, en canvi, pren **current->pi_lock**, esborra
**current->pi_blocked_on** i passa **current** a la propagació final.
Quan current i la tasca esperant són diferents, la cua del lock i l'estat
de la tasca no queden nets de manera coherent. `wait_lock` no substituïx
el pi_lock que governa eixe estat. La revisió del binari anterior ja havia
confirmat l'ús de current; ara es completa el contracte dels callers.

El [caller futex exacte](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/futex/core.c)
passa la tasca del waiter a `rt_mutex_start_proxy_lock`. El waiter de
`futex_wait_requeue_pi` és un objecte de pila. La referència de `pi_state`
manté un objecte distint: no allarga automàticament la vida de la pila ni
esborra `pi_blocked_on`. La referència temporal al propietari del lock
durant la propagació de prioritats tampoc resol eixa relació.

| Garantia | Redmi identificat | 5.10.262 revisat |
| --- | --- | --- |
| Identitat del pi_lock, blocked_on i tasca de propagació | current | waiter->task en els tres llocs |
| Error abans d'encolar | No hi ha guard de waiter_task en la implementació antiga | Retorn si waiter_task és nul |
| Resultat del wrapper | Neteja per qualsevol retorn no zero | Neteja només si el retorn és negatiu |
| Resultats del helper | 0 esperant, 1 adquirit, negatiu error | El wrapper respecta els tres casos |

La substitució d'identitat **a soles** introduïx el problema de desreferenciar
un waiter no inicialitzat; és el motiu del seguiment oficial. No es declara
que eixa regressió de la correcció parcial siga un segon crash observat en
el Redmi. El fitxer complet de
[5.10.262](https://github.com/gregkh/linux/blob/065a677fad98698de04279ba2cb152a472ab8b1f/kernel/locking/rtmutex.c)
inclou les dues correccions.

FUTEX/PI/RT_MUTEXES=y ja estaven establits. Ara es verifica també
**CONFIG_HAVE_FUTEX_CMPXCHG=y** en la configuració fixada: la porta del codi
`futex_cmpxchg_enabled` es resol a1 per compilació. Hi ha un camí de syscall
local sense una capacitat administrativa específica en la ruta revisada.
Encara calen estat PI vàlid, waiter encolat, identitats diferents i un
rollback pertinent; no s'ha demostrat l'encadenament temporal que deixaria
una referència utilitzable després de la vida de la pila. Els hooks Android,
la planificació i el context d'una app no s'han validat amb estímuls.

**Conclusió:** defecte estàtic confirmat i camí local justificat pel codi;
activació en el mòbil i elevació de privilegis no demostrades. No és correcte
reduir-lo a «qualsevol futex causa root», ni descartar-lo perquè hi ha locks.

## 64560: PID estable no significa líder estable

El [codi CPU timers exacte](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/time/posix-cpu-timers.c)
retén un `struct pid` en crear el temporitzador. `pid_for_clock` distingix
rellotges de fil i de procés; per fil comprova el grup, mentre que per
procés valida que el PID identifique un procés. El propietari del timer
no s'ha de confondre amb el procés el rellotge del qual es consulta:
[`__lock_timer`](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/time/posix-timers.c)
comprova `it_signal` contra el signal del caller i pren `it_lock`.
Això no immobilitza el líder del procés objectiu del rellotge.

En [`de_thread`](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/fs/exec.c),
un exec fet per un fil no líder canvia les associacions de PID/grup i
allibera l'antic líder. Este ja no és el líder quan passa per
[`__exit_signal`](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/kernel/exit.c):
la neteja per fil no implica eliminar la cua CPU compartida del procés.
Una consulta anterior pot conservar l'antic task i trobar després
`sighand == NULL`, encara que el procés i la cua continuen vius.

| Lloc | Comportament antic | Garantia de la correcció completa |
| --- | --- | --- |
| posix_cpu_timer_del | Davant sighand nul, pot advertir que el node continua encolat però retorna èxit | timer_lock_sighand repetix el lookup i obté el nou líder, o establix que el PID ha desaparegut |
| posix_cpu_timer_set | Pot retornar ESRCH sense acabar la gestió esperada | Usa el mateix helper; el cas de nanosleep també importa perquè el timer pot estar en la pila |
| posix_cpu_timer_rearm | Pot ometre el rearmament | Lookup/lock amb retry, compartit amb del/set |
| __exit_signal | Assignació ordinària de NULL a sighand | smp_store_release després de neteja/desassociació |
| __lock_task_sighand | Eixida nul·la sense adquirir el lock | smp_acquire__after_ctrl_dep en eixa branca |
| PID ja absent en el helper | No existix el helper | smp_rmb abans de verificar la cua, aparellat amb l'ordenació de la desassociació |

`timer_delete` reintenta amb TIMER_RETRY; si rep èxit, retira el timer i
crida `release_posix_timer`. Esta alliberació usa **call_rcu**: no és un
free immediat. La gràcia RCU protegeix lectors transitoris, però no repara
un enllaç de cua que persistix després. Igualment, `it_lock`, siglock,
referència PID i RCU protegixen objectes/relacions diferents.

S'han contrastat el [helper i els tres consumidors de5.10.262](https://github.com/gregkh/linux/blob/065a677fad98698de04279ba2cb152a472ab8b1f/kernel/time/posix-cpu-timers.c),
[signal](https://github.com/gregkh/linux/blob/065a677fad98698de04279ba2cb152a472ab8b1f/kernel/signal.c)
i [exit](https://github.com/gregkh/linux/blob/065a677fad98698de04279ba2cb152a472ab8b1f/kernel/exit.c).
El cas de firing conserva TIMER_RETRY. La neteja d'un procés que desapareix
no és equivalent al canvi de líder d'un procés que sobreviu.

**Conclusió:** POSIX_TIMERS=y i els canvis necessaris falten en el codi
identificat. Un timer armat/encolat i la coincidència amb el canvi de líder
són precondicions essencials, no observacions ADB. Ni el model ni un avís
estàtic demostren una escriptura controlada, root o una taxa d'èxit.

## Qualcomm: avanç del paquet, límit del runtime

S'han recuperat **només dos mòduls seleccionats** del firmware local amb
hash ja conegut. Extracció dirigida de super.img sparse, comprovació de
checksums de geometria/metadades LP, lectura de vendor_dlkm_a EROFS i
`dump.erofs --cat --path=/lib/modules/<nom>` per a cada mòdul. Cap mount,
instal·lació de paquet, lectura de particions del mòbil o canvi de permisos.
S'ha extret localment erofs-utils1.8.6-1 de Debian; el manifest fixa la cadena
tgz → super → vendor_dlkm → mòduls. Els artefactes complets queden ignorats.

Els dos `.modinfo` declaren `scmversion=g51ab44fbc4b7` i vermagic
`5.10.198-gki-g51ab44fbc4b7 SMP preempt mod_unload modversions aarch64`.
Això separa la procedència vendor de la del GKI. No demostra una incompatibilitat
de càrrega: versió de font, ABI/KMI i hash del codi són qüestions diferents.
La correspondència byte a byte amb els mòduls **carregats** continua pendent.

**57545 / KGSL:** el mòdul del paquet conté `get_active_cmdobj_lpac`.
S'han contrastat les instruccions i la decompilació seleccionada: el bucle
comprova el context LPAC però no el tipus cmdobj abans de continuar. És
el guard que afig el [fix oficial](https://git.codelinaro.org/clo/la/kernel/msm-5.10/-/commit/874311dc075047c51c9231e3de1bae0a7677b3b7).
La funció completa queda fixada per hash, sense publicar codi propietari.
Però trobar funcions hwsched/LPAC en un mòdul multiplaforma no establix
que Adreno613v1 use eixa ruta. Falten selecció de gpu_core, capacitat LPAC,
caller efectiu i política d'accés. **Informació insuficient** per al Redmi;
hi ha coincidència estàtica del guard absent en el paquet.

**57554 / FastRPC:** s'ha pogut llegir ara el
[fix complet msm5.10](https://git.codelinaro.org/clo/la/kernel/msm-5.10/-/commit/a065d4bacdae2cea6678a7528df8008d16452a63).
Mou l'actualització invoke/count fora de la cua final de submissió asíncrona,
guarda el temps inicial abans de send i actualitza en el col·lector abans
de context_free. En el binari del paquet, `fastrpc_internal_invoke`
conserva el punter als comptadors del context i l'actualització final
condicionada per profiling, absència d'interrupció i operació asíncrona.
`fastrpc_wait_on_async_queue` allibera el context; no conté la nova
actualització traslladada. La inspecció de `context_free` concorda amb
l'alliberació de les dades de perf. Coincidència estructural amb el codi
anterior al fix, no una conclusió basada en vermagic.

Falten permisos efectius d'open/ioctl, domini DSP adequat, suport asíncron,
profiling activat i la concurrència de resposta. La presència del node o
del mòdul no satisfà estes portes. **Informació insuficient** per confirmar
compatibilitat operativa al Redmi; candidat estàtic més concret que abans.
El risc documentat és UAF/panic, no root demostrat. No s'han publicat
offsets de camps, paquets d'invocació o una seqüència d'activació.

## 58942: flag actiu, algoritme diferent

ADB confirma migració de pàgina=1 i propietat màxima de pàgina4096.
Per tant queda descartada la hipòtesi «5.10/4K implica funcionalitat absent».
Este és codi ACK de memòria/migració, no una atribució a un mòdul Qualcomm.

El [fix publicat](https://android.googlesource.com/kernel/common/+/019d909caeb85547b9aed2beea73101ea73b958f)
és d'un arbre6.12 i exclou faults en padding abans d'una resta amb offsets
PTE/VMA. L'[algoritme5.10 concret](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/mm/memory.c)
calcula offsets de fitxer i limita end_pgoff al mínim que inclou
`data_pages + vm_pgoff - 1`. Si eixa suma és positiva i no desborda,
l'extrem no passa l'última pàgina de dades. En una VMA tota de padding
amb vm_pgoff positiu, resulta un rang buit; en el
[`xas_find` exacte](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/lib/xarray.c)
start>max termina sense pàgina, i
[`filemap_map_pages`](https://android.googlesource.com/kernel/common/+/730d06ec05ff5dc34389ff99ea4009411efba5e6/mm/filemap.c)
no entra en el bucle de mapatge.

És una restricció concreta, **no una prova universal d'absència de CVE**.
Falta tancar els invariants dels offsets i flags durant totes les transformacions
legítimes de VMA i els hooks vendor. La creació inicial del padding té
guards de fitxer `.so`, final del rang, mida i context linker64; split pot
produir una VMA tota de padding. No s'ha fabricat cap cas límit al telèfon.
Estat: **informació insuficient**, prioritat inferior als dos defectes GKI.

## Diagnòstic executat i decisió

**18 crides ADB en esta fase:** 1 comprovació de connexió i17 consultes shell.
El col·lector followup es va revisar abans d'executar-lo i es va filtrar
/proc/modules en el dispositiu per eliminar la columna d'adreces. El primer
filtre no incloïa `frpc_adsprpc`; una consulta corregida el va trobar.
No s'interpreta eixa primera absència de coincidència com a mòdul absent.

| Consulta passiva / pregunta | Resultat | Què no demostra |
| --- | --- | --- |
| gpu_model / gpu_revision | Adreno613v1; node revision inexistent | Suport o activació LPAC |
| /proc/modules seleccionat | msm_kgsl i frpc_adsprpc Live | Hash del binari carregat |
| Fitxers ko de vendor/vendor_dlkm | Permission denied | Driver absent o pegat present |
| srcversion/version dels dos mòduls | Paths inexistents | Revisió desconeguda, no «zero» |
| scmversion dels dos mòduls | Permission denied | No permet lligar la revisió runtime al paquet |
| Globs lpac/hwsched al nivell arrel de kgsl-3d0 | Sense coincidències | No cobrix atributs en altres grups ni capacitats internes |
| Nodes adsprpc | smd0664 i secure0644, system:system; tipus SELinux vendor_qdsp_device/vendor_xdsp_device | Cap open/ioctl, autorització SELinux o disponibilitat DSP comprovada |
| pagesize.max / pgsize_migration/enabled | 4096 / 1 | No prova per si sol el defecte58942 |
| uname -r / incremental | Coincidixen amb la compilació investigada | No és atestació de memòria viva |

| Candidat | Codi i component | Precondició oberta més important | Informació segura següent | Risc d'activació i relació amb root |
| --- | --- | --- | --- | --- |
| 43499 | Defecte estàtic; futex PI i gate cmpxchg compilats | Rollback/lifetime efectivament assolible en el context concret | Validar backport sobre arbre equivalent i revisar hooks/ABI offline | Carrera pot penjar o corrompre kernel; cap primitiu de root demostrat |
| 64560 | Defecte estàtic; POSIX timers compilats | Timer encolat i canvi de líder concurrent pertinent | Revisar invariants de ownership i correcció en build equivalent | UAF/panic possible; cap elevació demostrada |
| 57545 | Guard absent en el mòdul del paquet; KGSL carregat | Ruta LPAC/hwsched seleccionada en esta GPU | Taula gpu_core/probe, font vendor exacta o atribut públic pertinent | GPU hang/corrupció; podria ser codi inactiu per a este model |
| 57554 | Patró antic de perf en el mòdul del paquet; FastRPC carregat | Política d'accés i portes async/profiling/DSP | Font vendor exacta i revisió estàtica dels guards; metadades llegibles | UAF/panic; accés i root no provats |
| 58942 | Backport i flag actius; algoritme distint | Equivalència semàntica del defecte sota invariants reals | Tancar transformacions VMA/offsets offline | No justifica un test de corrupció en el mòbil |

CFI/SCS, PAN/W^X, KASLR i enduriment slab estan documentats per configuració
en l'informe principal. Poden dificultar convertir un error de vida en control
útil; no reparen l'ownership ni autoritzen a declarar impossible tota corrupció
de dades. SELinux Enforcing i bootloader locked continuen sent fronteres
diferents. No s'ha desactivat ni intentat eludir cap mitigació.

Root temporal continua sent una **línia de recerca estàtica justificada**, però
no una solució operativa disponible per al diagnòstic. Un crash posterior només
demostraria una fallada. Cap resultat demostra autorització Xiaomi, alteració
d'AVB, accés a TrustZone o arrancada d'un sistema alternatiu. Root podria
ampliar diagnòstics subjectes encara a SELinux; no equival a desbloqueig.

## Reproducció offline i límits dels tests

```sh
python3 scripts/inspect-kernel-directed.py
python3 scripts/inspect-kernel-directed.py --check-backports
python3 scripts/test-kernel-directed.py
python3 scripts/test-kernel-lifetimes.py
python3 scripts/test-android-kernel-audit.py
python3 scripts/inspect-xbl-ram-producer.py
```

L'inspector rebutja hashes diferents dels revisats. Comprova17 assertions
textuals dels contractes, el gate de configuració i metadades/hashes de quatre
funcions dels dos mòduls. No transforma coincidències de text en una prova
d'explotabilitat. Els inputs privats es resolen sota `work/` o `--inputs`;
els fitxers públics es poden recuperar dels URLs fixats (Gitiles TEXT és base64).
`--check-backports` requerix l'eina host `patch`; treballa en un directori
temporal i l'elimina després, sense modificar les fonts originals ni el mòbil.

Per revisar els mòduls, import ELF a Ghidra12.2 i exportació seleccionada amb
`scripts/ghidra/DumpNamedFunctions.java`, més contrast amb llvm-objdump del NDKr30.
No s'executa codi dels mòduls. El hash de funció cobrix bytes de l'objecte
relocatable; no és un hash de memòria carregada ni incorpora totes les relocacions.

Les14 proves de models comparen identitats, neteja, resultats del wrapper,
canvi de líder, firing, timer desarmat i eixida ordinària. Inclouen un recompte
DDR abstracte separat, amb1.296 combinacions de comptes petits. No modelen
el memory model ARM64, preempció, assignadors o planificació. Les8 proves
d'inputs comproven privacitat, límits ELF, hashes i extracció de funcions.
No hi ha reproducció concurrent, VM vulnerable arrancada, ASan repetit ni
binari nou enviat al mòbil.

Pròximes prioritats: compilar i validar les correccions en un arbre/build de
laboratori equivalent, després del contrast textual ja completat; establir
selecció LPAC i portes FastRPC amb fonts/metadades;
seguir el writer DDR identificat fins a la publicació, o un consumidor Tz/Config
concret. Un experiment de carrera requeriria una proposta i autorització
específiques; no està inclòs en els scripts ni s'ha executat.
