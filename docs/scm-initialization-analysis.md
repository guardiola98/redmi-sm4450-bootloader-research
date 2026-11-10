# Inicialització SCM i garanties de ShmBridgeDxe

2026-11-10. Pregunta: què ha de passar abans que ScmDxeLA publique una
interfície, i quines garanties de memòria aporta el proveïdor? Revisió
estàtica acotada; no repetix la reconstrucció EL3 ni executa firmware.
Adreces RVA dins de cada PE; ASM i decompilat Ghidra contrastats amb
[bytes originals](reviewed-pe-evidence.json).

ScmDxeLA SHA-256:
`bf446081b8d1156f7de9c1b329dcd774f9df427d890d2ca67f6259f6a985d77d`.
ShmBridgeDxe SHA-256:
`67a6b5e55bb08771068fe01cace2bfb9ffd984eade499d9b877dd96f6d4112c2`.
El segon PE ja estava inventariat, però sense revisió funcional: FFS
`9c1eb71f-dd6c-4ed5-9f6a-5cc0ca789f16`, secció PE `0x91880` dins del
primer FV descomprimit. La ruta completa i el hash del contenidor són en
[consumer-dependencies.json](consumer-dependencies.json).

## Selecció i publicació

`ScmDxeLA 0x14e4` crida la sonda `0x4534` a `0x14f8`. La sonda ja
estudiada usa l'estat EFI, no el booleà de disponibilitat del servei consultat.
Un resultat baix no zero selecciona `0x3744` (ARMv8), zero selecciona
`0x17b4` (antiga). Les instruccions **CBNZ a 0x1508 i 0x1528** retornen
qualsevol estat no zero de l'inicialitzador abans d'instal·lar el protocol.
**No hi ha fallback a l'altre inicialitzador després d'una fallada.**

Només amb inicialitzador zero es publica el GUID
`77ed108d-8524-4b8b-9d2e-34987aecb9c1` via BootServices+0x148 a
`0x1550`: taula ARMv8 `0xd130`, antiga `0xd0d8`. Els seus callbacks
+0x38 són, respectivament, `0x3cb4` i `0x1858`. Error d'instal·lació
es propaga a `0x1554`. El predicat és **estat != 0**, més estricte que
una comprovació exclusiva del bit EFI_ERROR.

Després de publicar, `0x1564` consulta `SecurityFlag`: només si retorna
zero i està actiu el bit `0x100` crida `0x306c` per registrar logs. Un
error d'esta operació es registra i `0x158c` retorna zero. És una operació
auxiliar posterior a la instal·lació: no demostra èxit d'un servei de
política, autenticació ni canvi d'estat de bloqueig.

## Precondicions dels inicialitzadors

| Inicialitzador | Seqüència verificada | Resultat i límits |
| --- | --- | --- |
| Antiga `0x17b4` | CreateEventEx via BootServices+0x170, tipus 0x200, prioritat 8, callback 0x159c, GUID d'esdeveniment a 0xd038. | Tail-call que propaga l'estat; no consulta ací la disponibilitat de 0x02001401. |
| ARMv8 `0x3744` | LocateProtocol del GUID ShmBridge (0xd098), dos buffers sol·licitats de 0x38 i 0x2000 via +8, inicialització d'objectes 0x4774, CreateEventEx amb callback 0x35f8. | Només zero en tots els passos que retornen normalment permet instal·lar SCM. Les fallades no activen la variant antiga. |

Si LocateProtocol retorna EFI_ERROR, `0x37b0` arriba a ASSERT `0x6cf0`:
`0x6da0 → 0x7308`, que escriu zero a sp+8 (`0x731c`) i espera que deixe
de ser zero (`0x7320/24`). Sense intervenció externa, no és un retorn
d'error normal. No inferir una desreferència posterior real a partir del
C descompilat, que conserva el codi després de l'ASSERT.

Les branques de NULL de l'allocator estan presents: primera reserva nul·la
retorna EFI error 9; segona nul·la passa per +0x10 per alliberar la primera
(`0x3858..64`). Això descriu el CFG del consumidor, no garantix que tota
fallada del proveïdor arribe a eixos retorns: també usa ASSERT.

La sonda anterior a estes reserves usa un argument (`0x4534`, preparació
de locals inicialitzats). `0x3880` selecciona amb `cmp #5 / b.cc`
(`0x38c8/cc`) el camí de registres; l'accés al buffer global 0xd418 és
en l'altra branca. **Descartada la dependència circular de la sonda
respecte a la reserva global encara no inicialitzada**, per esta crida.

## ShmBridge: garantia local de zero-fill

Taula `0x70a8 = [0x10001, 0x1514, 0x1524]`, instal·lada a `0x14e4`
sota el GUID anterior. +8 llig `*x1` com a mida, fixa alineació 0x1000
i passa per `0x2c18 → 0x2be4 → 0x2b94 → 0x2890`. El valor x2=2 que
li passa SCM queda substituït per este wrapper; no prova una opció de
seguretat o de zero-fill seleccionada pel caller. El punter de mida es
llig sense validació i no es modifica. SCM li passa locals vàlids.

`0x2b94` arredonix a pàgines; `0x2890` pot reutilitzar blocs lliures o
assignar-ne de nous. **En tots els retorns no nuls cap a +8, 0x2be4
neteja la mida original sol·licitada**, amb `0x2c08 → 0x45a8 → 0x460c`
(w2=0) → `0x4678`. La neteja es produïx també després de reutilitzar
blocs; no s'afirma zero-fill de tota la pàgina sobrera. Una petició de
mida zero retorna NULL. Diversos errors d'assignació/configuració criden
ASSERT, i no constituïxen simplement un retorn NULL ordinari.

+0x10 (`0x1524 → 0x2b4c`) marca disponible el bloc coincident de la
llista, sense netejar-ne el contingut, i retorna zero. Este contracte
és d'este proveïdor concret. **No cobrix la reserva de política MiToken**,
que usa el seu allocator intern; no descarta dades antigues en eixe búfer.

## Objectes i configuració

`0x4774` consulta `SmcInvokeConfig` mitjançant `0x61b8`, delegat a
`UEFI Config Lib` +0x18. Si no pot obtindre la interfície, retorna EFI
error 6; els altres estats depenen del callback. Amb consulta no zero es
conserven els valors originals **256/256/256** de `0xd188/190/198`.
Amb èxit separa un uint32 en camps **11/11/10 bits** (`0x47d8..e0`).

La mida de les taules d'objectes és
`24*local + align8(12*remote) + 2*((4*async+23)&~7)`:
11.296 bytes per defecte i màxim 81.920. No hi ha overflow d'esta suma
per valors representables de la configuració de 32 bits. Açò **no és
un límit del recompte de política MiToken**; són objectes d'una interfície
distinta. Tampoc valida totes les configuracions: amb zero objectes
remots, per exemple, `0x4ad8` arriba a ASSERT per taula plena. No s'ha
demostrat que eixa configuració siga efectiva.

Després reserva taules, obté de nou ShmBridge i registra l'objecte client.
Prepara EFI error 9 si manca reserva, EFI error 7 si falla registre/obertura
i conserva l'error de localització. Abans del retorn passa per `0x4b7c`:
**no s'ha de considerar garantida la propagació**, perquè la revisió següent
identifica una precondició de neteja que falta en una d'estes vies.
La disponibilitat d'este canal d'objectes no és equivalent a la del servei
de política de MiToken.

[scm-static-config.json](scm-static-config.json) traça la secció RAW
`uefiplat.cfg` exterior: `SecurityFlag = 0xC4` i cap clau exacta
`SmcInvokeConfig`. És una observació del recurs, no prova dels valors
retornats per la biblioteca ni de l'absència de sobreescriptures. Si 0xC4
és efectiu, el bit 0x100 no sol·licita el registre auxiliar de logs.

Actualització d'esta continuació: [procedència de configuració](uefi-configuration-provenance.md)
reconstruïx el proveïdor TE, HOB i getter concret. No hi ha tampoc variant
de la clau amb majúscules diferents en este recurs; ChipIDConfig no aporta
sobreescriptures locals. La cadena normal reconstruïda prediu 0xC4 i
comptes 256/256/256, sempre condicionada a usar esta taula intacta.
El getter té un temporal indeterminat en error; els guards d'estat SCM
eviten consumir-lo com a configuració reeixida.

## Neteja en errors tardans i decisió

**Nou defecte de robustesa confirmat: neteja amb inicialització parcial.**
En la primera entrada, els words originals `0xd438/440/450/460/468/488`
són zero. Les referències Ghidra revisades situen la construcció de taules
i objectes després de la reserva de `0x4820`, no abans. El helper
`0x6b18 → 0x6acc` crida BootServices+0x40 (AllocatePool) a `0x6aec` i
convertix EFI_ERROR en NULL a **0x6af0 → 0x6b08**, sense ASSERT en esta
via. A diferència de l'allocator estudiat de VerifiedBoot, el retorn NULL
per error ordinari té ací un productor local concret.

`0x482c → 0x48c0` prepara EFI error 9 i passa per `0x4a60 → 0x4b7c`.
Amb client nul, `0x4ba0` salta al registre d'error, però després **0x4c7c
crida 0x57fc amb punter zero**. El helper calcula
`((objecte-base_remota) mod 2^64)/12`, compara amb el nombre de remots i,
amb el valor per defecte 256, considera vàlid l'índex zero sobre base zero:
**STR WZR a adreça 0 a 0x582c**, seguit de stores +4/+8 a 0x583c si
continua. A més, `0x4ccc` intenta llegir a `async_base+8` sense comprovar
la base; seria adreça 8 en este estat, fins i tot si el nombre de remots
fora zero. Els accessos posteriors no s'assumixen executats si el primer
provoca excepció.

Precondicions: inicialització inicial amb estat original preservat,
selecció ARMv8 i èxit dels passos anteriors, després error AllocatePool.
El CFG i els accessos a base nul·la estan verificats amb bytes originals;
el model sintètic només calcula adreces, sense accedir-hi. L'estat real
de memòria, la possibilitat de provocar esgotament i el mapatge de la
pàgina zero no estan demostrats: no s'afirma corrupció concreta, explotació
ni bypass. Sí que es descarta que «preparar EFI error 9» baste per demostrar
un retorn segur d'este error. Este candidat té més valor que els recomptes
hipotètics de MiToken: la precondició prové d'un contracte d'error ordinari.

Hi ha una **omissió local de neteja addicional** en `0x3744`: si `0x4774`
retorna error després de les dues reserves, `0x381c` retorna sense +0x10.
Si CreateEventEx falla, `0x3854` fa el mateix. El callback `0x35f8` sí
que conté alliberaments dels dos blocs (`0x36e4/0x36fc`), però encara no
s'ha registrat reeixidament en estes vies. El destructor d'error de la
imatge `0x1490 → 0x6390` tracta la llista pròpia de ScmDxeLA, no la de
ShmBridge. Per tant la recuperació local dels dos blocs no està coberta.
Activació real, recuperació posterior de plataforma i impacte queden
condicionals; no s'ha demostrat repetició ni esgotament. No s'amplia esta
línia a tot l'allocator o al canal d'objectes sense un cas concret nou.

Conclusions: selecció, inicialització, publicació i disponibilitat del
servei són quatre fets diferents. Esta fase tanca les precondicions locals
de publicació, però no canvia el rebuig condicional EL3 ja documentat ni
identifica un productor de política. Tests sintètics d'estats i cotes en
`scripts/test-scm-initialization-model.py`; no són execució ni emulació SCM.

Reproducció: `python3 scripts/inspect-reviewed-pe-evidence.py`,
`python3 scripts/inspect-scm-static-config.py` i el test anterior. Les
exportacions Ghidra són locals/ignorades, sense PE propietaris en Git.

## Revisió dels contractes d'error — continuació des d'a566643

La revisió del **DxeCore local**, SHA-256
`a7fb96099cd5793966a4c01dc20a046d67c1858176e48cf3c9d2c6b69563b98c`,
aporta una comprovació del proveïdor de Boot Services, sense recórrer a
una especificació externa ni assumir una versió d'EDK2. La taula amb
signatura `BOOTSERV` a RVA `0x2a578` conté AllocatePool=`0xffd4`
(+0x40) i FreePool=`0x1048c` (+0x48). La connexió efectiva pressuposa
que el SystemTable passat a SCM correspon a este Core i no ha sigut alterat.

| Operació | Contracte local verificat | Conseqüència per a SCM |
| --- | --- | --- |
| AllocatePool → `0xfeec` | Per al tipus 4 i out-pointer vàlid de SCM, inicialitza `*out=0` a `0xff4c`; error de lock o reserva nul·la retorna EFI error 9. Reserva no nul·la retorna zero. | Productor ordinari de NULL verificat també al Core; no implica que s'haja produït ni que siga induïble. No hi ha estat d'èxit amb `*out=NULL` en esta ruta. |
| Wrapper SCM `0x6acc` | EFI_ERROR → NULL; èxit no nul → `0x6dd0`, neteja de la mida demanada. | Les taules tenen zero-fill quan l'assignació acaba normalment. La mida és sempre almenys 32 bytes, inclosa configuració zero. |
| FreePool → `0x100d0` | `CBZ x0` abans de llegir metadades; NULL retorna EFI error 2 (`0x10128/2c`). | **No és un `free(NULL)` d'èxit**. El wrapper SCM `0x6b84` convertiria l'error en ASSERT/espera. Però `0x4cec` evita FreePool si la reserva és nul·la: no és la causa del defecte observat. |
| ShmBridge +0x10 → `0x2b4c` | NULL o punter sense coincidència: no modifica la llista; coincidència: marca disponible, sense retornar pàgines a Boot Services. El wrapper retorna zero. | És un contracte diferent del FreePool anterior. La recuperació local és reutilització, no necessàriament reducció de pàgines reservades. |
| Esborrar objecte SCM `0x57fc` | Valida l'índex calculat, no NULL, alineació, marcador ni ocupació. | Amb objecte/base zero i nombre remot positiu, l'índex zero passa. No és un alliberador amb semàntica de NULL segura. |

L'última comprovació de `d450` és posterior als accessos d'objectes i
`d468+8`; per això el tractament documentat de NULL en FreePool no salva
la inicialització parcial. Si les escriptures a zero finalitzaren,
`0x5844/48` també decrementaria `d490`, inicialment zero. Dos esborrats
portarien el comptador a `2^64-2`. És una conseqüència **condicionada a
continuar després dels accessos**, no una corrupció observada. Tampoc es
demostra idempotència: després de FreePool la neteja no posa a zero les
bases globals. Una segona invocació requeriria estudiar els seus callers;
no es declara doble alliberament accessible.

### Inventari de propietat en les eixides seleccionades

| Punt de fallada | Estat adquirit | Recuperació local / retorn |
| --- | --- | --- |
| Segona reserva ShmBridge nul·la | Primera reserva | Es marca disponible amb +0x10; retorn EFI error 9 si el proveïdor torna normalment. |
| AllocatePool de taules | Dues reserves ShmBridge, taules inexistents | `0x4b7c` accedix a bases nul·les; no es pot garantir el retorn d'error preparat. |
| Localització/registre d'objectes posterior | Dues reserves ShmBridge i taules | Es crida `0x4b7c`; els estats parcials i els callbacks continuen sent precondicions per acabar. El retorn normal d'error de `0x4774` no allibera les dues reserves externes. |
| **CreateEventEx després d'objectes reeixits** | Dues reserves ShmBridge, taules i client creats | `0x384c → 0x3854` retorna l'error sense +0x10 **ni `0x4b7c`**. S'amplia l'omissió local a la reserva de taules d'este camí concret. |

L'última fila és evidència nova: el pool `d450` no forma part de la llista
de pàgines que recorre el destructor `0x6390`. Amb configuració per defecte
són 11.296 bytes sol·licitats addicionals sense FreePool local; amb altres
configuracions, la fórmula anterior. No es quantifica la memòria física
total ni es dona per provada una fuga acumulativa o l'absència de recuperació
externa. Les branques que passen per ASSERT no es compten com retorns normals.

### Accés nul: què determina l'entorn

També s'ha revisat de manera acotada **ArmCpuDxe**, SHA-256
`b8a7217745f23817c167c397b4a439c1e9a1c2c28f8bf7ee84479bf03c83e6b1`.
`0x4300` prepara vectors, `0x3028` selecciona VBAR segons CurrentEL;
`0x44b8` delega al handler registrat o a `0x75ec` quan el slot és nul.
Este gestor per defecte diagnostica i arriba a ASSERT a `0x7c50`, seguit
de bucle explícit a `0x7c54`. El helper d'espera `0x7254` també posa a
zero un local i el consulta repetidament. No hi ha ací conversió genèrica
de l'excepció a EFI error 9 amb retorn a l'inicialitzador.

Açò **no demostra** que l'STR a zero genere excepció ni que use eixe
handler. Falten: traduccions/atributs de pàgina actius per a VA 0..11,
nivell d'excepció efectiu, vectors/handlers instal·lats en eixe moment,
i intervenció eventual de watchdog o depuració. Una pàgina inaccessible
podria interrompre la inicialització; una pàgina escrivible podria rebre
els stores. Cap de les dues alternatives es presenta com observació.
No s'ha revisitat el monitor EL3; són rutines del driver UEFI local.

Reproducció de les noves peces:
`python3 scripts/extract-selected-uefi.py DxeCore ArmCpuDxe`, seguit de
l'inspector de bytes. L'extractor usa el manifest existent, valida hash
del contenidor i de cada PE i no repetix censos GUID. Per a Ghidra:
importació PE ARM64 i scripts `DumpFunctions.java`/`DumpInstructions.java`
en `scripts/ghidra/`; conservar les exportacions només en `work/`.

## Mapatge nul: evidència estàtica addicional i frontera SMEM

La configuració RAW hash-pinned conté **24 regions MemoryMap i 15
RegisterMap**, totes amb base/mida alineades a 4096 i cap rang que incloga
zero. Abans de les transformacions dinàmiques, el constructor inclouria
36 regions i exclouria tres `AddDynamicMem`; la base mínima inclosa és
`0x00400000`. L'inspector publica només estos agregats, no el cos del recurs.
No s'ha accedit a cap registre o adreça física.

El TE `0xa7012210 → 0xa7010288` transforma la taula de regions en
entrades de 32 bytes, amb **base física=base virtual**, longitud i atribut.
Exclou tipus 6/9/10 (`HobOnlyNoCacheSetting`, `NoMap`, `AddDynamicMem`),
no `NoHob` (tipus 4). Neteja la llista, comprova count<128, afegix una
entrada terminadora i crida `0xa701c738` a `0xa70104e4`.

`0xa701c738` reserva una taula de traducció nova, la posa a zero
(`0xa701ca00`) i la instal·la via `0xa7019b30` (`0xa701ca08`). El helper
selecciona TTBR0_EL1/EL2/EL3 segons CurrentEL; és codi UEFI del TE, no una
nova revisió del monitor segur. Cada regió passa a `0xa701c4dc`, que usa
base/longitud i descriptors de pàgina/bloc; `0xa701ccc8` inicialitza a zero
les taules subordinades noves. El final reeixit `0xa701cc18 → 0xa7019d4c`
activa SCTLR.M (`ORR #1` a `0xa7019d78`). No és una taula heretada que
simplement haja conservat totes les traduccions anteriors.

**Açò no fixa encara el mapa efectiu en l'error SCM.** La mateixa entrada
TE fa `LoadAndParsePlatformCfg` a `0xa700e8c0`, després mescla RAM amb
`0xa7011c38` a `0xa700e980`, i només llavors configura MMU a `0xa700ea08`.
La mescla pot afegir regions anteriors/posteriors als rangs RAW i transformar
AddDynamicMem. Usa la taula RAM preparada per `0xa70234d4`:

- `0xa70230c4` obté SMEM item **0x192** a `0xa70230f0` i comprova
  signatures/versió. Les entrades de memòria són dades de l'entorn de boot;
  no hi ha una captura efectiva d'eixe SMEM en esta auditoria.
- La versió 1 delega a `0xa7023300`; l'altra via convertix descriptors
  dins de `0xa70234d4`. El tipus/categoria filtra regions, però no s'ha
  establit una garantia universal de base no nul·la de totes les entrades.
- Si SMEM no està disponible amb error 6, hi ha un fallback explícit
  `{base=0x80000000, mida=0x60000000}` als literals `a7038b10/a7038b18`.
  No inclou zero, però no s'ha provat que eixa branca siga la seleccionada.

Conseqüència delimitada: **amb taules reeixides que només continguen els
rangs locals no nuls, sense additions que cobrisquen zero ni canvis posteriors,
la reconstrucció no proporciona una traducció per als accessos nuls SCM**.
Falten la taula RAM efectiva mesclada, el context de traducció en eixe moment
i qualsevol modificació posterior per a convertir-ho en un resultat runtime.
A més, la destinació de l'excepció/handler i qualsevol recuperació/watchdog
continuen condicionant el desenllaç. No s'afirma que s'executen els stores
posteriors, que es produïsca l'underflow del comptador o que el dispositiu
s'ature necessàriament.

Reproducció: `inspect-scm-static-config.py` afegix resum de rangs amb
validació de límits; dos tests nous comproven exclusions i rebuig de wrap
aritmètic. `inspect-uefi-config-contract.py` verifica els callsites/registre
TTBR i constants de fallback; referències `a7043a58 a7043a60 a7010558
 a7010288 a701c738` en ConfigTeLayout identifiquen les transformacions.
No es justifica repetir la recerca d'impacte nul fins disposar de nova
evidència sobre estes dades o transicions d'entorn.
