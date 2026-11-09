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
