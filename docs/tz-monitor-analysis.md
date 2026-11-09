# Monitor EL3: entrada i retorn SCM

Anàlisi estàtica i offline del mateix tz.mbn que
[el dispatcher](tz-dispatch-analysis.md). SHA-256 fixat:
`f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76`.
Adreces TZ = VA ELF, no offsets de fitxer. ScmDxeLA = RVA PE,
hash `bf446081b8d1156f7de9c1b329dcd774f9df427d890d2ca67f6259f6a985d77d`.

**Conclusió:** identificat el consumidor local dels paquets 0x81/0x83.
La ruta estàtica estudiada retorna el -1 del lookup al x0 no segur;
ScmDxeLA ARMv8 el transforma en `0x8000000000000003`. Açò completa
l'enllaç funcional sota les precondicions descrites, sense observar una
execució real, provar un caller MiToken +0x18 ni indisponibilitat global.

## Pregunta i cobertura nova

Pregunta: on es registra l'entrada publicada a +0x58, i com torna
`[1,0x83,-1,0…]` al caller no segur?

Dos MSR VBAR_EL3, 0x146800d8 i 0x146849e0, carreguen literals
0x14680218/0x14684b20, ambdós **0x14680800**. La taula té 16 slots
separats per 128 bytes. Dotze tenen stub d'error; quatre desen context:

| Slot | Literal amb destí | Handler |
| --- | --- | --- |
| 0x14680c00 | 0x14680c68 | 0x1c00ec78 |
| 0x14680d00 | 0x14680d70 | 0x1c00ee70 |
| 0x14680e00 | 0x14680e58 | 0x1c00ec78 |
| 0x14680f00 | 0x14680f60 | 0x1c00ee70 |

L'exportació Ghidra inicial no havia desassemblat estos slots indirectes
ni els handlers. S'han descodificat explícitament en la base d'anàlisi;
**absència en l'ASM anterior no significava absència de codi al binari**.
La crida inicial de 0x14680c00 a 0x14681000 conserva x8/x9 i la resta
dels arguments; el caller conserva LR abans de desar el frame de 0x110.

0x1c00ec78 extrau ESR_EL3[31:26]. Els valors 0x17/0x13 van a
0x1c00ed48, que passa el frame i l'antic SCR_EL3 a **0x1c00f9ec**.
Al retorn restaura els registres, carrega SCR_EL3 de la taula per CPU
0x1c01c058 (literal 0x1c00ee60) i fa **ERET a 0x1c00edf0**.
El handler 0x1c00ee70 delega en 0x1c010604: identificat, però la seua
semàntica completa d'interrupcions queda fora d'esta fase síncrona.

## Inicialització i encaminament d'entrada

0x1c010880 inicialitza contextos, posa byte **0x1c01c0d0=1**, offset
0x1c01d8f8=0 i offset 0x1c01d900=0x110. El selector 0x1c010a74
usa la taula byte 0x1c015904: índex 0 dona base 0x1c01c0d8;
índex 3 dona un context per CPU a 0x1c01c6f0+CPU*0x208. Són distintes
regions. Ací s'anomenen C0 i C3; el paper no segur de C3 es deduïx de
les branques SCR_EL3.NS, no del número per si sol.

Amb **NS=0**, 0x1c00f9ec crida **0x1c00feec**. Este dispatcher consulta
una taula de 69 offsets signed32 a 0x1c0157c0, base 0x1c00ff40,
per comandaments 1..0x45. Comandament 1 va a **0x1c01001c**.
Allí el subtipus és `frame[1] & 0x7f`; taula signed32 a 0x1c0158e8,
base 0x1c01003c, per subtipus 1..7. No confondre esta taula de
comunicació segura amb el lookup de serveis SCM 0x1c099c20.

El paquet inicial **[1,0x81,…]**, construït per 0x1c038154 i enviat
per SMC 0x14690118, selecciona subtipus 1 → 0x1c01004c. Després dels
helpers d'inicialització arriba a 0x1c0105b0 → **0x1c00f870**:

- +0x58 no nul → global **0x1c01c078** a 0x1c00f9b8. El valor publicat
  pel constructor és **0x1c1368a0**, el stub del dispatcher ja estudiat.
- +0x60 no nul → entrada per CPU de **0x1c01c080** a 0x1c00f9d4.

Amb **NS=1**, l'ID normalitzat `ID & 0x3fffffff` es compara amb casos
especials 0x7fff, 0x8000, 0x02000112, 0x0200060b i 0x3400fa04.
**0x42001401 no en satisfà cap** i arriba a **0x1c00fc14**:

1. Desa el frame no segur en C3 (0x1c01102c) i registres de sistema
   (0x1c010f40); conserva l'estat de retorn.
2. Prepara C0 amb 0x1c010ca4 i **0x1c0111a4**, passant l'entrada global
   0x1c01c078 i la taula de piles per CPU.
3. En el mode inicialitzat byte=1, **0x1c010df0** posa l'entrada a +0x1c0
   del context de sistema temporal i la pila al frame+0x100. Els primers
   arguments x0..x5 es conserven; no s'interpreten com la política.
4. 0x1c010ca4 → 0x1c00f000 restaura ELR_EL3 de context+0x110+0xb0
   (0x1c00f084/0x1c00f088). ERET entrega el frame al stub publicat.

Esta ruta requerix inicialització reeixida, contextos i pila vàlids, i que
els vectors/monitor locals siguen els utilitzats. Dins del stub continuen
les condicions ja documentades sobre x6/x7, context lliure i camins especials.
No s'ha provat que qualsevol crida arbitrària supere estes precondicions.

## Retorn del rebuig al caller

El paquet estudiat **[1,0x83,-1,0…]** arriba amb NS=0. Comandament 1,
subtipus 3 → **0x1c010520** → 0x1c0105b0 → **0x1c00f870**.
Si byte de mode=1 i el SCR guardat en C3 té bit 10, abans neteja 0x70
bytes des de C3+0x20: x4..x17, no els quatre resultats. Ho fa via
0x1c010b2c. El model contempla esta condició; no pressuposa preservació
de tots els registres alts.

| Origen en frame segur | Destí en C3 | Instrucció de destí |
| --- | --- | --- |
| +0x10, x2 = -1 | +0, x0 | 0x1c00f8cc |
| +0x18, x3 = 0 | +8, x1 | 0x1c00f8bc |
| +0x20, x4 = 0 | +0x10, x2 | 0x1c00f8ac |
| +0x28, x5 = 0 | +0x18, x3 | 0x1c00f89c |

Les metadades opcionals +0x30..+0x60 són zero en este paquet i no
modifiquen entrada/pila ni altres camps. 0x1c00feec retorna control **3**.
0x1c00fbc0 selecciona **0x1c00fcec**. El bit alt de 0x83 demana desar
el context segur via 0x1c01111c (C0, distint de C3). Després:

- **0x1c00fd0c → 0x1c011054:** copia C3 al frame de retorn; en el mode
  inicialitzat són 0x110 bytes via 0x14683348, identificada com a còpia.
- 0x1c00fd14 restaura sistema/ELR des de C3; 0x1c00fd80 posa NS=1.
- El vector recarrega x0..x30 i fa ERET. **x0=-1, x1..x3=0**.

Exemples de bytes originals (la resta i els offsets en
[tz-monitor.json](tz-monitor.json)):

| VA | Bytes | Operació |
| --- | --- | --- |
| 0x1c00fa40 | b4 05 00 37 | tbnz w20,#0,0x1c00faf4 |
| 0x1c010020 | 08 19 40 92 | and x8,x8,#0x7f |
| 0x1c00f8c0 | 76 0a 40 f9 | ldr x22,[x19,#0x10] |
| 0x1c00f8cc | b6 02 00 f9 | str x22,[x21] |
| 0x1c00fd0c | d2 04 00 94 | bl 0x1c011054 |
| 0x1c00edf0 | e0 03 9f d6 | eret |

## Comparació UEFI i classificació

ScmDxeLA 0x46dc és la SMC ARMv8; 0x46e0/0x46e4 repetix només si
w0 és positiu amb signe. -1 no repetix. 0x3990/0x3998 i 0x3a14
convertixen -1 a **EFI 0x8000000000000003**. El marcador 1 de resposta
només s'escriu per èxit a 0x39b8; no confondre'l amb el comandament 1
del paquet segur, que ja ha sigut consumit pel monitor.

| Observació | Classificació i límit |
| --- | --- |
| Rebuig lookup → paquet → x0 no segur → EFI error 3 | Comportament estàtic verificat per la ruta/contexts indicats. Cap invocació real observada. |
| MiToken omet alliberament en error SCM | Defecte local confirmat; ara hi ha un productor concret d'error en esta composició de proveïdors. Activació des d'un caller +0x18 i acumulació continuen condicionals. |
| Bucle >=256 i lectura fora de 0x4c4 | Condicionals; este camí retorna error abans d'interpretar política. No valida un recompte alternatiu ni descarta altres productors. |
| Búfer de política sempre inicialitzat | Qüestió pendent; la ruta rebutjada no invoca el productor. Netejar registres no inicialitza el búfer apuntat. |
| ChipInfo deixa word indeterminat en ruta normal | Ja descartat amb DAL; la nova ruta no contradiu el getter verificat. |
| VerifiedBoot fals èxit | Sense canvi: branca local amb nul, activació no demostrada; no s'ha analitzat keymaster/RPMB ací. |
| Indisponibilitat global de 0x02001401 | No demostrada; falta cobertura de runtime/altres components, no una coincidència literal. |

La variant **ScmDxeLA 0x1858** emet w0=1 amb paquet apuntat per x2,
no l'ID ARMv8 0x42001401. El namespace també depén de NS: el comandament
segur 1 no prova el tractament d'una petició no segura 1. El mapping
local -1→EFI error 7 continua verificat, però **no s'ha reconstruït una
ruta equivalent de petició antiga fins al servei de política**. No
extrapolar-li el resultat ARMv8 ni qualificar-la de fallback operatiu.

Altres dispatchers rellevants identificats: EL3 0x1c00f9ec, comandaments
segurs 0x1c00feec i handler 0x1c010604. Les taules extretes són cobertura
estructural, no una auditoria de les 69 operacions ni una cerca exhaustiva
de serveis carregables. L'absència en l'ASM inicial queda descartada com
argument per dir que faltava el monitor local.

## Reproducció i punt de represa

`python3 scripts/inspect-tz-monitor.py` verifica hash, límit d'entrada 8 MiB,
mapatge únic en LOAD, literals, 16 prefixos, 80 entrades de taula i bytes
puntuals. Reutilitza el parser ELF existent. No executa firmware.

Sobre el projecte Ghidra existent, `-noanalysis`, amb `-scriptPath
scripts/ghidra`, executar els post-scripts:

```
-postScript DisassembleAddresses.java 14680c00 14680d00 14680e00 14680f00 1c00ec78 1c00ee70 14681000
-postScript DumpInstructions.java work/TrustZone-monitor.asm
```

`python3 scripts/test-tz-monitor-model.py`: cinc proves sintètiques de
canvi de domini de registres, neteja condicionada, separació NS/subtipus
i rebuig d'entrades fora de l'abast del model. No emula el monitor ni
prova accessibilitat. Fitxers ASM/Ghidra propietaris romanen en work/.

La fase tanca la frontera del consumidor EL3 local. Pendents útils:
(1) referències indirectes d'interfície MiToken que demostren un caller;
(2) encaminament específic de la convenció SCM antiga, si és pertinent;
(3) productors/taules carregables en altres components locals, abans de
proposar límits del format de política. No s'ha fet xarxa ni canvi al dispositiu.
