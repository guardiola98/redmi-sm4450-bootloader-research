# TrustZone: estructura i consulta de serveis

Base: commit 1b03a74. Exclusivament estàtic/offline. SHA-256 TZ verificat:
`f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76`.

## Mapatge reproduïble

`inspect-tz-structure.py` valida ELF64 LE/AArch64, límits de program headers,
segments i relació filesz/memsz per LOAD. `docs/tz-structure.json` conserva
35 headers, 33 LOAD, entry 0x14680000 i candidats literals. Les adreces
següents són **VA ELF**, no RVA PE ni offsets de fitxer. Memòria sense bytes
de fitxer no es considera origen d'instruccions. Flags ELF no proven els
permisos efectius de pàgina en execució.

Ghidra ha importat tz.mbn en work/ghidra-project/TrustZone i exportat ASM a
work/TrustZone.asm. S'han notificat conflictes de funcions/thunks en algunes
adreces i una incidència de cache de tipus; l'import i l'export han acabat.
No usar el pseudocodi com una prova completa de tots els límits de funció.
`DumpAddressReferences.java` exporta referències i pseudocodi de callers
per adreces concretes. Tots els resultats propietaris queden en work/.

## Ruta de consulta verificada

La cadena diagnòstica `OEM_enable_syscall_tracing` a VA 0x1c138537
referencia un helper 0x1c03ec48. Callers a 0x1c077a18, 0x1c077be0 i
0x1c077c14 permeten localitzar una ruta de dispatch a **0x1c07798c**.
No s'ha deduït el dispatch només del text: el codi llig identificador,
normalitza, consulta descriptor, comprova error i prepara l'execució.

- 0x1c0779c4..0x1c0779f0 extrau bits 24..29 de l'identificador.
  Cas zero va a 0x1c077840, encara no reconstruït.
- 0x1c077a58 valida l'ID amb 0x1c07795c. Per 0x42001401 el bit 31
  és zero i este helper retorna zero immediatament.
- 0x1c077a64..0x1c077a78 selecciona màscara segons bits superiors;
  per l'ID estudiat usa **0x3f00ffff**, resultat **0x02001401**.
- 0x1c077a7c crida **0x1c099c20**, amb descriptor local inicialitzat.
  La consulta retorna 0 i ompli camps +4/+8/+0xc/+0x10 en èxit
  (0x1c09b440..0x1c09b44c), inclòs punter callback a +0x10.
  Error o callback nul deriva a 0x1c077bc8 abans de preparar la invocació.

### Resultat específic de 0x02001401

Traça de comparacions de la consulta, contrastada amb bytes originals:

1. Major que 0x02001300 → 0x1c099cc4.
2. Menor/igual que 0x32000100 → 0x1c099cd4.
3. Menor/igual que 0x02001805 → 0x1c099e10.
4. Menor/igual que 0x02001501 → 0x1c099e20.
5. Resta 0x02001301 amb aritmètica de 64 bits → índex **0x100**.
6. `cmp x8,#0x11; b.hi 0x1c09b450`: retorna **1**, inicialitzat a
   0x1c099c24, sense passar per la taula ni escriure un callback.

**Comportament verificat:** esta consulta rebutja l'ID normalitzat de
MiToken. No és una prova d'absència global del servei. Encara falta unir
l'entrada SMC de ScmDxeLA amb esta ruta, resoldre el dispatch alternatiu,
possible selecció en runtime i altres components carregats. No s'afirma
que el dispositiu execute este build/slot ni que totes les crides fallen.
Si esta ruta és l'efectiva, MiToken no arribaria a interpretar la política
per este servei, sinó a la seua via d'error; conseqüència **condicional**.
La traducció completa de l'error fins a UEFI continua pendent.

## Hipòtesis descartades i límits

Les cinc coincidències literals del valor reduït 0x1401 són desalineades,
no registres de servei demostrats. La instrucció `mov w8,#0x1401` a
0x1c089ae0 compara una mida: el camí acceptat usa 0x1400 com a capacitat
abans de cridar 0x1468320c. No identifica per si sola el servei SCM.
La consulta real construïx constants amb mov/movk i taules de salts:
queda descartat usar l'absència de literal complet com a prova d'absència.

No s'ha reconstruït el format de política ni una garantia de recompte.
Bucle i lectura fora del rang de MiToken continuen condicionals; neteja
omesa continua defecte local. VerifiedBoot no canvia de classificació.
No hi ha tokens, payloads, execució de firmware ni conclusions de bypass.

## Proves i represa

`test-tz-structure.py`: quatre casos de mapatge/límits sintètics.
`test-tz-dispatch-model.py`: normalització/rebuig i fronteres de rang.
El model representa només les branques enumerades, no emula TZ.
Bytes amb VA/offset en `tz-dispatch-bytes.txt`.

Represa concreta: 0x1c077840 (cas owner zero), callers de 0x1c07798c i
camí d'error 0x1c077bc8 fins al retorn SMC. Després determinar si hi ha
una altra consulta per 0x02001401 abans de continuar el productor de política.

## Owner zero i retorn al monitor — continuació des de 8a35afa

Revisió sobre els mateixos hashes TZ i ScmDxeLA, verificats de nou abans
de llegir les exportacions. Adreces TZ = VA ELF. Bytes puntuals amb offsets
originals en [tz-return-bytes.txt](tz-return-bytes.txt).

### Cas 0x1c077840

Precondició al caller: `(ID >> 24) & 0x3f == 0`. No és una segona cerca
indistinta de serveis Qualcomm. Conserva els dos primers words del context
i neteja els altres set. Després de validar ID amb 0x1c07795c:

| Funció = ID & 0xffff | Comportament verificat |
| --- | --- |
| 0 | Escriu 0x10001 al primer word. Compatible amb consulta de versió, sense atribuir nom original. |
| 1 | Exigix `(argument & 0xffffffffbfff0000) == 0x80000000`; selecciona pel low16 de l'argument. |
| Altres | Escriu -1 de 64 bits i registra error. |

Per funció 1, subconsultes 0/1 retornen 0; 0x7fff/0x8000 criden
0x1c0931d4 amb 1/0 respectivament i invertixen el resultat booleà.
Este helper fa una altra SMC via 0x1c136cc0, ID 0x40; l'efecte intern
continua desconegut. Resta de subconsultes: -1. No hi ha crida a
0x1c099c20 ni lectura del paquet de política en 0x1c077840.

**Descartat:** que este cas siga un fallback local al servei MiToken
0x02001401 després del rebuig; l'owner d'este ID és 2, no 0.
Tampoc es pot equiparar directament esta funció amb la variant antiga
ScmDxeLA que emet SMC w0=1: falta saber com l'EL3 tracta eixa convenció.

### Callers i condicions d'entrada

Una crida directa a 0x1c07798c en l'ASM i referències Ghidra: **0x1c0387fc**,
dins 0x1c0386a4. No és una prova d'absència d'altres callers indirectes.
0x1c0386a4 requerix un punter no nul a un context de 0x70 bytes i el copia
a la pila. Separa els valors especials 0x7ffffffe/0x7fffffff i IDs amb
`(ID & 0x3f00ff00) == 0x04000000`. 0x42001401 no satisfà cap excepció.
El camí normal exigix un context local disponible via 0x1c038f70, inicialitza
un flag de retorn a zero i passa el context a 0x1c07798c.

Caller de 0x1c0386a4: stub **0x1c1368a0**, crida a 0x1c1368e4. Desa
x0..x13 en 0x70 bytes i passa el seu punter. Abans, 0x1c0392fc consulta
un conjunt de nou entrades amb x6/x7: si retorna context, pren altra
branca (0x1c13691c); si no, 0x1c0390e4 ha d'obtindre un context lliure.
Si no en troba, bucle d'aturada a 0x1c136918. No s'ha modelat com a error
normal retornat. Estes són precondicions reals, no una entrada incondicional.

La rutina d'inicialització 0x1c038154 escriu l'adreça del stub a +0x58
d'un paquet (0x1c038280..0x1c038288) i el límit de pila per CPU a +0x60.
Açò és evidència de publicació de l'entrada, però falta reconstruir el
consumidor del paquet en el monitor: no prova per si sola l'encaminament
de la SMC d'UEFI cap al stub.

### Error de lookup fins a SMC

Per 0x42001401 en este camí, la consulta retorna 1. 0x1c077a80..0x1c077a98
fa dos controls: callback nul suggerix -3, però retorn de consulta no zero
el substituïx per **-1** (CSINV). No atribuir -3 a este rebuig.

0x1c077bc8 no executa l'operació especial owner 0x34, i el context temporal
de servei continua nul. A 0x1c077c54 recupera -1 amb extensió de signe;
la segona consulta de l'ID també falla; 0x1c077c70 escriu -1 al context.
La màscara 0x1a8001 a 0x1c077c7c..0x1c077c90 no conté bit 16 (-1+17),
i el word +0x38 s'havia netejat: es netegen els set resultats +8..+0x38.
Retorn de control de 0x1c07798c: **0x100**, distint del -1 del context.
No s'ha invocat el callback de política ni la preparació 0x1c075ba8.

0x1c03886c..0x1c0388ac empaqueta els quatre primers words del context:
word0=1, word1=0x83 (0x100 != 0x101, flag local zero), word2=-1,
words3..13=0. Copia 0x70 bytes a la pila per CPU (0x1c0388c0..0x1c0388d4).
El stub els recarrega en x0..x13 (0x1c1368f8..0x1c136910) i executa
**SMC a 0x1c136914**. Per tant l'error viatja ací en **x2**, no en x0.
La preparació del missatge és verificada sota les precondicions anteriors.

**Frontera pendent:** esta SMC és una comunicació de TZ al monitor. No hem
seguit encara l'EL3 fins a la represa d'UEFI. Si el monitor retorna -1 en
w0 a ScmDxeLA ARMv8, 0x3880 el transforma en 0x8000000000000003; és una
implicació condicional, no un resultat end-to-end demostrat. En la variant
antiga -1 es transformaria en 0x8000000000000007. El paquet retornat per TZ
no es pot passar directament al model del retorn d'UEFI.

### Abast de la fase

Tres crides directes al lookup 0x1c099c20 en l'exportació: 0x1c0777fc
(helper de consulta de disponibilitat), 0x1c077a7c i 0x1c077c64.
0x1c0777b8 aplica les mateixes màscares i escriu bool de disponibilitat
segons retorn zero, amb retorn propi zero. No és una altra implementació
del servei de política. Altres entrades/monitors no queden descartats.

Cinc proves noves en test-tz-return-model.py: consultes owner zero,
precedència dels errors -1/-3 i distribució del missatge de retorn. Són
models de branques, no emulació ARM ni prova d'encaminament del monitor.
La neteja omesa MiToken continua confirmada al CFG; interpretació de política
continua condicional i no s'activa en el camí de rebuig estudiat. No canvia
la classificació de VerifiedBoot ni hi ha conclusió sobre bloqueig.

## Consulta de disponibilitat i selecció ScmDxeLA

Pregunta de fase: el selector ScmDxeLA comprova transport o disponibilitat
del servei consultat? La taula original i les instruccions responen:

- Al lookup TZ, rang 0x02000601..0x0200060a: índex `(ID-0x02000601)`,
  taula de halfwords a 0x1c13fb00, destí `0x1c09a1dc + 4*entrada`.
  Per 0x02000601, entrada 0 → callback **0x1c0777b8**, amb camps descriptor
  +4=0x02000601, +8=1, +0xc=0x201, +0x10=callback.
- Per **0x02000602**, entrada 0x49d → **0x1c09b450**, retorna 1 sense
  descriptor. La taula concreta no el registra, igual que el cas MiToken
  estudiat, encara que hi ha altres IDs del mateix rang registrats.
- El callback de consulta 0x1c0777b8 retorna zero al seu caller fins i tot
  quan la consulta interna falla; si té punter d'eixida, escriu bool 0/1
  segons èxit del lookup i dos words zero. Cal separar este retorn
  d'operació de la resposta «servici disponible».
- **ScmDxeLA 0x4534** consulta 0x02000601 amb argument 0x02000602.
  A 0x4588..0x458c retorna `1 ^ (estat_EFI >> 63)`. **No llig** el word
  de disponibilitat. A 0x14fc..0x1500 resultat 1 tria inicialització
  0x3744/taula ARMv8; resultat 0 tria 0x17b4/taula alternativa.

Per tant, **descartada** la deducció «taula ARMv8 seleccionada → el lookup
TZ registra 0x02000602». La selecció prova com a màxim una consulta sense
bit d'error EFI. Pot ser una sonda deliberada de la convenció ARMv8:
no es classifica com a defecte sense conéixer el contracte de disseny.
No s'ha demostrat quina branca pren el dispositiu ni la ruta completa de
la sonda a través del monitor. La coincidència de la taula i el wrapper
és evidència estàtica, no una observació runtime.

Reproducció: `python3 scripts/inspect-tz-scm-probe.py`, hashes fixats,
10 entrades reals i bytes de TZ/ScmDxeLA a `tz-scm-probe.json`.
No executa el selector ni el lookup. L'informe de la fase anterior havia
anomenat 0x1c038114 com a inicialitzador: **corregit a 0x1c038154**;
0x1c038114 només llig un flag. La crida al constructor real és a 0x1c059b8c.

### Límit actual de la cadena monitor

0x1c038154 construïx paquet amb word0=1/word1=0x81 i entrada +0x58;
el caller d'inicialització 0x1c038550 és invocat des de 0x146900f8
via literal 0x14690178. El bootstrap recarrega x0..x13 i fa SMC a
0x14690118. Això enllaça la publicació del stub amb una eixida SMC inicial.
No s'ha reconstruït qui consumix els comandaments 0x81/0x83 a EL3,
ni el mapping dels arguments de la SMC d'UEFI a x0..x13 del stub.
La reconstrucció des d'una crida arbitrària UEFI fins al retorn no està
completa: cal este consumidor o una especificació local verificable.
No s'ha assumit que l'EL3 de bootstrap siga el monitor definitiu de runtime.

No s'han obert noves línies de recursos/PE: els pendents amb valor informatiu
ara són estes fronteres funcionals, no repetir censos de GUID. Les fonts
públiques pertinents no estan disponibles localment; no s'ha fet xarxa.
