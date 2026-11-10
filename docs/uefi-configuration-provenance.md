# Procedència i contractes de configuració UEFI

2026-11-10, continuació des d'`a566643`. Anàlisi exclusivament estàtica
del TE exterior de `uefi.elf`, de ScmDxeLA i del recurs RAW inventariat.
**La cadena local està reconstruïda; no és una lectura de configuració
efectiva del dispositiu.** Cap accés a MMIO, execució, xarxa o font nova
de firmware. [Recurs i valors](scm-static-config.json),
[bytes i taules](uefi-config-contract.json).

## Origen de la biblioteca que consulta SCM

El TE té SHA-256
`064e33de95ebb586b0f103cfa03510a5459bca6068318294981673af8b4e9ed0`.
Les adreces següents són **VA preferides**, no RVA de PE ni adreces runtime.
El mapatge usa ImageBase `0xa7001000`, delta de capçalera `0xf38` i
les seccions de [uefi-te-structure.json](uefi-te-structure.json).

1. `0xa7012410` reinicia l'estat de configuració i passa el nom literal
   `uefiplat.cfg` a `0xa70144a0` (`BL 0xa7012440`). El buscador enumera
   fitxers FFS de tipus 2, compara el nom UI (secció 0x15) i obté la secció
   RAW 0x19. No és una lectura d'una variable UEFI o d'un fitxer Android.
2. Es processen `Config`, `MemoryMap`, `RegisterMap`, `ConfigParameters`
   i `ChipIDConfig`. La taula de paràmetres té parelles de punters
   `{nom,valor}` de 16 bytes, amb valors textuals copiats a memòria pròpia.
3. `0xa700f290` inicialitza el registre de biblioteques compartides i
   publica les bases/comptes al bloc d'informació (+0x48/+0x50 per regions,
   +0x58/+0x60 per paràmetres). `0xa700f34c` crida `0xa701d73c`, que
   registra `UEFI Config Lib`, revisió `0x10002`, taula `0xa703c428`.
4. La interfície de biblioteques compartides `0xa703c3d0` s'exporta en
   un HOB GUID `bedaeabc-5e70-4d66-9733-213d072b9d04`. Coincidix amb
   els bytes de `ScmDxeLA 0xd048`. SCM `0x8524/0x84d4` busca el HOB,
   `0x621c` llig el punter a +0x18 i `0x6174` demana la biblioteca per
   nom amb versió sol·licitada zero. `0x61b8` invoca el callback +0x18.

| Offset de biblioteca | Entrada TE | Contracte reconstruït |
| --- | --- | --- |
| +0x08 | `0xa701d380` | Busca una regió de memòria per nom. |
| +0x10 | `0xa701d44c` | Busca un paràmetre textual, comprova capacitat i copia la cadena. |
| **+0x18** | `0xa701d714 → 0xa701d578` | Getter de 32 bits usat per SCM; delega al parser de 64 bits i reduïx el valor. |
| +0x20 | `0xa701d728 → 0xa701d5b8` | Getter de 64 bits sobre la mateixa taula. |

El getter numèric compara noms sense distingir majúscules ASCII
(`0xa701b760`), amb cerca des de l'índex zero: **primer match**.
Clau absent: EFI error 14; taula/base no preparada: error 6;
out-pointer nul al getter de 64 bits: error 2; valor nul o format
rebutjat: error 3. El parser admet decimal i prefixos `0x`/`0X`; el
valor `0xC4` és representable. No s'atribuïx validació exhaustiva dels
casos d'overflow decimal o cadenes degenerades a esta revisió.
El wrapper de 32 bits també pressuposa un out-pointer vàlid: no hereta
el control de NULL del getter de 64 bits perquè li passa el seu local
de pila. SCM li proporciona locals vàlids; no hi ha caller nul provat.

## Valors locals i sobreescriptures

| Element | Evidència del recurs / codi | Conclusió acotada |
| --- | --- | --- |
| `SecurityFlag` | Una fila, línia 113, `0xC4`. | Si esta taula arriba intacta al getter, retorna 0xC4: el bit 0x100 de logs SCM no està actiu. |
| `SmcInvokeConfig` | Cap fila, tampoc amb comparació ASCII sense majúscules. | En la cadena reconstruïda, consulta no reeixida; SCM conserva 256/256/256, 11.296 bytes de taules. No declarar-los valors runtime universals. |
| `ConfigParameterCount` | 64; 43 files de valors després de la declaració, sense noms duplicats. | És capacitat de la taula textual, no recompte d'objectes SCM ni de política MiToken. |
| `PlatConfigFileName` | `"uefiplatLA.cfg"`; `OsTypeString="LA"`. | La referència revisada del primer és `0xa7013800`, generació d'informació de versió. No substituïx el literal `uefiplat.cfg` en el carregador reconstruït. |
| `ChipIDConfig` / `ChipID_RegAddr` | Ni secció ni clau presents en este RAW. | La sobreescriptura per chip existeix al codi però no hi ha files aplicables en este recurs. No llegir el registre del dispositiu per decidir-ho. |

La sobreescriptura `0xa7012c70` requerix tres camps, una clau existent
`ChipID_RegAddr` i que el camp hardware `(word >> 12) & 0xffff` coincidisca
amb el selector. Busca el nom de paràmetre existent amb comparació exacta
(`0xa701b668`), assigna una cadena nova i substituïx el punter de valor
(`0xa7012e70`). **No crea una clau absent**. La cerca del getter, en canvi,
és insensible a majúscules. No s'ha observat una discrepància per a les
dues claus SCM; no hi ha dades de ChipIDConfig en el RAW seleccionat.

El registre compartit `0xa7018b74` afegix entrades; la consulta
`0xa7018c60` amb versió zero retorna el primer nom coincident
(`0xa7018ce8 → 0xa7018d4c`). Afegir una segona biblioteca amb el mateix
nom **no prova una substitució** d'esta primera. No hi ha un setter de
claus en la taula de cinc words revisada. Això no prova immutabilitat:
els punters de dades també es publiquen al bloc d'informació i no s'han
exclòs escriptures per àlies, un altre HOB, un registre reinicialitzat o
un recurs diferent en un altre entorn.

El cens **existent** de noms FFS en `uefi.elf` i `tools.fv` conté un
`uefiplat.cfg` i cap `uefiplatLA.cfg`. No és una cerca de tots els sistemes
de fitxers del paquet ni una prova d'absència global. Les cadenes
`SmcInvokeMaxRemoteObj`/`SmcInvokeMaxLocalAsyncOp` dels errors SCM no són
consultes verificades a configuració: l'inicialitzador llig la clau
empaquetada `SmcInvokeConfig`. No confondre suggeriments de diagnòstic
amb claus efectivament consumides.

## Defectes observats en seguir el contracte

**Getter de 32 bits: temporal no inicialitzat en error.**
`0xa701d578` reserva pila i passa `x29+0x18` al getter de 64 bits sense
inicialitzar-lo. `0xa701d5b8` retorna per clau absent sense escriure eixe
out-pointer (`0xa701d618/61c`). En tornar, `0xa701d590` el llig
incondicionalment: si els 32 bits alts són zero, escriu els baixos al
caller (`0xa701d5a8`) i conserva l'error; en cas contrari substituïx
l'error per EFI error 2. Defecte local d'inicialització/contracte de
sortida confirmat en la consulta d'una clau absent, sota esta biblioteca.
Els bytes indeterminats i l'estat final concret no estan observats.

SCM `0x4774` només usa l'out-word de `SmcInvokeConfig` amb estat zero;
`0x1564..0x1570` també condiciona l'ús de `SecurityFlag`. **Cap dels dos
consumix com a configuració vàlida el word escrit en error.** Amb qualsevol
valor previ del temporal, un error de consulta continua sent no zero;
es mantenen els defaults o s'ometen els logs. Es descarta esta cadena
concreta de fals èxit, sense estendre la garantia a altres consumidors.

**Parser de taula: frontera incorrecta.** `0xa70129d0` reserva
`16*capacitat` bytes. El guard a `0xa7012af4/af8` usa `count > capacitat`,
seguit de comprovació de capacitat no nul·la. Amb `count == capacitat`
entra en la inserció: stores de punters a `base+16*count` i `+8`
(`0xa7012bd8/0xa7012c08`), fora de la taula sol·licitada. El comprovant
ASSERT `count < capacitat` només és dins de l'altra branca i no ho evita.
És una frontera errònia confirmada; **no activada pel recurs local de
43/64 valors**. L'allocator pot subassignar dins d'una pàgina: no s'afirma
escriptura fora d'una pàgina física, ni capacitat d'alterar el recurs
oficial, ni corrupció runtime. El model només calcula índexs, sense
generar un fitxer de configuració que active la frontera.

## Reproducció i cobertura

`python3 scripts/inspect-scm-static-config.py` inventaria línies i seccions;
no emula el parser. `python3 scripts/inspect-uefi-config-contract.py`
verifica hash del TE dins d'`uefi.elf`, mapatge, callbacks i identitat HOB.
`python3 scripts/test-uefi-config-model.py`: sis proves sintètiques de
validesa de temporals, guards SCM, frontera de taula i mapatge.

L'import TE antic no disposava de loader natiu. Ara s'ha usat BinaryLoader
sobre els bytes originals a base de fitxer `0xa7001f38`, processador
`AARCH64:LE:64:v8A`, compilador `default`, amb pre-script
`scripts/ghidra/MapAuditTe.java` i post-scripts `DumpFunctions.java` i
`DumpInstructions.java`. El pre-script separa header/text/data/reloc,
fixa permisos d'anàlisi i entrada `0xa700e0b8`; no reubica ni executa
firmware. Un primer intent de rebase alterava el mapatge i es va excloure;
només s'han usat exportacions `work/ConfigTeLayout.*`, contrastades amb
bytes originals. És una revisió funcional de configuració, no de tot el TE.

Límit restant: confirmar la identitat de la taula efectiva requeriria
evidència addicional de l'entorn, o traçar totes les possibles escriptures
per àlies. No és necessari per confirmar els defectes locals ni per
concloure que els dos callers SCM revisats conserven els seus guards.
