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
