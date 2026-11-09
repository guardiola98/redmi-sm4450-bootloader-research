# MiToken: contractes i errors pendents

Anàlisi estàtica offline, 2026-11-09. Font: `work/MiTokenDxe.asm`,
`work/LinuxLoader.asm` i PE original MiTokenDxe, SHA-256 verificat
`5960ae5e4b2ae712f8ef1e854cb37e3fcaf0ecb1427aa40eeebd733829be68b9`.
Les adreces són RVA. No s'ha executat firmware.

## Callback +0x18: 0x1ac0 → 0x1b4c

Contracte reconstruït: x1 apunta a una eixida de **64 bits**; x0 (interfície)
és substituït per x1. Reserva 0x4c4 bytes amb 0x2cac, conserva el búfer en
x20 i escriu zero a l'eixida a 0x1b90, sense validar el punter.
0x2cac → 0x2c5c arredonix la reserva a pàgines; 0x2cd8 → 0x2c14 marca
el bloc com a disponible en l'allocator intern (no és un FreePool directe).

La primera localització (GUID a 0x9078) ignora el retorn i consulta +0x48
si el punter retornat no és nul; tampoc comprova el retorn del callback.
El word local a sp+0xc que este servici hauria d'omplir no té una
inicialització explícita en el pròleg. La inicialització de sp+0x10 en avant
no el cobrix. **Defecte potencial:** si no s'escriu, la comparació posterior
pot consumir dades indeterminades de pila. Cal reconstruir el proveïdor
per establir quan pot passar; no atribuïm valors concrets a eixes dades.

Segona localització (GUID 0x9098): error amb bit 63 → retorn del mateix
estat. El callback +0x38 rep ID 0x02001401, argument 0x22 i descriptors
locals. Error amb bit 63 → mateix retorn. Resposta[0] distinta d'1 →
0x8000000000000007. Eixida roman zero en estos errors.

**Comportament verificat / defecte potencial de recursos:** estes tres
vies ometen 0x1cd0..0x1cd4, l'únic alliberament local. Després d'una reserva
reeixida, el bloc queda ocupat en l'allocator; impacte acumulatiu condicionat
a repetibilitat de les crides i errors. No s'ha establit freqüència de crida
ni esgotament accessible. No confondre-ho amb la fallada de reserva.

Amb resposta[0]=1 extrau el nibble baix de búfer[0xc]. Si no és zero,
llig un recompte little-endian de 32 bits de búfer+0xdc i compara el word
local amb elements de 4 bytes des de +0xe0. Si no troba coincidència,
neteja l'eixida; si la troba, conserva el nibble. Retorna l'estat SCM
conservat en x21; no força zero en el camí de resposta vàlida.

**Defecte potencial de robustesa:** índex efectiu de 8 bits a 0x1ca0 i
comparació `cmp w8,w9,UXTB` a 0x1cb4. Sense coincidència, recompte >=256
no pot igualar l'índex i el bucle es repetix. Recompte 250..255 llig més
enllà dels 249 elements que caben en la mida sol·licitada 0x4c4. La reserva
real s'arredonix a una pàgina: això **no demostra accés fora de la reserva
física**, però sí lectura fora del rang declarat al servici. Per >=256,
l'últim byte llegit és +0x4df. Un match anterior pot acabar el bucle.
La possibilitat que el proveïdor produïsca estos recomptes és una
**hipòtesi no confirmada**; no hi ha entrada hostil ni bloqueig demostrat.

## Callback +0x10 i caller ABL

0x1a58 rep cadena en x1, firma en x2 i longitud de firma en w3.
Calcula strlen abans de validar amb 0x1e84: una cadena nul·la arriba als
ASSERT del helper 0x25d8, no a un retorn d'error normal. 0x1b0c passa
longituds de 32 bits i transforma qualsevol retorn intern no zero en
0x50 (0x1b38..0x1b40). **Comportament verificat:** pèrdua de detall dels
errors, però no conversió d'error en èxit en este wrapper.

ABL 0x57de0 invoca +8 (obtenció), mentre 0x57e48 → 0x5a1fc carrega
+0x10 (verificació). La primera crida no és una segona verificació
criptogràfica: correcció de terminologia de les notes històriques.
ABL reserva longitud consultada+1 a 0x57dc0, distinta de la reserva exacta
de 0x55c7c. Amb consulta 128, 129 bytes permeten també el NUL que escriu
0x57e44 a l'índex retornat, fins i tot quan la cache informa 128.
**Candidat descartat sota reserva reeixida i contracte normal:** desbordament
per eixe NUL. Falta comprovar la ruta completa de fallada de l'allocator ABL;
no s'afirma que un nul retorne normalment al caller.

## Contrast de bytes i límits

Lectura del PE amb mapatge de seccions PE, sense assumir RVA=offset:

| RVA | Bytes little-endian | Instrucció de l'exportació ARM64 |
| --- | --- | --- |
| 0x1b90 | 7f 02 00 f9 | str xzr,[x19] |
| 0x1bec | 80 07 f8 b7 | tbnz x0,#63,0x1cdc |
| 0x1c14 | c0 06 f8 b7 | tbnz x0,#63,0x1cec |
| 0x1c20 | 21 07 00 54 | b.ne 0x1d04 |
| 0x1ca0 | 2c 1d 40 92 | and x12,x9,#0xff |
| 0x1cb4 | 1f 01 29 6b | cmp w8,w9,UXTB |
| 0x1cb8 | 41 ff ff 54 | b.ne 0x1ca0 |
| 0x1cd4 | 01 04 00 94 | bl 0x2cd8 |
| 0x1d00 | 02 00 00 14 | b 0x1d08 |
| 0x1d04 | f5 0f 41 b2 | mov/orr x21,0x8000000000000007 |

Proves: `python3 scripts/test-mitoken-contract-model.py`, quatre casos,
amb enumeració de recomptes 0..255 i detecció sintètica de cicle. No simulen
SCM, memòria real, RSA ni firmware. Següent: identificar callers de +0x18,
contracte del proveïdor del recompte i escriptura garantida de sp+0xc.

Contrast addicional amb PE LinuxLoader SHA-256
`60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`: ABL `0x57dc0`: `00 05 00 11`. ABL `0x57e44`: `9f 6a 28 38`. ABL `0x5a200`: `08 08 40 f9`.

## Revisió de contractes des de 2cd75e2

### Referències i abast de la cerca

Taula original confirmada: 0x9648 = `[1,0x1784,0x1a58,0x1ac0]`;
0x1ac4 és una branca directa a 0x1b4c. A 0x1ae4 es passa la taula a
la instal·lació del protocol (crida indirecta 0x1afc). No s'ha trobat cap
altra crida directa a 0x1b4c en l'exportació MiToken.

| Localització MiToken en ABL | Ús del punter recuperat |
| --- | --- |
| 0x55b60, local x29-0xe0 | +8 via 0x59fe0, consulta i obtenció |
| 0x57d1c, local x24-0x10 | +8 a 0x57de0; +0x10 via 0x5a1fc |
| 0x58550, local x24-0x10 | +8 a 0x585bc/0x5861c; +0x10 a 0x5865c |

Les tres referències ADRP/ADD identificades al GUID 0xb1800 no porten a
+0x18. La crida +0x18 de 0x55e.. correspon a una altra interfície de
pantalla (missatges `WtShowScreen`), no basta coincidir en l'offset.
VerifiedBootDxe no conté els bytes del GUID MiToken; MiTokenDxe els conté
una vegada i ABL una vegada. **No s'ha identificat caller de +0x18 en
estos tres mòduls.** No equival a absència global: les crides indirectes,
àlies o altres mòduls no analitzats impedixen afirmar que siga codi mort.

### Separació de les dues respostes

Identificacions llegides del PE, sense assignar tipus originals no provats:

- GUID 0x9078: `b0760469-970c-487a-a4b5-28db7b45cef1`;
  +0x48 rep un punter a word de 32 bits en sp+0xc. El text posterior
  `The sn in dp don't match chip sn` és compatible amb un número de sèrie;
  no és prova de les garanties del servei.
- GUID 0x9098: `77ed108d-8524-4b8b-9d2e-34987aecb9c1`;
  +0x38 rep x1=0x02001401, x2=0x22, x3=sp+0x38 i x4=sp+0x10.
  x3 apunta als words de 64 bits `{búfer,0x4c4}`. No s'ha demostrat que
  0x22 siga una longitud: és un argument independent, no una cota del comptador.

Hi ha **dues regions distintes**: resultats locals SCM i búfer extern de
política. Els 32 bytes sp+0x10..sp+0x2f estan inicialitzats amb zeros per
0x1b84; la primera entrada de 64 bits ha de ser 1 per continuar. Si el
servei no escriu esta entrada, el caller retorna error i no interpreta la
política. Açò descarta el candidat «resposta local SCM completament absent
acceptada com a èxit» sota memòria preservada.

En canvi, la reserva retornada per 0x2cac no es neteja en este caller.
L'allocator pot reutilitzar blocs (0x2998..0x2a28) sense zero-fill visible
abans del retorn. Que la primera entrada SCM siga 1 **no demostra** que
s'haja escrit tot el búfer. El caller no comprova bytes escrits, capçalera,
versió ni longitud interna abans de llegir +0xc i +0xdc. La mida 0x4c4
passada al servei limita el rang declarat, però no acota per si sola el
valor de 32 bits emmagatzemat a +0xdc. Un búfer de mida correcta pot
codificar 256; el test sintètic nou ho comprova sense generar una petició.
Només el contracte/implementació del proveïdor pot descartar-ho.

### Classificació revisada

| Observació | Classificació i condicions |
| --- | --- |
| Reserva reeixida seguida d'error de localització, transport o resposta | **Defecte de neteja confirmat al CFG**: omet el helper que marca disponible el bloc. No depén de comptadors fora de contracte. Activació i acumulació en un caller real no demostrades. |
| Resposta local SCM no escrita | **Candidat descartat** com a fals èxit: inicialment zero, es requerix 1. |
| Word sp+0xc no escrit pel primer servei | **Comportament condicional**: consum indeterminat només si després hi ha política amb nibble i recompte no nuls. Retorns ignorats i falta d'inicialització confirmats; fallada real del proveïdor no provada. |
| Recompte >=256 sense match | **Comportament condicional verificat pel model**: cicle. Producció d'eixe recompte és hipòtesi sense evidència. |
| Recompte 250..255 | **Comportament condicional**: lectura més enllà de la mida declarada, sense demostrar eixida de la pàgina reservada. |
| Resposta parcial amb entrada SCM=1 | **Hipòtesi**: manca validació local, però es desconeix si viola el contracte del proveïdor. |

No es pot elevar el cicle a defecte reachable sota un contracte que limite
el recompte a <=249. Tampoc es pot assumir eixa garantia pel simple fet
que el caller passe 0x4c4. No s'ha demostrat activació de cap anomalia des
d'ABL ni impacte sobre autenticació.

### Reproducció i límit de fonts

`python3 scripts/inspect-mitoken-contract-evidence.py` verifica hash,
mapatge RVA, GUID, taula i bytes de les instruccions de preparació/lectura.
`python3 scripts/test-mitoken-contract-model.py`: cinc proves passen.
No executen ni emulen firmware. S'ha contrastat l'ASM amb estos bytes,
no s'ha fet un segon desassemblatge independent.

El corpus local inspeccionat conté els tres PE/exportacions anteriors,
però no la implementació del proveïdor SCM ni del callback +0x48.
Les referències públiques guardades en docs són enllaços, no còpies de
fonts d'estos proveïdors. Per respectar offline no s'han consultat per
xarxa, ni s'ha usat la documentació QSEE com a contracte d'esta crida SCM.
**Comparació amb fonts públiques i garanties del productor pendents per
falta de fonts locals pertinents.**

Següent pas: disposar localment dels proveïdors dels dos GUID i del servei
0x02001401, identificar el format de política i els seus límits, i ampliar
la cerca de consumidors de MiToken a altres mòduls ja extrets. Fins llavors,
les conclusions sobre neteja són locals i les de dades malformades condicionals.
