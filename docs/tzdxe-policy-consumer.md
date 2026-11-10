# TzDxeLA: consumidor independent del servei de política

Revisió estàtica acotada, 2026-11-10. SHA-256 PE
067ae49e6dab576b1d5bbb2be6ede7c498440d70b3f64ad9d47bbbec742a0af0,
verificat abans d'importar a Ghidra. Evidència original en
[reviewed-pe-evidence.json](reviewed-pe-evidence.json). Adreces RVA.

Pregunta: un altre consumidor documenta garanties del servei 0x02001401?
**Resultat:** TzDxeLA 0x3454 el consulta independentment; no obté la
interfície MiToken ni invoca el seu +0x18. La mida torna a ser 0x4c4,
però la garantia de zero-fill és d'este consumidor, no del productor TZ.

## Ruta i precondicions

La taula 0xf250, revisió 0x10007, és publicada amb GUID
9a10db8c-08ba-45ca-a894-40c2514d4645 a la inicialització 0x2958.
Entrada +0x18=0x1e74 → crida 0x1ed4 a 0x1d08. També hi ha altres
callers de 0x1d08 en les vies de càrrega. Esta rutina prepara una petició
SCM +0x28, operació 1; **només si retorna no zero** crida diagnòstic
0x3454 a **0x1e50**. Això identifica un caller concret de la rutina
nova, però no prova que la fallada siga activable des d'una entrada real.

0x3454 consulta ChipInfo (o usa estat prèviament preparat), després SCM
0x02000604. Si transport no negatiu, marcador=1 i estat &0x501 no zero,
retorna abans de política. La consulta 0x3200010b separa logs xifrats:
error de transport retorna; resultat[1]=1 pren una altra via. Per arribar
a la reserva de política cal superar estes branques. Els valors reals de
configuració/estat no s'han llegit del dispositiu ni assumit.

La consulta usa el protocol SCM conegut, GUID 0xf128, via helper 0x3bdc.
No és un altre dispatcher segur ni un productor alternatiu. Es manté la
conclusió de rebuig en el lookup TZ reconstruït sota les seues precondicions.

## Contracte de búfers i errors verificat

- 0x37ec..0x37f4 reserva 0x4c4 amb alineació 0x1000 via 0x4380/0x4330.
  Mida arredonida a pàgina. Reserva nul·la → retorn; no inferir que els
  errors EFI ordinaris de l'allocator tornen nul sense passar per ASSERT.
- 0x3824 i **0x3834** netegen 0x4c4 bytes de pila i del búfer extern
  amb 0x9224. Els descriptors/resultats locals també es posen a zero.
- 0x3844/0x384c construïxen 0x02000603; **0x3854** li suma 0xdfe →
  **0x02001401**. 0x3850 posa argument descriptor 0x22, i 0x3838 desa
  `{punter,0x4c4}`. Crida SCM +0x38 a **0x3860**.
- Error bit63 → 0x39c0 → registre d'error → epíleg 0x3994. No llig
  política en eixe camí. En transport no negatiu copia 0x4c4 a pila;
  exigix estat exactament zero i examina **byte +0xc & 0x0a**.
  No consulta el recompte +0xdc de MiToken ni aporta un màxim per a ell.
- No exigix marcador de resposta=1 en esta consulta concreta. Això no
  demostra acceptació de política no escrita: els bytes s'han netejat,
  i la màscara és zero si el servei deixa el búfer intacte. No s'ha
  demostrat cap resposta parcial real ni cap efecte d'autenticació.

**Descartat per este consumidor:** heretar dades antigues del búfer
sense cap escriptura del servei. **No descartat en MiToken:** allí no
existeix la mateixa neteja local. Dos consumidors que passen 0x4c4 no
constitueixen una especificació del límit del recompte.

## Nova observació de recursos

La via que reserva el búfer de política no crida l'alliberador 0x42e8
ni conserva el punter en una cache pròpia. L'error de 0x3860 torna per
0x3994 sense alliberar-lo; també passa en les eixides posteriors d'esta
via. L'allocator marca el node ocupat (0x4218, o 0x42d4 si reutilitzat),
i 0x42e8 seria qui el marcaria disponible (0x4318). El free de 0x1e58
allibera **una altra reserva**, la petició de 0x38 bytes del caller.
La branca de logs xifrats sí té neteja explícita del seu altre búfer.

**Defecte local de neteja confirmat**, independent del de MiToken, amb
caller directe identificat en diagnòstic d'error de càrrega. Possible
retenció d'almenys una pàgina per entrada que reserve amb èxit; acumulació,
repetibilitat, activació real i impacte global **condicionals**. No es
classifica com a vulnerabilitat demostrada ni com a mecanisme de desbloqueig.
Este candidat mereix més prioritat que repetir els models de +0x18:
la següent pregunta és si els callers registrats poden tornar repetidament
per este error sota un contracte normal, amb estat que permeta diagnòstic.

No s'ha creat un model redundant del mateix salt sense free. Els bytes,
callers i distinció entre reserves aporten l'evidència nova. Les cotes
internes del productor de política continuen desconegudes. No s'ha
executat la rutina, llegit logs del dispositiu ni usat identificadors reals.

## Contractes, repetició i límits — continuació des d'a566643

La rutina `0x3454` és diagnòstica i no retorna un estat aprofitable pel
caller. `0x1d08` posa a zero l'identificador de resultat quan SCM +0x28
retorna **qualsevol estat no zero**, crida diagnòstic i després allibera
la petició pool de 0x38. Si el diagnòstic retorna normalment, el caller
`0x1e74` transforma identificadors `0` i `0xffffffff` en EFI error 1;
altres identificadors produïts amb estat SCM zero donen èxit. No conserva
l'error EFI específic, però tampoc el convertix en èxit. Si la reserva
pool de 0x38 falla, `0x1d08` retorna zero sense diagnòstic; el mateix
caller ho transforma en error 1. No confondre-ho amb la reserva de política.

| Porta de `0x3454` | Resultat verificat |
| --- | --- |
| ChipInfo encara no inicialitzat (`f568 & 1 == 0`) | Error de localització/getter: eixida; target sense configuració: registra i continua sense fixar el flag. Target reconegut fixa `f568=1`. |
| Estat de seguretat `0x02000604` | Només transport no negatiu, marcador 1 i bits `0x501` actius causen eixida immediata. Error de transport es registra i continua; protocol absent també continua. |
| Consulta de xifrat `0x3200010b` | EFI_ERROR: eixida; resultat[1]=1: branca xifrada; qualsevol altre resultat no negatiu: política. Protocol absent salta directament a reservar política (`0x3590`). |
| Després de reservar política | Protocol encara absent a `0x3840`, error SCM, estat positiu, màscara de política zero o final normal: tots retenen la reserva ocupada. |
| Branca xifrada | Reserva pròpia de 0x3000; després d'èxit d'assignació, l'eixida comuna `0x3a18 → 0x43bc → 0x42e8` marca lliure el bloc també amb protocol absent o error SCM, si el flux arriba a eixa eixida. |

**Els flags no són una barrera d'una sola execució.** `f568` evita repetir
ChipInfo; `f588`, llegit a `0x38b8` i fixat a `0x3920`, només afecta el
diagnòstic de versió/log posterior a reservar i consultar política. Cap
dels dos impedix una altra reserva de política. La rutina no conté un
bucle de reintents de política: una entrada pot reservar com a màxim un
bloc de política. La repetició requerix noves entrades a la rutina, que
poden vindre de múltiples callsites dins d'una crida QSEE, com es delimita
més avant. La reentrada simultània, el TPL efectiu i la sincronització
entre clients no s'han provat; la finestra de notificació posterior és condicional.

Callers directes de `0x1d08` confirmats als bytes: `0x1ed4` (entrada de
protocol +0x18), `0x216c`, `0x25c8` i `0x28c4` (altres vies de càrrega).
La referència `0x28c4` pertany a un tram sense funció delimitada en
l'exportació Ghidra, per la qual cosa no se li atribuïx un contracte d'entrada
complet. `0x2018` també crida `0x1e74` després de llegir un fitxer.
Cap d'estos fets demostra quantes vegades els consumidors de plataforma
invocarien el protocol, ni que els estats segurs deixen passar la política.

### Què alliberen realment els helpers

- `0x50a8`: wrapper de BootServices.FreePool. No valida NULL; EFI_ERROR
  porta a ASSERT. El DxeCore local retorna error 2 davant de NULL, com
  es documenta en [SCM](scm-initialization-analysis.md). `0x1e58` li passa
  el punter pool de la petició, no el búfer de política.
- `0x42e8`: alliberament lògic de l'allocator de pàgines **propi de
  TzDxeLA**. NULL o punter desconegut no fan res; una coincidència posa
  busy=0 i suma la capacitat del node a `f598`. No neteja bytes, no trau
  el node i no crida FreePages. No comprova si ja estava lliure.
- `0x3fa8`: destructor que recorre esta mateixa llista, però només
  FreePages/FreePool dels nodes amb busy=0 (`CBNZ` a `0x3fdc` evita els
  ocupats). La reserva de política no alliberada continua busy=1 i esta
  rutina tampoc la recupera. Açò reforça la retenció local, sense descartar
  un reset o recuperació externa de plataforma.

La quantificació correcta és **capacitat d'almenys una pàgina que deixa
d'estar disponible per cada entrada reeixida en la reserva de política**.
Pot reutilitzar-se un bloc lliure més gran: no sempre és exactament una
pàgina ni necessàriament una nova crida AllocatePages. Si es repetira la
seqüència amb `n` reserves reeixides i sense recuperació externa, quedarien
`n` nodes ocupats, almenys `4096*n` bytes. **No s'ha demostrat que eixa
seqüència ocórrega**; es manté «defecte local confirmat, acumulació condicional».

### Nova inconsistència de propietat: cache de càrrega ShmBridge

És un búfer diferent del de política. `0x2958` obté ShmBridge amb GUID
a `0xf158`, reserva 0x82000 bytes i desa punter/capacitat en `f4c0/f4c8`
(`0x29f8/0x2a24`). `0x1f2c` retorna el punter de cache quan la mida
demanada és <=capacitat (`0x1f4c → 0x1f98`); només una petició major
allibera i torna a reservar, actualitzant la cache.

Però `0x1e74`, després de còpia i crida de càrrega que retornen normalment,
invoca ShmBridge +0x10 a **0x1ef0**, sense invalidar `f4c0/f4c8`.
Les referències globals revisades només mostren escriptures en inicialització
i creixement, no en esta eixida. El proveïdor concret marca el node lliure
a `ShmBridgeDxe 0x2b7c`. Una segona crida amb mida compatible recupera
un punter a un node lliure **sense tornar-lo a adquirir**.

Conseqüències condicionals separades:

1. Sense altres assignacions intermèdies, una segona eixida torna a marcar
   lliure el mateix node. `0x2b88/8c` incrementa una altra vegada el comptador
   de bytes disponibles, perquè el free no comprova busy. Per al bloc
   inicial de 0x82000, les dues baixes sumen 0x104000 tot i ser un sol bloc.
2. Si un altre client rep eixe node lliure entre crides, la cache antiga
   pot referenciar memòria ara ocupada pel segon client. Cal demostrar
   selecció/reassignació i seqüència de callers per atribuir-hi corrupció real.

**Inconsistència local de propietat confirmada** entre consumidor i
proveïdor; comptabilitat repetida i àlies sota les seqüències descrites.
No és prova que les pàgines s'hagen desmapat, ni d'ús de memòria física
ja retornada a UEFI, ni de vulnerabilitat explotable. El camí no necessita
èxit del diagnòstic ni una política concreta, però sí que les rutines
intermèdies retornen. No s'ha identificat una seqüència real de clients.

Reproducció: `inspect-reviewed-pe-evidence.py` verifica GUIDs/bytes;
`DumpAddressReferences.java` sobre `TzDxeLA.pe` amb objectius `f4c0 f4c8
f568 f588 1d08 1e74 3fa8` reconstruïx les referències en `work/`.
`test-tzdxe-resource-model.py` exercita quatre contractes sintètics de
portes, estat d'error, cache i propietat compartida. No crea contingut
de càrrega ni executa firmware; els noms d'objectes del model són simbòlics.

## Continuació dirigida: callers reals en codi i propietat entre assignadors

Esta revisió substituïx el límit anterior «cap seqüència de clients
identificada» per **seqüència estàtica concreta, activació runtime pendent**.
No s'ha tornat a executar cap escàner GUID: s'han comparat dos GUIDs en
adreces ja identificades i seguit les taules/callers existents.

### QSEE i seqüència finita de càrregues

TzDxeLA publica una segona taula `f2d0`, revisió `0x10002`, amb GUID
`a74862ce-680f-4fe1-a311-df41f4030391` (`f148`). `0x3330` la registra;
`0x2958 → 0x2d2c → 0x3330` arriba allí si la consulta SecurityFlag falla
o si el bit 0x40 està actiu. El valor RAW 0xC4 satisfaria el bit, sota
la cadena intacta de configuració; no és un estat efectiu observat.

| Slot QSEE | Implementació local | Contracte pertinent |
| --- | --- | --- |
| +8 | `0x2da8` | Inicialització diferida `0x2fb0` si `f55c==0`; lookup d'aplicació; si no hi ha ID, càrrega de partició `0x2058` a `0x2f54`. |
| +0x10 | `0x3288` | Operació SCM 2 amb ID. No carrega el búfer estudiat. |
| +0x18 | `0x32d8` | Operació SCM 6. No és +0x18 de la primera taula TzDxeLA ni el callback MiToken. |
| +0x20 | `0x31dc` | Una altra entrada que crida `0x2fb0` a `0x324c` i després `0x279c → 0x2414`; contrastada en instruccions, encara que l'exportació C no la delimita com a funció. |

**Caller exterior concret:** VerifiedBootDxe `0x16c8` localitza exactament
eixe GUID a `d0f8`. Si `d268==0` i el servei previ +0x48 retorna no zero,
`0x1740` invoca QSEE +8 amb nom `keymaster` i un out-pointer local vàlid.
El caller comprova estat a `0x1744`. Açò establix un enllaç de càrrega,
no modifica la conclusió sobre el seu assignador ni sobre autenticació.
No s'afirma que eixa branca s'haja executat en el dispositiu.

`0x2fb0` té esta seqüència local, sense bucle:

1. Si `f558==1`, retorna error 1. En cas contrari consulta la versió de
   característica 10 amb `0x1c48`. EFI_ERROR retorna sense fixar `f558`;
   un resultat acceptat fixa `f558=1` a `0x3000`.
2. Amb versió >=`0x401000`, SecurityFlag consultat amb estat zero i bit
   0x04 actiu, crida SCM operació 0x12 via `0x1c20`. **Retorn no zero**
   (no necessàriament un error) selecciona dues càrregues de serveis:
   `0x3128 → 0x2414`, després `0x318c → 0x2414`. El significat del
   retorn de l'operació 0x12 no s'ha extrapolat d'un nom.
3. Amb SecurityFlag consultat amb estat zero i bit 0x80 actiu, fa una
   càrrega d'aplicació a `0x3078 → 0x2414`. Si falla amb EFI_ERROR,
   intenta la via per etiqueta `0x30b0 → 0x2058`.
4. En les vies que tornen normalment amb zero, el caller fixa `f55c=1`
   (`0x2e48` o `0x3258`): la inicialització diferida no es repetix en
   cada StartApp. Els flags `f558/f55c` són diferents dels diagnòstics
   `f568/f588`; no confondre les garanties.

Les dues vies de servei passen per `0x255c → 0x22f4` (operació 0xb),
no per `0x1d08`; **no generen per si mateixes la reserva de política**.
Errors de càrrega poden conduir als fallbacks `0x21ec`; si estos fallen
amb EFI_ERROR hi ha ASSERT. No assumir que la seqüència sempre finalitza.

Amb les tres càrregues principals acceptades, mides compatibles amb la
cache i retorn normal dels serveis, cada `0x2414` usa `0x1f2c` i acaba
alliberant via ShmBridge a `0x2488`. La segona i tercera no readquirixen
el node. **Una sola entrada QSEE pot contindre alliberaments repetits**;
no cal postular crides externes arbitràries per construir el CFG. La mida
de les particions, retorn de versió/operació 0x12 i èxit de lectura/càrrega
continuen sense verificar. Si la mida creix, s'activa una branca diferent
del helper, que no queda simulada pel model acotat de cache-hit.

Per a política diagnòstica, el fallback d'aplicació aporta dos callsites
consecutius possibles de `0x1d08` en cas d'error. Cada reserva continua
condicionada a les portes de `0x3454`. El segon error pot acabar en ASSERT.
**No hi ha prova de repetició il·limitada ni d'esgotament acumulatiu**;
s'ha precisat una seqüència finita, no observat el seu resultat.

Referències de ShmBridge `71f8`: les lectures reconstruïdes només formen
part de les sumes/restes de `0x2b4c/0x2890`; la selecció de nodes usa
busy/tipus/capacitat/alineació. No s'ha provat que el comptador inflat
controle una reserva. La inconsistència de propietat sí permet la branca
de reutilització per un altre client quan el node està lliure, sota les
precondicions del seu assignador. No hi ha intercalació runtime demostrada.

### Neteja de keystore amb l'assignador equivocat

`0x14e4` crida **`0x2b18` a `0x14f8`** abans d'inicialitzar la cache.
Esta rutina busca una partició i requerix un únic resultat. Calcula la mida
amb `(LastBlock+1)*BlockSize`, localitza ShmBridge (`0x2bc4`) i reserva
via **el seu +8 a `0x2c08`**. No s'ha extret ni examinat el contingut de
keystore; només instruccions i metadades de propietat.

Després de la reserva no nul·la, tant els errors de lectura/SCM com el
final normal convergixen en `0x2d00`: neteja bytes amb `0x5398` i crida
**`0x43bc → 0x42e8` a `0x2d10`**. Este free busca exclusivament la llista
privada TzDxeLA `f368`; ShmBridge registra el node en la seua llista `7110`.
No hi ha transferència ni registre en la llista privada. Sota assignacions
UEFI vàlides i no solapades, el punter és desconegut i el free privat no fa
res: el node ShmBridge queda ocupat. Netejar bytes no allibera capacitat.

**Defecte local confirmat de parella assignador/alliberador**, també en el
camí reeixit, diferent del búfer de política i de la cache de 0x82000.
El caller ignora l'estat retornat de `0x2b18` (`0x14fc..0x1504`), però
no es deriva d'això una conseqüència sobre protecció de claus. No s'ha
provat existència/selecció efectiva de la partició, mida, repetició del
driver ni recuperació externa. En el CFG revisat hi ha una invocació per
entrada d'inicialització, no un bucle que demostre fuga acumulativa.

Validació: inspector ampliat a **9 PE** amb GUIDs a adreces fixes, taula
QSEE i callsites; set proves sintètiques TzDxeLA, incloses parella incorrecta
d'assignadors i portes de seqüència finita. Referències reproduïbles amb
`DumpAddressReferences.java`: Tz `2fb0 2da8 2b18 f558 f55c f148 f2d0`,
ShmBridge `71f8 7110`. Cap payload, dada privada o execució de firmware.

### Contracte resolt de l'operació SCM 0x12 que selecciona serveis

Per a la taula SCM ARMv8 `d130`, +0x28 és `0x3d4c`. El selector resta
1: operació 0x12 usa índex 17. El byte fix `a4d5=0xc6` del switch
selecciona `0x3e00 + 4*0xc6 = 0x4118`; allí conserva **SMC 0x3200010a,
descriptor zero**, i crida `0x3a20` a `0x4124`. No confondre-ho amb
`case 0x12` del C, que correspon a l'operació següent.

El resultat és un estat compost: transport no zero es propaga quan el
camp de resultat és zero; resultat de resposta no zero es transforma en
EFI error 7; amb transport/resultat zero, tipus de resposta `0xee01` dona
error 3 per a esta operació, i altres tipus donen zero. No hi ha un booleà
local constant que determine la branca QSEE. TzDxeLA selecciona les dues
càrregues quan eixe estat és no zero; això és compatible amb una via de
recuperació, no prova per si mateix confusió entre error i autorització.

**Límit resolt:** falta el retorn efectiu d'este servei, no l'enllaç entre
TzDxeLA i ScmDxeLA. No s'ha reconstruït de nou EL3 ni consultat el dispositiu;
no es generalitza esta ruta a la taula SCM antiga. El model de portes ja
tracta el retorn com a estat simbòlic no zero i no necessita noves proves
redundants de la mateixa condició.

### Inicialització parcial: protocols publicats sense rollback

La seqüència `0x14e4` crida `0x2958` i, només si retorna zero, salta a
`0x1ba4` (`0x1508/0x1528`). Hi ha tres publicacions independents:

| Etapa | Handle / interfície | Tractament d'error |
| --- | --- | --- |
| `0x2a28` | Handle local inicialment NULL a `0x2998`; GUID `f108`, taula `f250`. Cache ShmBridge ja reservada. | Qualsevol estat no zero torna a l'entrada; no allibera cache. |
| `0x3370`, condicional | ImageHandle; QSEE GUID `f148`, taula `f2d0`. | EFI_ERROR a `0x2ad0` arriba a ASSERT `0x2afc`. No assumir retorn normal d'esta fallada. |
| **`0x1c0c`** | ImageHandle; GUID `f78552e0-f751-427f-9451-930e60d839b8` a `f118`, taula `f228` (rev. `0x10000`). | **Retorna x0 sense comprovar ni alterar l'estat** fins a `0x1c1c`. |

No s'ha assignat un nom funcional al tercer GUID només per proximitat de
cadenes. La seua taula conté `0x191c/0x1960/0x19b8/0x19d0`.
El C de Ghidra etiqueta `0x1ba4` com void; les instruccions demostren
que preserva el retorn EFI, de manera que no s'ha usat eixa inferència de
tipus per al CFG.

Un error ordinari en l'última instal·lació arriba a `0x1150`: guarda
estat a `0x1210`, crida destructor `0x1490` a `0x1220` i retorna l'error
original a `0x1224`. El destructor només visita la llista privada
`0x3fa8`; no hi ha UninstallProtocolInterface/UninstallMultiple de les
publicacions anteriors, ni free de la cache ShmBridge. La primera
publicació ja és suficient per al defecte, independentment de la porta
SecurityFlag de QSEE.

**Contracte local de DxeCore:** la taula Boot Services identifica
InstallMultiple `0xc430`, UninstallMultiple `0xc930` i StartImage `0x6e3c`.
`0xc430` desfà només els parells instal·lats dins de la mateixa invocació
(`0xc5c8/0xc5d4/0xc648`); cada invocació Tz d'ací té un sol parell.
No és una transacció de tota la inicialització del driver.

InstallProtocol `0xc204` reserva el node de 0x58 bytes a `0xc29c`; NULL
torna EFI error 9 sense ASSERT (`0xc2a0 → 0xc2d8 → 0xc308`). El helper
`0x1e238 → 0x1e204 → 0x1e114` conserva el contracte ordinari del pool:
EFI_ERROR es convertix en NULL (`0x1e128/0x1e12c/0x1e138`). **No s'ha
provocat eixa fallada**: només s'ha verificat que el contracte la permet.
El node de protocol guarda l'interface pointer a +0x38 (`0xc3cc`), sense
copiar la taula ni el codi fora de la imatge.

Si el driver és iniciat pel StartImage local, el seu EFI_ERROR selecciona
`0x70d8 → 0x70f0 → 0x6424(image,1)`. Esta neteja:

- Tanca entrades OpenProtocol que tenen l'ImageHandle com a agent
  (`0x6508/0x6510/0x652c`); tancar una obertura no desinstal·la un servei.
- Retira informació de depuració (`0x7670`) i les interfícies d'imatge
  amb GUIDs fixes a `2a3c8/2a3d8/2a3e8`, no els GUIDs Tz.
- Demana FreePages del rang d'imatge a `0x660c`; no comprova el retorn
  abans de continuar alliberant metadades.

El callback indirecte de `0x6484` també està resolt: HOB
`b323179b-97fb-477e-b0fe-d88591fa11ab`, TE `0xa703c350`, publicació
`0xa70180e4`, taula `0xa703c360`, slot +0x28 → `0xa702bd40`.
Este crida `0xa7030948`: ajust d'atributs de memòria (`0xa7032a58`) i
retirada d'informació textual de depuració (`0xa7032140`), no rollback
de protocols Tz. La ruta d'emulador només és aplicable si la imatge té
un proveïdor d'emulació; no s'ha pressupost per al PE AArch64 natiu.

**Conclusió:** omissió local de rollback confirmada. Sota entrada nativa
via StartImage, èxit de publicacions prèvies, fallada EFI tardana,
retorn dels callbacks de neteja i FreePages reeixit, queden registres
amb punters a la imatge ja alliberada. És una **referència pendent
condicional**, més precisa que afirmar una fuga de pool o un crash
observat. No s'ha provat fallada real, consulta posterior del protocol,
reutilització de pàgines, execució a través del punter ni explotabilitat.
La fallada de la primera instal·lació només prova retenció local de
cache, sense protocol publicat; la fallada QSEE amb ASSERT no demostra
la cadena de retorn/descàrrega.

Validació: bytes seleccionats de DxeCore/TzDxeLA i HOB/taula del TE en
els inspectors existents; quatre models de vida de registre/imatge,
inclòs èxit i els tres punts de fallada. Són estats simbòlics, no fallades
induïdes en un assignador ni execució del firmware. Referència dirigida
del HOB: `DumpAddressReferences.java … a703c350` en ConfigTeLayout;
exportació local ignorada `work/te-image-unload-refs.txt`.

### Continuació del camí de fitxers

La revisió de creixement descarta cache antiga conservada quan la nova
reserva falla. El [contracte de fitxers](tzdxe-file-resource-contracts.md)
documenta en canvi pèrdua del temporal de pool, handles sense Close,
FreePool(NULL) en errors GetInfo i pèrdua del recompte de lectura curta.
Els proveïdors Fat i FvSimpleFileSystem tenen distinta vida de l'arrel;
no s'ha demostrat quin selecciona este caller ni acumulació en execució.

### Finestra concreta de reentrada durant publicació

La primera taula `f250` es publica a `0x2a28` **abans** de LocateProtocol
SCM `0x2a50`, que emplena `f428`. El word original `f428` és zero; les
referències reconstruïdes identifiquen `0x2a44` com a pas d'out-pointer,
mentre les altres són lectures. La rutina anterior de keystore usa un
handle local distint: no inicialitza este global. No s'afirma absència
universal d'escriptures externes o àlies no identificats.

El slot +0x18 de la taula acabada de publicar és `0x1e74`. Amb entrada
vàlida, cache suficient i reserva pool de petició reeixida, arriba a
`0x1d08`: llig `f428` a `0x1e34` i carrega el callback a **[f428+0x28]**
a `0x1e3c`, sense guard de NULL ni flag de preparació.

DxeCore establix una possible reentrada **síncrona**, sense necessitar
dos CPUs: InstallMultiple eleva TPL a16 (`0xc484/0xc488`), instal·la el
protocol i assenyala notificacions registrades via `0xc400 → 0xb2d8 →
0xb374 → 0x170f0`. Els events NotifySignal s'encuen per prioritat via
`0x16d58`. Abans de retornar, `0xc660` restaura el TPL original amb
`0x16594`; si hi ha notificació pendent de TPL superior a l'original,
`0x16618/0x1661c/0x16638` la despatxa, callback a `0x16ca4`.
Les llistes de protocols ja estan actualitzades i el lock s'ha solt.

Per exemple, amb TPL d'entrada4 i un subscriptor NotifySignal de TPL8,
el callback pot executar-se **dins d'InstallMultiple**, abans de la
consulta SCM posterior del driver. Si localitza la primera interfície
i crida +0x18 amb les precondicions anteriors, s'intenta llegir VA0x28.
No s'ha creat cap event, subscriptor, dada d'entrada ni prova de firmware.

**Classificació:** ordre de publicació/preparació confirmat; accés nul
per reentrada condicional. Falta un subscriptor real d'este GUID, el seu
TPL, la crida efectuada i l'estat de mapatge. Sense subscriptor no s'ha
demostrat cap reentrada; amb TPL igual/inferior al restaurat, el callback
queda ajornat en esta restauració concreta. No confondre esta finestra
amb els flags `f558/f55c` de QSEE, ni amb un crash inevitable.

Tres models de l'ordre de notificació verifiquen estes diferències;
14 proves en el script de recursos. Referències locals reproduïbles:
`DumpAddressReferences.java … f428 f108` en Providers/TzDxeLA.pe,
exportades a `work/tz-publication-reentry-refs.txt` (ignorat).
