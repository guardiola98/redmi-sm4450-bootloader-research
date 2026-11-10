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
bloc de política. La repetició requerix noves crides externes. La reentrada
simultània, el TPL efectiu i la sincronització entre clients no s'han provat.

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
