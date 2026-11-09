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
