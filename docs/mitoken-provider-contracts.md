# Contractes de proveïdors: revisió des de 5b87a841

Anàlisi offline dels PE del cens existent. No s'han executat firmware,
SMC ni dades d'identificació. Complementa mitoken-interface-errors.md.

## ScmDxeLA alternativa 0x1858

Evidència ARM64 0x1874/0x187c: punters arguments/resultats no nuls;
retorn 0x8000000000000002 si fallen. Reserva persistent de 0x50 a 0x18a4;
retorn nul → 0x8000000000000009. La reserva global és reutilitzada,
no una fuga per crida. 0x18b0..0x18c0 neteja el paquet segons flag intern;
no neteja el búfer extern de política.

0x1958..0x1968 llig **deu** slots de 64 bits i desa els 32 bits baixos.
No consulta x2=0x22. Precondició real: arguments llegibles de 80 bytes.
MiToken compleix esta precondició: sp+0x38/sp+0x40 contenen punter/mida i
sp+0x48..sp+0x87 estan inicialitzats a zero. No hi ha lectura fora del seu
descriptor. La reducció del punter a 32 bits exigix adreça representable;
no s'ha demostrat que la reserva concreta viole eixe requisit.

Constants del PE a 0xa2d8 = {16,56}, 0xa2e0 = {24,12}. El paquet
conté capçalera, deu arguments a +16 i resposta des de +56. 0x19dc crida
0x17e8; esta protegix l'enviament amb flag 0xd218. Si ocupat, error 2.
0x45cc passa el paquet en x2, posa w0=1 i executa SMC a 0x45e0;
retorn positiu repetix. 0x17e8 transforma -4→error 3, -13→error 20,
altres no zero→error 7 i zero→èxit; lleva el flag després de la crida.

Només amb èxit, 0x19e8..0x1a24 llig l'offset de resposta i copia quatre
words a quatre slots de 64 bits amb extensió zero. Amb offset inicial 12,
la lectura comença a paquet+64 (56+12-4) i acaba a +79: dins dels 80 bytes.
No hi ha validació local de l'offset després de la crida segura: exigir
que TZ preserve/retorne un offset vàlid és una precondició encara no provada.
No afirmar un desbordament real sense un valor possible del productor.

| Aspecte | Alternativa 0x1858 | ARMv8 0x3cb4 |
| --- | --- | --- |
| Arguments | Deu slots fixos, truncats a 32 bits | Recompte nibble baix <=10; 0x22 en copia dos |
| Comunicació | Paquet global de 80 bytes, SMC w0=1 | Registres, ID efectiu 0x42001401 |
| Exclusió local | Flag comprovat en 0x17e8, després de preparar paquet | RaiseTPL/RestoreTPL entorn de 0x3880 |
| Resultats | Quatre words copiats del paquet | Marcador 1 generat i tres registres |
| Error transport | No copia resultats | Pot escriure primer resultat; retorna error |
| Política externa | No valida comptador ni completitud | No valida comptador ni completitud |

El marcador 1 no té el mateix origen en ambdues vies. No assumir una
semàntica interna TZ comuna només perquè MiToken aplique la mateixa prova.

## Cobertura i fonts

El cens de 93 PE és una cerca literal de tres GUID en seccions PE directes
dels **dos FV GZIP d'uefi.elf**, no 93 auditories funcionals. Anàlisi
funcional: LinuxLoader, MiTokenDxe, VerifiedBootDxe, ChipInfo i ScmDxeLA;
DALSys s'hi incorpora en esta sessió. LinuxLoader prové d'abl.elf i està
fora dels 93. No comptar els PE seleccionats per GUID com tot el firmware.

Queden fora d'esta cobertura: seccions no PE/directes o compressió anidada,
imagefv.elf (l'experiment LZMA anterior va excedir el límit), tools.fv
(inspecció anterior sense coincidències, no auditoria funcional), XBL,
TrustZone i altres imatges inventariades en bootchain-local.json. L'inventari
del paquet consta de 114 fitxers, una mètrica distinta del recompte PE.

No hi ha tz.mbn extret al directori work inspeccionat ni fonts públiques
locals del servei 0x02001401. El seu hash al manifest és identificació,
no anàlisi de la implementació. Restricció offline: no s'han obert els
enllaços públics del repositori ni descarregat fonts. Per tant **el format
TZ, la cota del comptador i l'escriptura completa continuen sense verificar**.
No atribuir-li el límit 249 deduït de la mida del caller.

## Reavaluació

- Neteja MiToken omesa: defecte local confirmat, amb activació/repetició
  no demostrades perquè no s'ha identificat consumidor +0x18.
- Cicle >=256 i lectures per >=250: comportaments condicionals; cap de
  les dues capes de transport aporta la cota de política necessària.
- Dades ChipInfo no inicialitzades: condicionals a la implementació DAL
  i a la via d'error; el wrapper per si sol no garanteix inicialització.
- Descartat: lectura fora del descriptor MiToken per les deu lectures
  fixes de 0x1858. Descartat: que els 93 PE siguen auditoria completa.
- Paquet SCM persistent: no classificar-lo com fuga per crida; és un global
  reutilitzat. No és la reserva local perduda de MiToken.

## DAL completat fins a la lectura concreta

El protocol bootstrap `ae37b942-457f-4c91-a196-d9669fd347a3` és registrat
per DALSys 0x14d8, taula 0x1e0b8. +8 → 0x1430 escriu la taula de serveis
0x1e0d0 al caller; +0xc8 d'esta taula → 0x22b8. Ghidra DALSys importat
al projecte Providers; hash conservat en mitoken-provider-bytes.txt.

ChipInfo 0x1940..0x1950 passa device ID **0x0200006f** i &global_handle.
DALSys 0x22b8 posa el handle a zero i recorre fins a 32 registres de drivers;
si no troba ID retorna -0x52. Delega al factory registrat; propaga error.
En la via que requerix inicialització addicional, error allibera el handle,
el posa a zero i propaga el codi. És inicialització del **handle**, no del
word que consulta MiToken. ChipInfo no instal·la la interfície si falla.

Registre local ChipInfo: descriptor 0xa0c8 → 0xa0d8 → 0x7d60,
factory **0x3208**, llista d'ID a 0xa1d0 amb 0x0200006f. 0x3208 prepara
handle 0xa390, taula **0x7d78**; entrada +0x88 = **0x345c**.
Açò resol la delegació que el pseudocodi del wrapper deixava indirecta.

0x345c conserva x1; crida 0x5248; posa w0=0 a 0x3474 i escriu el valor
a `[x19]` a 0x3478. 0x5248 llig el word global **0xa42c** i retorna.
No hi ha branca d'error ni eixida sense escriptura en esta implementació.
No cal conéixer ni llegir el valor d'identificació per demostrar el contracte.
La procedència i exactitud del valor global no equivalen a la inicialització
del destí: ací es prova que el destí rep un word, no que el word identifique
correctament el dispositiu.

**Reclassificació:** candidat de dades de pila no inicialitzades **descartat
per la ruta normal amb este driver registrat, handle intacte i destí vàlid**.
Continua condicional si la localització falla i MiToken continua sense
invocar ChipInfo, o si s'usa una altra implementació/estat alterat. No hi ha
evidència d'estes condicions en el flux real ni d'un consumidor +0x18.
El retorn ignorat és una debilitat de robustesa, no una lectura indeterminada
demostrada sota el contracte concret d'èxit.

## Validació i continuació

Bytes de les instruccions decisives afegits a mitoken-provider-bytes.txt;
mapatge RVA amb el lector PE existent. No s'han afegit tests que només
repetisquen l'assignació del getter. La comparació de mides del paquet és
aritmètica estàtica (16+40=56; 56+24=80; 56+12-4+16=80).

Tres passos següents: (1) productor TZ del servei, amb fonts locals
versionades; (2) cobertura de volums/formats que queden fora dels 93 PE;
(3) consumidors reals de +0x18 abans d'intentar atribuir impacte als errors.
La falta de fonts públiques locals bloqueja només el contracte intern TZ,
no la documentació ni la reconstrucció dels proveïdors UEFI.

## Precisió posterior: què selecciona la variant SCM

La [reconstrucció TZ](tz-dispatch-analysis.md) identifica el callback de
consulta de disponibilitat 0x02000601, i la taula concreta no registra
0x02000602. ScmDxeLA 0x4534 consulta eixe segon ID, però el selector
només examina el bit d'error EFI del transport; no llig el bool de
resposta. No deduir disponibilitat d'un servei de l'elecció ARMv8 ni
classificar el selector com a defecte per esta diferència de canals.

La ruta de rebuig MiToken normalitzada s'ha seguida fins a la SMC de TZ
0x1c136914, missatge amb error en x2. La traducció del monitor fins al
w0 d'UEFI continua pendent; no prova indisponibilitat global, ni canvia
la classificació del bucle o de les lectures de política condicionals.

## Actualització del retorn EL3

La frontera monitor→UEFI anterior queda resolta per la
[ruta local ARMv8](tz-monitor-analysis.md): paquet segur x2=-1 → context
no segur x0=-1 → EFI error 3. Requerix el monitor/contextos inicialitzats
i les condicions d'entrada documentades. La variant antiga usa una
petició distinta; el seu mapping local -1→error 7 no prova el mateix
encaminament. Cap garantia nova sobre el contingut de política ni sobre
selecció real de variant; no es deduïx indisponibilitat global del servei.
