# TzDxeLA: contractes de fitxers i errors de neteja

2026-11-10. Continuació dirigida per la branca de creixement de la cache,
després de `332be4f`. Només anàlisi de codi local i models d'estats;
cap lectura de particions, contingut de fitxers del dispositiu o keystore.
Els RVA corresponen al PE indicat; no són adreces runtime.

## Cache: cas descartat i nova omissió del caller

Tz `0x1f2c`, quan mida > capacitat, allibera el punter antic a `0x1f64`,
posa capacitat a zero (`0x1f74`) i substituïx el punter pel resultat de la
nova reserva (`0x1f7c/0x1f80`). Si és NULL, retorna amb **punter NULL i
capacitat zero**; només recupera capacitat si la reserva té èxit.
Es descarta la hipòtesi d'una cache antiga conservada després de fallar
el creixement. El primer free encara pot repetir el d'un caller anterior;
és la inconsistència de propietat ja documentada, no un defecte nou.

El caller de fitxers `0x2630` rep de `0x4a00` un búfer temporal de pool
i la mida. A `0x2734` demana la cache compartida. Si rep NULL, retorna
error 9 a `0x2764` i **no passa per l'únic FreePool del temporal,
`0x275c`**. El punter temporal no ix per l'out-pointer; es perd en tornar.
La ruta reeixida copia, publica els out-paràmetres i sí que allibera el
temporal. El destructor privat Tz no gestiona este pool de Boot Services.

**Omissió local confirmada al CFG**, condicionada a lectura/assignació
inicial reeixides i **retorn NULL** de la reserva compartida. La reserva
pot ser de creixement per a un fitxer major que la cache; no s'han
verificat mides efectives. No és una fuga acumulativa demostrada.

**Restricció del proveïdor, verificada després:** ShmBridge `0x2890`,
amb mida no nul·la, prova AllocateMaxAddress i després AllocateAnyPages
(`0x29b8/0x29d8`); si ambdós fallen, arriba a ASSERT `0x2af0` abans del
retorn NULL textual `0x2af4`. Fallades de configuració de memòria també
convergixen ací després de FreePages; error del node pool de0x30 va a
ASSERT/bucle `0x2b24/0x2b28`. ASSERT `0x1640 → 0x1720` espera en
`0x1738/0x173c`. **L'error ordinari del proveïdor no aporta el NULL
necessari per a perdre el temporal en un retorn normal del caller.**

Petició zero sí retorna NULL abans d'assignar (`0x28a8`), però no satisfà
la condició de creixement mida>capacitat no negativa. No s'ha establit
un altre productor admissible, ni una reserva reeixida a adreça zero.
La branca continua en espera d'eixa precondició. El model de NULL és un
contracte del consumidor, no una simulació d'esgotament de ShmBridge.
Cap fallada s'ha provocat.

## `0x4a00`: propietat dels handles i dels dos búfers

La rutina localitza un únic volum, obté SimpleFileSystem, fa OpenVolume
(`0x4ad8`), obri el fitxer (`0x4b00`), consulta informació (`0x4b2c`,
després `0x4b64`), reserva dades (`0x4bd8`) i llig (`0x4bfc`).
`0x4ef0` usa AllocatePool de tipus 4 sense zero-fill; `0x50a8` és el
wrapper FreePool que fa ASSERT en EFI_ERROR.

| Eixida després d'obrir el fitxer | Close del fitxer | Pool d'informació | Pool de dades |
| --- | --- | --- | --- |
| Primera reserva d'informació NULL, `0x4b44 → 0x4c10` | Omet | No reservat | No reservat |
| Reserva de dades NULL, `0x4bdc → 0x4c08` | Omet | Allibera `0x4c0c` | No reservat |
| GetInfo inicial amb error diferent de BUFFER_TOO_SMALL, o segon GetInfo amb error | Crida `0x4b98` | Allibera si existix | **FreePool(NULL)** a `0x4bcc` |
| Read amb error | Crida | Allibera | Allibera |
| Read reeixit | Crida | Allibera | Retorna al caller |

En totes estes vies, **no hi ha Close de l'arrel retornada per OpenVolume**.
Només es carrega el handle del fitxer a `0x4b90`; el de l'arrel és un
local diferent. File.Close s'invoca sense propagar el seu estat, però no
s'atribuïx conseqüència addicional a eixa omissió sense proveïdor que falle.

### El proveïdor determina si l'arrel reté una reserva nova

S'han extret dos PE **ja inventariats**, pel seu nom i hash, sense cens
nou de GUID. La interfície SimpleFileSystem té GUID coincident
`964e5b22-6459-11d2-8e39-00a0c969723b` (Fat `e0c8`, FV `90d8`).

- **Fat**, SHA-256
  `767e38ab1e37b5614d30b286031c1ceca47efc8934a1e583cd3e1f97b302222c`:
  publica OpenVolume `0x5704` des de `0x2914/0x2970`. L'entrada està
  contrastada en ASM perquè Ghidra no la delimita en l'exportació C.
  Cada OpenVolume reeixit crida `0x57bc` (`0x5770`), que reserva
  **0xb8 bytes** a `0x5810`, copia la taula de fitxer `e238`, enllaça
  el handle i retorna una interfície pròpia a `0x5784`. Close `0x30f8`
  retira i allibera **el handle rebut** via `0x3184 → 0x3200`; tancar
  el fill no tanca el handle arrel independent.
- **FvSimpleFileSystem**, SHA-256
  `9ac1dcc80fbfe21baa9084c5db6e8d664babb89c32a46e3de1d14a703a3683dd`:
  Taula `0x9148` publicada a `0x1944`; OpenVolume `0x13f4` guarda
  una arrel per volum i la reutilitza
  (`0x1460/0x1464`, retorn `0x17c8`). Close `0x228c` detecta eixa
  arrel i no l'allibera (`0x22dc/0x22e0`). No es pot traslladar a este
  proveïdor la reserva de 0xb8 per invocació de Fat.

Amb **Fat com a proveïdor efectiu**, l'omissió Tz deixa un handle de
0xb8 bytes sol·licitats per cada OpenVolume reeixit, fins i tot si el
fitxer es llig i es tanca correctament. Per n invocacions reeixides sense
recuperació externa, el model suma 0xb8*n bytes, més metadades possibles.
**Ni el proveïdor efectiu ni n estan observats**: és una conseqüència del
contracte local, no evidència d'acumulació real o d'esgotament.

### GetInfo amb error pot activar ASSERT durant la neteja

`0x4b8c` fixa el registre del búfer de dades a zero abans que existisca
eixa reserva. Després de tancar el fitxer i alliberar informació si escau,
qualsevol estat no zero arriba a `0x4bc8/0x4bcc`, que passa eixe zero a
FreePool. DxeCore retorna error 2; el wrapper Tz `0x50c0/0x50f8` crida
`0x5214`, que arriba a l'espera `0x5900`, local zero i bucle
`0x5914/0x5918/0x591c`.

Per tant, **l'error de GetInfo no té garantia de propagació normal** en
eixes branques: la neteja substituïx el retorn previst per ASSERT/espera.
No requerix una fallada de memòria: requerix un estat d'error de GetInfo
en eixe punt. No s'ha demostrat que el proveïdor efectiu el produïsca.
La via Read amb búfer ja reservat sí passa un punter no nul al free;
no generalitzar la conclusió a tots els errors del lector.

## Recompte de lectura perdut: conseqüència encara condicional

La petició Read passa la mida esperada per referència a `0x4bf8/0x4bfc`.
Després de retornar zero, `0x4bb4/0x4bb8` publica **FileInfo.FileSize**,
no el recompte que Read haja actualitzat. `0x2630` copia eixa mida completa
a la cache a `0x274c`, sense comparar-la amb bytes realment llegits.

Els dos proveïdors locals admeten lectura reeixida més curta al final:
Fat Read `0x55b4 → 0x5238` reduïx el recompte a mida-posició
(`0x53a8..0x53bc`) i actualitza bytes transferits; FV `0x231c` també
el reduïx (`0x23cc..0x23d8`) i retorna zero a `0x2408`.
**Això no demostra una lectura curta en esta seqüència concreta**:
amb fitxer estable, posició inicial zero i mida coherent, s'espera
lectura completa. Falta canvi de mida, incoherència de proveïdor o altra
condició admissible entre GetInfo i Read que produïsca eixe resultat.

Si es donara, el consumidor copiaria una cua no escrita pel Read.
**L'ompliment del pool local restringix el seu contingut:** DxeCore
`0xfb44` crida `0x1378` a `0xfe78`; el flag original `24f71=0x2b`
té bit0x08 actiu. Per això `0xfe8c → 0x1320 → 0x1d84 → 0x214c`
ompli tot el payload arredonit de la reserva amb el byte **`24f70=0xaf`**.
Les referències dirigides de les dues constants són lectures; no hi ha
sobreescriptura local identificada. Sota estos valors intactes i sense
altres escriptures, la cua és de0xAF, **no dades antigues indeterminades**.
Zero-fill absent no significa absència de qualsevol inicialització.

La còpia no excedix per això la reserva sol·licitada; no és una lectura
fora del pool demostrada. Tampoc prova divulgació, acceptació d'una
imatge incompleta o canvi d'autenticació. El model usa longituds i un
valor escalar de patró, sense bytes d'imatge ni payload. No es trasllada
esta garantia a caches privades reutilitzades que no tornen a AllocatePool.

## Accessibilitat i reproducció

`0x2414` usa `0x2630` quan el paràmetre de fitxer no és nul.
**Correcció de la continuació des de `3ec36af`: QSEE +0x20 no aporta
eixa forma de crida.** El wrapper `0x31dc` força `x2=0` a `0x3228`,
i `0x2414:0x2438` selecciona la partició per GUID. S'ha identificat
FeatureEnablerDxe `0x255c` com a caller exterior, amb GUID i out-ID vàlids,
però tampoc activa els defectes del lector. La via VerifiedBoot +8 també
és de partició. La cadena `31dc → 279c → 2414 → 2630` no és un camí
factible amb els arguments verificats del wrapper.

Els candidats correctes per seguir fitxers són **la primera interfície
Tz `f250`**, +0x20=`0x279c` amb tercer argument no nul, i
+0x38=`0x27a8`, que crida `0x2630` directament a `0x27ec`.
No són els mateixos slots de QSEE `f2d0`; falta consumidor exterior
verificat d'estes entrades. Vegeu el
[seguiment de FeatureEnabler](tzdxe-policy-consumer.md#consumidor-featureenabler-i-correcció-de-la-ruta-de-fitxers).
No s'han fabricat fitxers ni executat les interfícies.

```sh
python3 scripts/extract-selected-uefi.py Fat FvSimpleFileSystem
python3 scripts/inspect-reviewed-pe-evidence.py
python3 scripts/test-tzdxe-file-model.py
```

Ghidra: importacions PE normals als projectes locals ignorats
`FileProviderAudit/Fat.pe` i `FileProviderFvAudit/FvSimpleFileSystem.pe`;
exportacions `DumpFunctions.java` i `DumpInstructions.java`. Taules,
GUIDs a adreces fixes i bytes dels callsites en
[reviewed-pe-evidence.json](reviewed-pe-evidence.json), ara 12 PE.
Nou proves simbòliques comparen contractes de recursos, errors i longituds;
no simulen un dispositiu ni establixen accessibilitat efectiva.
