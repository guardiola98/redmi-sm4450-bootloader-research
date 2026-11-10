# Conversió de la taula RAM UEFI: índexs i capacitat

Anàlisi estàtica dirigida del TE exterior, 2026-11-10, sorgida en seguir
la procedència del mapa usat per SCM. Hash/mapatge i bytes en
[uefi-config-contract.json](uefi-config-contract.json); VA preferides,
no adreces observades en execució. No s'ha llegit ni generat SMEM, executat
firmware o accedit a particions. Els models representen només índexs.

## Entrada i estructura

L'entrada TE crida `0xa70234d4` a `0xa700e7e8`. La rutina neteja dues
taules de **0x900 bytes**, a `a7044610` i `a7044f10`, i reinicia els
comptadors `a7044608/a7045810`. Cada descriptor és de 0x48 bytes: capacitat
**32** per taula. `0xa70230c4` obté SMEM item 0x192, comprova dues
signatures i rebutja versió zero. Versió 1 crida `0xa7023300`; altres
versions no nul·les recorren l'altra via de `0xa70234d4`.

Els descriptors d'entrada versió 1 tenen stride 0x40; l'altra via usa 0x48.
El filtratge selecciona categoria 0xe i tipus 1 per a RAM normal; tipus
5..8 de la mateixa categoria van a la taula de precàrrega. Estes condicions
són del codi local, **no una especificació completa de SMEM**. No es coneixen
la versió, l'ordre ni el nombre real de descriptors de la plataforma.

## Desacord entre índex d'entrada i índex filtrat, versió 1

En `0xa7023300`, `x25` comença en `a7044610+0x40` (`0xa702334c`) i
avança **0x48 per cada entrada d'origen**, també si queda descartada
(`0xa7023454..0xa7023468`). Però `x9`, usat per la major part del
nou descriptor, es calcula amb el recompte de RAM acceptada
(`0xa70233b4`). Eixes dos posicions només coincidixen mentre tots els
registres anteriors siguen RAM seleccionada.

| Camps del descriptor RAM | Destinació observada |
| --- | --- |
| Nom, base +0x20, mida +0x28, tipus +0x30/+0x34 i EFI memory type +0x3c | Índex filtrat `j`, incrementat només per RAM acceptada. |
| ResourceAttribute +0x38 | `STR w10,[x25,#-8]` a `0xa70233cc`: índex d'entrada `i`. |
| ARM attribute +0x40 i camp +0x44 | `STR d8,[x25]` a `0xa70233d8`: índex d'entrada `i`; literal `0x0000000100000022`. |

Per tant, **si hi ha almenys una entrada descartada o de precàrrega abans
d'una RAM acceptada, `i != j` i els camps es separen entre descriptors**.
Exemple purament d'índexs: `[no seleccionada, RAM]` publica base/mida en
slot 0 i els tres atributs en slot 1. Les taules havien sigut netejades;
els atributs del primer descriptor poden quedar a zero, encara que els
literals previstos siguen ResourceAttribute=0x703c07 i ARM attribute=0x22.
No s'ha demostrat eixe ordre en la taula efectiva ni el seu resultat MMU.

L'altra via usa `x9` tant per al cos com per als atributs (`0xa7023660/64`),
i **no té este desacord concret**. No és correcte generalitzar-lo a totes
les versions. En versió 1 també podria superar-se el límit de l'array amb
l'índex d'atributs `i>=32` encara que hi haja <=32 registres RAM acceptats;
el guard del recompte filtrat no limita `i`. Esta és una condició de
frontera, no una seqüència SMEM real ni un payload.

**Classificació:** defecte local confirmat d'indexació/inicialització,
activació condicionada a versió i ordre de registres no verificats. No
prova alteració de les proteccions MMU efectives ni impacte d'autenticació.

## Límit de capacitat comprovat després de començar l'escriptura

Les dues vies, per a les dues taules, calculen el destí i copien el nom
abans de rebutjar el registre número 33. Després incrementen count i
comparen amb 0x21; el salt que porta a ASSERT és **posterior als stores**
de descriptor. Una comparació efectuada abans d'alguns stores no els
protegeix si el salt de control encara no s'ha executat.

| Via | Primera còpia del nom | Stores posteriors / salt de capacitat |
| --- | --- | --- |
| Versió 1, RAM | `0xa70233a4` | `0xa70233c4..33d8`, salt `0xa70233dc` i ASSERT `0xa70234b0`, bucle `0xa70234b4`. |
| Versió 1, precàrrega | `0xa702341c` | `0xa7023440..344c`, salt `0xa7023450`. |
| Altra versió, RAM | `0xa7023640` | `0xa7023658..3664`, salt `0xa7023668`. |
| Altra versió, precàrrega | `0xa70236ac` | `0xa70236d0..36dc`, salt `0xa70236e0`. |

Amb 32 entrades ja acceptades, el següent destí inicial és
`base + 32*0x48 = base + 0x900`, fora de la taula declarada, **abans que
ASSERT puga impedir eixa primera còpia**. En la taula RAM coincideix amb
l'inici de l'array adjacent de precàrrega; no és prova d'escriptura fora
d'una pàgina física. En la de precàrrega coincideix amb la ubicació del
seu comptador `a7045810`: no s'assumix que l'execució posterior mantinga
el recompte original ni que arribe sempre al mateix ASSERT. L'evidència
suficient és la primera escriptura fora de taula anterior al guard.

**Classificació:** defecte local confirmat d'ordre de validació;
activació amb excés de descriptors condicionada a dades SMEM no observades.
No s'han provat controls del productor anterior a UEFI. No es presenta
com un crash inevitable ni com una corrupció física accessible.

## Proves i punt de continuació

`test-uefi-ram-index-model.py`: quatre tests d'índexs contrasten filtratge,
via alternativa, frontera 32/33 i desacord entre recompte i índex màxim.
No creen descriptors binaris ni representen continguts de memòria.
L'inspector de configuració verifica ara **131 instruccions TE** i literals
d'atributs; la revisió completa del component continua fora de l'abast.

Per a establir activació caldrien metadades autoritzades de versió, nombre,
tipus i ordre de descriptors SMEM efectius o un contracte del productor
anterior. No s'ha demanat una captura del dispositiu: seria fora de les
restriccions d'esta fase. El mapa nul SCM continua condicionat als límits
documentats en [inicialització SCM](scm-initialization-analysis.md).
