# Consumidors MiToken: revisió acotada des de f6672cc

Offline, 2026-11-10. Pregunta: hi ha obtenció indirecta de la interfície
que arribe a +0x18, més enllà de les coincidències literals ja resoltes?
No s'han repetit els escàners de GUID dins dels 110 PE ni l'anàlisi RSA.

## Dependències i inventari

S'ha ampliat el lector FV existent per interpretar DEPEX, conservant
hash, FFS, camí de seccions, contenidor descomprimit i hash de cada PE/TE.
`inspect-consumer-dependencies.py` llig les còpies locals fixades per hash;
la descompressió en memòria és necessària per accedir a metadades noves,
no una nova extracció de les imatges ni una repetició de la cerca literal.

[consumer-dependencies.json](consumer-dependencies.json): 71 expressions
DXE DEPEX, totes acceptades pel parser acotat, cap operand GUID MiToken.
MiTokenDxe té **TRUE; END** (bytes 06 08): no declara dependència explícita
de ChipInfo/SCM. Açò no prova ordre real de crides ni fallada d'un proveïdor.
BEFORE/AFTER, si apareixen, serien ordre entre fitxers, no consum d'interfície.
L'absència de DEPEX tampoc prova independència de serveis en runtime.

El recorregut recursiu confirma **93 PE en uefi + 17 PE en tools** i
identifica **un TE exterior addicional**, FFS
8af09f13-44c5-96ec-1437-dd899cb5ee5d, 286.920 bytes, SHA-256
064e33de95ebb586b0f103cfa03510a5459bca6068318294981673af8b4e9ed0.
Per tant són 110 ocurrències PE + 1 TE, amb ABL separat. Els 93/110 PE
anteriors no eren falsos: excloïen este tipus i nivell del contenidor.
Cap garantia de cobertura funcional completa ni de checksums PI.

## Referències i invocacions

Hashes dels tres PE en [reviewed-pe-evidence.json](reviewed-pe-evidence.json),
verificats abans de Ghidra. Adreces RVA, llegides amb mapatge PE.

| Evidència nova | Resultat |
| --- | --- |
| Referències Ghidra a MiToken 0x9648/0x9660/0x1ac0/0x1b4c | 0x1ae4 entrega la taula a InstallMultipleProtocolInterfaces; 0x9660 apunta al wrapper, 0x1ac4 a la implementació. Cap segon canal d'eixida identificat en estes referències. Registre confirmat, no consumidor. |
| Ebl 0x10c74, crida indirecta 0x10d5c a +0x18 | Interfície localitzada amb GUID 0x1d1e8 = ChipInfo. No MiToken. |
| Ebl 0xe0f0, crida indirecta 0xe154 a +0x18 | GUID 0x1d188 = 03c4e603-ac28-11d3-9a2d-0090273fc14d. Distint de MiToken; el retorn de LocateProtocol es seguix fins al callback. |
| Ebl 0x11f98 construeix GUID a la pila | Prové de constants 0x1b7d0, GUID 9042a9de-23dc-4a38-96fb-7aded080516a, no MiToken. Descartada esta construcció indirecta concreta. |
| QcomBds 0x1d78, crida 0x1e18 a +0x18 | GUID 0x1e248 = d874d61a-4b87-7608-a00f-58add7052530, no MiToken. |
| Ebl 0x3428/0x13680/0x1388c i QcomBds 0xf604 | Enumeració d'handles seguida de Boot Services +0x108 (ConnectController), no invocació genèrica de +0x18 sobre cada interfície. |

Evidència ARM64: Ebl 0x10ca8 carrega LocateProtocol +0x140 i 0x10d58
carrega callback +0x18 del punter retornat; QcomBds 0x1da4/+0x1e14
fa la mateixa relació. En l'enumeració QcomBds 0xf630 carrega +0x138,
però 0xf65c carrega +0x108 de Boot Services, no d'una interfície MiToken.
Bytes originals al manifest; les funcions/exportacions completes romanen
localment en work/Ebl.* i work/QcomBds.*. Són imatges de l'uefi principal:
l'Ebl de tools té un altre hash i no s'ha equiparat funcionalment.

Els clients ABL coneguts continuen només en +8/+0x10; s'ha reutilitzat
l'evidència anterior. No es declara que totes les crides indirectes dels
mòduls nous estiguen resoltes. En particular, les càrregues d'imatges,
interfícies transmeses entre mòduls, GUID construïts d'altres maneres i
callbacks rebuts com a dades impedixen una conclusió de codi inaccessible.

## Decisió

**Cap consumidor real de MiToken +0x18 identificat.** La cobertura de
metadades dels contenidors estudiats queda ampliada, però la cobertura
funcional no és exhaustiva. Les coincidències +0x18 anteriors són
candidats descartats com a consumidors MiToken, no bugs d'altres protocols.

Es rebaixa a **en espera** la investigació d'impacte de la fuga, el cicle,
les lectures i la resposta parcial d'este callback: el CFG/model ja són
coneguts, manca un caller i la ruta TZ reconstruïda retorna error abans
de política. No es rebaixa la certesa del defecte local de neteja.
Reobrir amb un caller verificat, un flux d'àlies resolt o un productor
alternatiu concret; no simplement perquè queden funcions per descompilar.

Reproducció: scripts inspect-consumer-dependencies.py,
inspect-reviewed-pe-evidence.py i test-depex-parser.py (4 proves noves).
El parser DEPEX valida truncament, pila, END, ordenació i SOR; no avalua
la disponibilitat real de protocols. Les limitacions dels lectors FV
heretats consten al manifest. Cap firmware ni comandament d'Ebl executat.
