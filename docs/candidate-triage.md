# Classificació i punt de represa — 2026-11-10

Continuació des de `f6672cc`, exclusivament estàtica/offline sobre artefactes
locals autoritzats. «Confirmat» qualifica el defecte de programació i les
seues precondicions verificades; **no equival a vulnerabilitat explotable**.
«En espera» és una decisió de prioritat, no una prova d'inaccessibilitat.
Els informes històrics es conserven; esta matriu fixa l'estat vigent.

## Candidats demanats

| Candidat | Evidència directa / models | Precondicions i incerteses | Classificació i decisió |
| --- | --- | --- | --- |
| MiToken: omissió d'alliberament | 0x1bec/0x1c14/0x1c20 eviten 0x1cd4; l'allocator deixa ocupat el bloc. EL3/ScmDxeLA aporten un productor d'error per la ruta reconstruïda. | Reserva reeixida, entrada real a +0x18 i error posterior. No hi ha caller identificat ni repetició demostrada. | **Defecte local confirmat; impacte en espera.** Reobrir amb un caller o flux d'àlies verificat. |
| MiToken: cicle per recompte >=256 | Índex limitat a 8 bits a 0x1ca0/0x1cb4. Model detecta cicle amb recompte gran i absència de match. | Resposta SCM acceptada, nibble no nul, recompte >=256 i cap match entre els 256 elements visitats. Productor d'eixe recompte desconegut; la ruta TZ reconstruïda rebutja abans de política. | **Comportament condicional; en espera.** Cal productor admissible i consumidor, no més valors sintètics. |
| MiToken: lectura fora de 0x4c4 declarat | 249 elements caben des de +0xe0; amb recompte >=250 i sense match previ es llig fora del rang declarat. Models cobreixen fronteres. | Mateixes portes de política; no s'ha demostrat que el productor supere 249. Últim byte del recorregut de 8 bits: +0x4df, dins d'una pàgina reservada. | **Condicional; en espera.** Descartat presentar estos bytes com una lectura demostrada fora de l'assignació física. |
| MiToken: dades de política no inicialitzades | Reserva pròpia reutilitzable sense zero-fill; marcador local 1 sintetitzat pel transport ARMv8, no garantia d'escriptura completa del productor. Model separa marcador i contingut. | Cal retorn de transport acceptat i política absent/parcial; no està observat ni establit pel contracte TZ. | **Hipòtesi sense productor provat; en espera.** TzDxeLA/ShmBridge netegen els seus búfers, però això no es trasllada a MiToken. |
| MiToken: word ChipInfo indeterminat | Caller ignora estat i no neteja el word; però getter DAL concret 0x345c → 0x5248 escriu i retorna zero. | Protocol/handle vàlids eliminen la precondició. Falta de localització o estat anòmal no demostrats. | **Descartat en ruta normal del proveïdor; condicional fora d'ella.** No repetir DAL sense evidència nova. |
| VerifiedBoot: fals èxit | Branca amb NULL a 0x17bc/0x185c omet transferència i arriba a retorn zero. Models injecten NULL i delimiten l'efecte local. | Cal que el seu allocator torne NULL; els errors ordinaris recorren ASSERT/espera. SCM nou usa un altre allocator i no aporta esta precondició a VerifiedBoot. | **Comportament condicional; en espera.** No hi ha cadena «esgotament → fals èxit» demostrada ni canvi d'autenticació verificat. |

Per a instruccions/bytes i contractes complets: [MiToken](mitoken-interface-errors.md),
[proveïdors](mitoken-provider-contracts.md), [monitor](tz-monitor-analysis.md),
[VerifiedBoot](verifiedboot-failure-analysis.md). No s'han repetit RSA,
censos GUID ni proves del monitor per justificar una conclusió nova.

## Nous candidats amb evidència més concreta

| Candidat | Fet verificat | Límit / decisió |
| --- | --- | --- |
| ScmDxeLA: neteja amb inicialització parcial | AllocatePool EFI_ERROR → NULL sense ASSERT; 0x4774 prepara error 9 però crida 0x4b7c. Amb globals originals zero i nombre remot per defecte, 0x57fc intenta escriure a base nul·la; hi ha lectura posterior de base nul·la+8. | **Defecte confirmat sota error ordinari d'assignació. Prioritat alta dins de la investigació**, sense grau de severitat de seguretat assignat. Activació, mapatge i efecte real desconeguts. |
| TzDxeLA: búfer de política no recuperat | 0x3454 reserva/neteja 0x4c4, consulta 0x02001401 i no allibera eixa reserva en error ni retorn. Caller directe 0x1e50 i entrada del seu protocol +0x18 identificats. | **Defecte local confirmat; conseqüència acumulativa condicional.** Cal reconstruir freqüència/reentrada i portes de diagnòstic; el seu +0x18 no és el de MiToken. |
| ScmDxeLA: dues reserves ShmBridge en errors tardans | 0x3744 retorna d'error d'objectes o CreateEventEx sense alliberar les reserves; callback de neteja encara no registrat en eixes vies. Destructor de la imatge tracta una altra llista. | **Omissió local confirmada en retorns normals; impacte condicional.** No assumir que la fallada inicial de taules retorna normalment: té el defecte anterior. No estendre a totes les assignacions. |

Detall i bytes: [inicialització SCM](scm-initialization-analysis.md),
[TzDxeLA](tzdxe-policy-consumer.md), [manifest PE](reviewed-pe-evidence.json).
Les conseqüències potencials són interrupció de la inicialització o retenció
de memòria; no s'ha demostrat cap modificació de política de seguretat,
autenticació, claus, persistència o estat de bloqueig.

## Hipòtesis descartades o restringides

- Les crides +0x18 seleccionades d'Ebl/QcomBds són d'altres interfícies;
  enumerar handles/ConnectController tampoc demostra cridar MiToken.
- La presència de la taula MiToken i el seu registre no prova un consumidor.
  71 DEPEX sense el GUID tampoc proven que el callback siga codi mort.
- Transport ARMv8 seleccionat no implica disponibilitat de 0x02001401.
  Error del seu inicialitzador no provoca fallback a la variant antiga.
- La sonda SCM d'un argument no necessita el buffer global que s'assigna
  després; es rebutja esta dependència circular concreta.
- La mida 0x4c4 del consumidor, el límit de deu arguments SCM i els camps
  11/11/10 de taules d'objectes **no** fixen el màxim del recompte de política.
- Zero-fill de TzDxeLA elimina allí l'herència de política antiga si no hi
  ha escriptures; el zero-fill de ShmBridge cobrix la mida sol·licitada.
  Cap d'estes garanties prové del productor segur de la política MiToken.
- El rebuig d'una ruta local SCM, inclosa la convenció antiga estudiada,
  no prova indisponibilitat global del servei ni equivalència entre transports.

## Cobertura, proves i aturada

Inventari: **110 ocurrències PE + un TE exterior**, ABL separat. 71 DEPEX
interpretades; TE caracteritzat estructuralment; Ebl/QcomBds, TzDxeLA i
ShmBridge revisats només en funcions pertinents. No són 110 auditories
funcionals completes. Manifestos conserven contenidor, FFS, secció, hash
i mapatge. El loader Ghidra disponible no ha importat directament el TE;
cap semàntica s'ha atribuït a partir d'eixe intent fallit.

No s'ha identificat cap consumidor MiToken +0x18 després d'esta revisió
acotada. La cerca d'impacte queda en espera per manca de nova evidència,
no perquè s'hagen resolt totes les crides indirectes. Contracte del productor
de política, dades efectives de configuració i altres handlers carregables
continuen oberts. No s'ha fet xarxa ni s'han incorporat fonts públiques noves.

La suite s'executa amb cada `scripts/test-*.py` separat: **54 proves en
13 scripts**, incloses 13 noves (4 DEPEX, 4 TE, 5 SCM). Els models no
executen firmware ni fan accessos a les adreces nul·les calculades.
Hashes/bytes verificats pels inspectors dels components nous; `git diff
--check` net. Les proves de RSA existents són sintètiques i formen part de
la regressió, sense repetir experiments criptogràfics sobre firmware.

S'atura esta iteració després de quatre fases coherents i de conservar el
punt de represa. No es declara l'auditoria completa ni les fonts esgotades:
les següents preguntes requerixen una revisió específica nova, no continuar
descompilant sense criteri de decisió.

## Tres prioritats següents

1. **SCM, conseqüència del camí d'assignació fallida:** revisar estàticament
   el mapatge/tractament d'excepcions UEFI i l'entrada d'inicialització per
   delimitar l'efecte d'accés nul, sense induir esgotament ni executar firmware.
2. **TzDxeLA, repetibilitat del diagnòstic:** seguir callers de la seua
   interfície registrada i les portes de 0x3454; decidir si la retenció pot
   repetir-se sota un contracte normal. Parar si depén d'estat no disponible.
3. **Configuració i contracte efectius:** seguir `UEFI Config Lib` per
   determinar origen/sobreescriptures de les dues claus SCM; només reobrir
   la política MiToken si apareix un caller o productor concret. No repetir
   la reconstrucció EL3 ni inferir límits a partir d'altres búfers.
