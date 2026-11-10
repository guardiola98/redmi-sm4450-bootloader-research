# Classificació i punt de represa — 2026-11-10

Continuació vigent des de `a566643`, exclusivament estàtica/offline sobre artefactes
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
| TzDxeLA: búfer de política no recuperat | 0x3454 reserva/neteja 0x4c4 i omet free en totes les eixides posteriors. Flags de cache no impedixen noves reserves; destructor omet nodes ocupats. | **Defecte local confirmat; acumulació condicional.** Portes de diagnòstic reconstruïdes; falta seqüència real repetida amb assignacions reeixides. El seu +0x18 no és el de MiToken. |
| ScmDxeLA: recursos en errors tardans | 0x3744 retorna sense recuperar dues reserves ShmBridge; si falla CreateEventEx després d'inicialitzar objectes, també omet el pool de taules (11296 bytes per defecte). Destructor tracta una altra llista. | **Omissió local confirmada; acumulació condicional.** No assumir retorn normal després dels accessos nuls de la fallada inicial de taules. |
| TzDxeLA/ShmBridge: cache alliberada però vigent | 0x1e74 allibera el node compartit sense invalidar punter/capacitat; 0x1f2c retorna la cache sense readquirir-lo. Free de ShmBridge no comprova busy. | **Inconsistència local confirmada.** Repetició compatible duplica comptabilitat; un client intermedi pot crear àlies. Seqüència real, corrupció i pàgines retornades a UEFI no demostrades. |
| UEFI Config Lib: temporal indeterminat en error | Getter de 32 bits 0xa701d578 usa el temporal sense inicialitzar encara que falle el getter ampli; pot escriure out-word indeterminat o substituir error original per error 2. | **Defecte confirmat de gestió d'error.** No convertix error en èxit; SCM comprova estat zero i conserva defaults. No prova dada efectiva indeterminada en SCM. |
| Parser de configuració: frontera de capacitat | 0xa7012af8 rebutja count>capacitat, però accepta igualtat i escriu un descriptor fora dels 16*capacitat bytes declarats. | **Defecte condicional confirmat.** Recurs local té 43 entrades per a capacitat 64: no l'activa. Cap configuració alternativa efectiva ni corrupció física demostrada. |

Detall i bytes: [inicialització SCM](scm-initialization-analysis.md),
[TzDxeLA](tzdxe-policy-consumer.md), [manifest PE](reviewed-pe-evidence.json),
[procedència de configuració](uefi-configuration-provenance.md).
DxeCore confirma error ordinari/NULL del pool i error 2 per FreePool(NULL).
ArmCpuDxe té diagnòstic/espera per defecte, però el mapatge de VA zero,
CurrentEL i handlers actius no estan establits; no es declara un crash concret.
La cadena de configuració verificada prediu defaults SCM i SecurityFlag=0xC4
només sota la taula local intacta; no certifica valors efectius en execució.
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

## Cobertura i proves vigents

Inventari: **110 ocurrències PE + un TE exterior**, ABL separat; 71 DEPEX
interpretades. Revisió funcional dirigida de DxeCore, ArmCpuDxe i la ruta
de configuració del TE, a més dels components anteriors. No són auditories
completes dels executables. El TE s'ha importat amb mapatge de seccions
explícit verificat contra hashes/offsets; l'error històric del loader natiu
no és una barrera actual per a esta ruta. Vegeu el procediment reproduïble
en [configuració](uefi-configuration-provenance.md).

No s'ha identificat cap nou consumidor MiToken +0x18. La cerca d'impacte
continua en espera de caller/productor concret. No s'ha repetit el monitor
EL3, cap cens GUID ni experiments RSA; executar els tests ja existents
forma part de la regressió. No s'ha consultat xarxa per investigar firmware;
només s'han publicat commits autoritzats al repositori.

**64 proves en 15 scripts** passen executant cada `scripts/test-*.py`
separat. Inclouen 4 models nous TzDxeLA i 6 de configuració. Inspectors
verifiquen hashes i bytes seleccionats; `git diff --check` net. Els models
usen estats/índexs simbòlics, sense executar firmware ni provocar fallades.

## Punt de continuació i tres prioritats

1. **Callers de la cache TzDxeLA:** seguir la seqüència local de càrregues,
   inclosa la inicialització, per acotar repetició i alliberaments del mateix
   node. Separar este defecte de la retenció de política diagnòstica.
2. **Errors de configuració:** comprovar consumidors ja identificats del
   getter estret i si validen l'estat abans d'usar out. No fabricar recursos
   alternatius ni assumir que la frontera 64 s'assolisca en la configuració local.
3. **Conseqüència SCM pendent d'entorn:** mapatge de VA zero/handlers i
   recuperació global només si apareix evidència local concreta. MiToken i
   VerifiedBoot continuen en espera de les precondicions especificades.

Les quatre fases demanades estan documentades; l'auditoria no es declara
exhaustiva. La continuació prioritza les noves rutes amb evidència concreta.
