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
| TzDxeLA/ShmBridge: cache alliberada però vigent | 0x1e74 allibera el node compartit sense invalidar punter/capacitat; 0x1f2c retorna la cache sense readquirir-lo. Free de ShmBridge no comprova busy. | **Inconsistència local confirmada.** Repetició compatible duplica comptabilitat; un client intermedi pot crear àlies. Seqüència finita identificada en la inicialització QSEE; activació runtime, corrupció i pàgines retornades a UEFI no demostrades. |
| TzDxeLA: free de keystore d'un altre assignador | 0x2b18 reserva amb ShmBridge +8 i neteja amb free privat 0x42e8; les llistes són distintes i el punter desconegut s'ignora. Caller 0x14f8. | **Defecte local confirmat també en camí reeixit.** Presència/mida de partició i acumulació no demostrades; no s'ha accedit al contingut. |
| TzDxeLA: publicació parcial sense rollback | Fallada EFI de l'últim InstallMultiple 0x1c0c torna sense desinstal·lar protocols anteriors; DxeCore StartImage descarrega imatges que retornen error. Cada InstallMultiple només desfà la seua transacció. | **Omissió confirmada; referència pendent condicional.** Requerix ruta StartImage nativa, error tardà i neteja/FreePages reeixits. No hi ha ús posterior demostrat. Error de la publicació QSEE, en canvi, arriba a ASSERT. |
| UEFI Config Lib: temporal indeterminat en error | Getter de 32 bits 0xa701d578 usa el temporal sense inicialitzar encara que falle el getter ampli; pot escriure out-word indeterminat o substituir error original per error 2. | **Defecte confirmat de gestió d'error.** No convertix error en èxit; SCM comprova estat zero i conserva defaults. No prova dada efectiva indeterminada en SCM. TE 0xa7024990 ignora estat, però la seua clau és present i vàlida localment. |
| Getter de configuració de 64 bits: overflow decimal | Conversor retorna error 3 i UINT64_MAX; wrapper perd l'estat i getter ampli retorna zero amb el valor saturat. | **Pèrdua local d'error confirmada; activació condicional.** Claus seleccionades sense overflow; cap consumidor +0x20 amb eixa entrada identificat. Getter de 32 bits ho rebutja. |
| Parser de configuració: frontera de capacitat | 0xa7012af8 rebutja count>capacitat, però accepta igualtat i escriu un descriptor fora dels 16*capacitat bytes declarats. | **Defecte condicional confirmat.** Recurs local té 43 entrades per a capacitat 64: no l'activa. Cap configuració alternativa efectiva ni corrupció física demostrada. |
| Conversor RAM UEFI v1: atributs amb índex incorrecte | Atributs usen índex d'origen; base/mida usen recompte filtrat. Entrades prèvies descartades separen els camps. | **Defecte local confirmat; activació condicional.** Versió/ordre SMEM desconeguts. La via alternativa usa índex coherent. |
| Conversors RAM UEFI: guard de capacitat tardà | Primera còpia de l'entrada 33 es fa a base+0x900 abans del salt a ASSERT, en les dues taules i vies. | **Defecte local confirmat; activació condicional.** Recompte SMEM efectiu i controls del productor no establits; no inferir retorn normal ni corrupció física accessible. |

Detall i bytes: [inicialització SCM](scm-initialization-analysis.md),
[TzDxeLA](tzdxe-policy-consumer.md), [manifest PE](reviewed-pe-evidence.json),
[procedència de configuració](uefi-configuration-provenance.md),
[conversió de RAM](uefi-ram-table-analysis.md).
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

**80 proves en 16 scripts**: recompte dels scripts, amb comprovació final
completa registrada en PROGRESS.md. Inclouen 11 models nous TzDxeLA,
11 de configuració i 4 d'índexs RAM. Inspectors
verifiquen hashes i bytes seleccionats; `git diff --check` net. Els models
usen estats/índexs simbòlics, sense executar firmware ni provocar fallades.

## Punt de continuació i tres prioritats

1. **Cache TzDxeLA:** seqüència QSEE i caller VerifiedBoot identificats;
   acotar mides/metadades de partició i selecció d'altres clients només amb
   artefactes autoritzats, sense obrir keystore ni assumir retorns segurs.
2. **Configuració:** candidats locals delimitats en 25 callsites revisats;
   reobrir impacte amb entrada efectiva diferent o consumidor de +0x20.
   No fabricar recursos alternatius ni repetir models de defaults resolts.
3. **Conseqüència SCM pendent d'entorn:** la mescla SMEM item 0x192
   és la frontera concreta abans del mapa MMU; el RAW no inclou zero.
   Sense estat efectiu, mantindre crash/underflow/recuperació condicionals.

Les quatre fases demanades estan documentades; l'auditoria no es declara
exhaustiva. La continuació prioritza les noves rutes amb evidència concreta.
