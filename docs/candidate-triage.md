# Classificació i punt de represa — 2026-11-10

Continuació vigent des de `3ec36af`: anàlisi estàtica d’artefactes locals
autoritzats i diagnòstic Android de només lectura. «Confirmat» qualifica el defecte de programació i les
seues precondicions verificades; **no equival a vulnerabilitat explotable**.
«En espera» és una decisió de prioritat, no una prova d'inaccessibilitat.
Els informes històrics es conserven; esta matriu fixa l'estat vigent.

Contrast posterior [Android/QSEE de només lectura](device-qsee-validation-2026-11-10.md):
dos cicles retinguts de `mtd@1.3`, cadascun amb desassignació abans i després
de shutdown, sense fallada prèvia visible en els tags seleccionats. Cap
registre nou en les comparacions passives. No aporta el caller, allocator
ni productor UEFI necessari per canviar esta matriu; cap evidència nova
de desbloqueig. Neteja Android redundant continua com a hipòtesi local,
no com a double-free efectiu ni equivalència amb ShmBridge.

Continuació des de `3ec36af`: FeatureEnablerDxe és un caller verificat
de QSEE +0x20, però el wrapper força càrrega de partició per GUID.
**Corregida** la cadena de fitxers `31dc → 279c → 2414 → 2630`: x2=0
impedix l'últim salt. Cal seguir la primera interfície Tz `f250` +0x20
amb argument de fitxer o +0x38; encara sense consumidor exterior.
[Contrast de família posterior](featureenabler-chip-family.md): Android
exposa chip_family141, exclosa per FeatureEnabler. El caller estàtic no
prova activació al dispositiu; soc_id568 és un camp diferent.

Continuació DDR des de `7257cbc`: resolts getter/publicació0x1c i
proveïdor0x1b. La font DDR i la porta d'exclusions tenen ara adreces/camps
concrets en [l'informe XBL](xbl-ram-producer-analysis.md). No s'ha observat
la taula runtime; es mantenen les restriccions de v1/entrada33.

Revisió [kernel/root temporal](android-temporary-root-feasibility.md):
Image del paquet idèntic al GKI oficial i config coincident en Android.
CVE-2026-43499 i64560 conserven codi anterior a la correcció; prioritat
estàtica amb explotabilitat/root sense provar. La taula separada inclou
19 CVE i descartaments per codi/config, sense canviar la classificació UEFI.

Seguiment des de `316669e`: [contractes complets5.10 i callers](kernel-lifetime-followup-2026-11-10.md)
revisats per43499/64560; gate cmpxchg compilat confirmat, cap carrera/root
executats. ADB resol GPU, mòduls i migració=1. Els mòduls del paquet
conserven els patrons anteriors als fixes57545/57554, però LPAC i accés
async/profiling/DSP no estan establits: **informació insuficient** per
confirmar compatibilitat operativa.58942 manté eixe estat per diferències
d'algoritme. En XBL queda identificat el writer DDR0x1b+0x60 amb màxim
local condicionat de tres fragments; no és un límit global ni desbloqueig.

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
| TzDxeLA: notificació abans de preparar SCM | Publica primera taula abans d'emplenar f428; DxeCore pot despatxar NotifySignal durant RestoreTPL, abans del retorn d'InstallMultiple. Slot+0x18 usa f428 sense guard. | **Ordre confirmat; accés nul condicional a reentrada.** Falta subscriptor concret, TPL compatible i crida; no equival a concurrència observada ni crash garantit. |
| TzDxeLA: recursos de lectura de fitxers | 0x2630 perd temporal pool si la cache retorna NULL; 0x4a00 omet Close arrel i Close fitxer en errors de reserva. Fat crea un handle arrel de 0xb8 per OpenVolume, FV el reutilitza. | **Omissions locals confirmades; activació/retenció depenen de ruta i proveïdor.** Errors ordinaris ShmBridge arriben a ASSERT, no al NULL necessari per perdre el temporal; eixa cadena queda en espera. No hi ha caller exterior de fitxers verificat ni acumulació observada. |
| TzDxeLA: neteja GetInfo amb NULL | Errors previs a reserva de dades arriben a FreePool(NULL) 0x4bcc; DxeCore error2 activa ASSERT/espera del wrapper Tz. | **Defecte de propagació d'error confirmat.** Falta error efectiu de GetInfo; no generalitzar a Read, on el pool ja és vàlid. |
| TzDxeLA: longitud de lectura curta ignorada | Retorna FileInfo.FileSize encara que Read actualitze un recompte menor; els proveïdors locals admeten retorn zero curt al final. | **Pèrdua de recompte confirmada; còpia de cua condicional.** DxeCore amb constants locals intactes ompli el pool amb0xAF: no es prova herència de dades antigues. Fitxer estable des de posició zero no aporta activació; cap lectura fora de pool, divulgació o autenticació alterada provades. |
| UEFI Config Lib: temporal indeterminat en error | Getter de 32 bits 0xa701d578 usa el temporal sense inicialitzar encara que falle el getter ampli; pot escriure out-word indeterminat o substituir error original per error 2. | **Defecte confirmat de gestió d'error.** No convertix error en èxit; SCM comprova estat zero i conserva defaults. No prova dada efectiva indeterminada en SCM. TE 0xa7024990 ignora estat, però la seua clau és present i vàlida localment. |
| Getter de configuració de 64 bits: overflow decimal | Conversor retorna error 3 i UINT64_MAX; wrapper perd l'estat i getter ampli retorna zero amb el valor saturat. | **Pèrdua local d'error confirmada; activació condicional.** Claus seleccionades sense overflow; cap consumidor +0x20 amb eixa entrada identificat. Getter de 32 bits ho rebutja. |
| Parser de configuració: frontera de capacitat | 0xa7012af8 rebutja count>capacitat, però accepta igualtat i escriu un descriptor fora dels 16*capacitat bytes declarats. | **Defecte condicional confirmat.** Recurs local té 43 entrades per a capacitat 64: no l'activa. Cap configuració alternativa efectiva ni corrupció física demostrada. |
| Conversor RAM UEFI v1: atributs amb índex incorrecte | Atributs usen índex d'origen; base/mida usen recompte filtrat. Entrades prèvies descartades separen els camps. | **Defecte local confirmat; activació condicional.** Productor XBL identificat genera v3; no activa este defecte. Versió/ordre runtime encara no observats. La via alternativa usa índex coherent. |
| Conversors RAM UEFI: guard de capacitat tardà | Primera còpia de l'entrada 33 es fa a base+0x900 abans del salt a ASSERT, en les dues taules i vies. | **Defecte local confirmat; activació condicional.** Constructor XBL i actualitzador estudiats mantenen <=32 des d’estat intacte; esta cadena ordinària no activa entrada33. Recompte runtime i altres writers no establits. |

Detall i bytes: [inicialització SCM](scm-initialization-analysis.md),
[TzDxeLA](tzdxe-policy-consumer.md), [manifest PE](reviewed-pe-evidence.json),
[recursos de fitxers Tz](tzdxe-file-resource-contracts.md),
[procedència de configuració](uefi-configuration-provenance.md),
[conversió de RAM](uefi-ram-table-analysis.md),
[productor XBL](xbl-ram-producer-analysis.md).
DxeCore confirma error ordinari/NULL del pool i error 2 per FreePool(NULL).
ArmCpuDxe té diagnòstic/espera per defecte, però el mapatge de VA zero,
CurrentEL i handlers actius no estan establits; no es declara un crash concret.
La cadena de configuració verificada prediu defaults SCM i SecurityFlag=0xC4
només sota la taula local intacta; no certifica valors efectius en execució.
Les conseqüències potencials inclouen interrupció, retenció de recursos i
accessos a memòria no vàlida sota les precondicions indicades; no s'ha
demostrat cap modificació de política de seguretat,
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
forma part de la regressió. El contrast web primari de ChipInfo no ha
retornat contingut accessible; no sustenta cap conclusió. Publicació Git
autoritzada, sense firmware ni captures privades.

**129 proves en 19 scripts** validades: regressió completa de128 i el
cas nou de família dins dels19 tests Tz, segons PROGRESS.md. Inclouen 19 models TzDxeLA, 11 de configuració,
9 d’índexs/comptes RAM, 9 de fitxers, 22 d’anàlisi QSEE i 5 de metadades XBL. Inspectors
verifiquen hashes i bytes seleccionats; `git diff --check` net. Els models
usen estats/índexs simbòlics, sense executar firmware ni provocar fallades.

## Punt de continuació i tres prioritats

1. **Consumidors/notificacions TzDxeLA:** identificar subscriptor de la
   primera interfície publicada abans de preparar SCM, o caller de la
   primera taula Tz `f250` +0x20 (x2 no nul) / +0x38. QSEE+0x20 i
   VerifiedBoot+8 són rutes de partició; no proven la via de fitxers.
2. **Productor SMEM0x192:** v3/stride0x48 i límit32 ja delimitats en XBL.
   Si es reprén, seguir getter DDR/exclusions i despatx de fases, no repetir
   el constructor. Sense dades efectives, el mapa zero/crash SCM és condicional.
3. **Configuració:** continuar amb consumidor real de biblioteca+0x20
   o escriptura posterior a la taula compartida. No repetir els 25 callsites
   revisats, defaults resolts, monitor EL3, censos GUID o models RSA.

Les quatre fases demanades estan documentades; l'auditoria no es declara
exhaustiva. La continuació prioritza les noves rutes amb evidència concreta.
El [tancament de sessió](audit-session-2026-11-10.md) registra commits,
comandes de reproducció, projectes locals i adreces exactes de represa.
