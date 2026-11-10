# Contrast Android/QSEE amb l'auditoria UEFI — 2026-11-10

Base actualitzada amb `git pull --ff-only`: `1cfd6cd`, branca `main`.
Continuació de les [observacions inicials](device-adb-qsee-observations-2026-11-10.md)
i de la [classificació estàtica](candidate-triage.md). Les consultes ADB de
només lectura estan autoritzades expressament en esta sessió; substituïxen
la restricció històrica de no contactar automàticament el telèfon.

**Resultat: evidència nova de l'ordre de neteja d'un client Android, cap
evidència nova de desbloqueig. No es justifica continuar acumulant errors
QSEE en repòs com a línia prioritària.** La causa exacta requerix el caller
i la biblioteca d'esta compilació; la similitud amb errors UEFI no els substituïx.

## Consultes efectivament realitzades

- Un dispositiu ADB autoritzat. El primer intent fallava pel socket del
  servidor ADB dins del sandbox Debian; repetit fora d'eixa restricció,
  ha funcionat. No s'han elevat privilegis en Android.
- Propietats consultades individualment: `river`, `OS2.0.218.0.VMWEUXM`,
  verified boot `green`, flash locked `1`, vbmeta `locked`, secureboot `1`,
  verity `enforcing`, slot `_b`. Sense canvis entre les tres captures.
- `init.svc.qseecom-service=running`, `init.svc.qseelogd=stopped`,
  `persist.sys.qseelogd=true`. El valor persistent no equival a procés actiu.
- `ps -A` correlacionat localment amb els PIDs dels logs; no es publiquen
  PIDs, TIDs, identificadors QSEE ni la llista de processos.
- Tres `logcat -d -b main -v epoch` amb només `QSEECOMAPI:V`,
  `MTService-TEE:V`, `MTService:V`, `*:S`. Diferència entre inicis de la
  primera i tercera captura: **207,92 s**; entre primera i segona: **80,25 s**.
  S'ha consultat `/proc/uptime` per contrastar els intervals.
- Consulta addicional dels mateixos tags en `system`: cap registre.
  `logcat -g -b main -b system`: dos buffers circulars de 2 MiB.
  No es netegen buffers ni s'activa logging. No s'ha examinat tot el kernel,
  el món segur ni tots els tags; no afirmar cobertura completa.
- Lectura de la declaració init i el manifest VINTF del servei.
  `ls -l` sobre `/vendor/bin/mtd@1.3` i les dues rutes lib/lib64 de
  `libQSEEComAPI.so`: **Permission denied**. No s'han eludit els permisos,
  copiat executables, llegit particions ni accedit a la TEE directament.

Els logs originals estan únicament en `work/adb-qsee-2026-11-10/`, ignorat
per Git, amb directori privat i fitxers de captura restrictius. Inclouen
diagnòstics amb identificadors: **no compartir-los**. El nou col·lector
reutilitzable manté les entrades crues en memòria i només emet agregats.

## Relació observable dels components

La declaració init associa `vendor.mtdservice-1-3` amb
`/vendor/bin/mtd@1.3`, classe `hal`. El manifest declara
`vendor.xiaomi.hardware.mtdservice`, versió `1.3`, transport `hwbinder`,
interfície `IMTService/default`. `ps` mostra `mtd@1.3` amb usuari `root`.

En cada un dels dos cicles, `MTService-TEE` i `QSEECOMAPI` tenen el mateix
PID **i TID**, atribuïbles al `mtd@1.3` de la consulta de processos.
Per tant són tags emesos dins d'eixe procés durant el cicle observat;
no són tres processos independents. `qseecomd` i
`vendor.qti.hardware.qseecom@1.0-service` també apareixen en `ps`, però
no se'ls atribuïxen estos dos errors. El mapatge contemporani de PID no
exclou formalment reutilització anterior; no és una pila de crides.

Després dels cicles hi ha diagnòstics `getFidoService` i `getMlipayService`.
Delimiten el context Android, però no identifiquen l'app que ha sol·licitat
la transacció ni demostren que eixes consultes causen el cicle anterior.
No s'han invocat servicis Binder, funcions FIDO, pagaments ni operacions
d'autenticació per estimular-lo.

## Ordre, freqüència i errors previs

Les tres captures retenen **els mateixos 30 registres**, amb un interval
entre primer i últim de **1,340 s**. 24 són del PID atribuït a `mtd`,
i sis d'un altre procés. Cada comparació té 30 registres coincidents i
**zero registres nous**. No són 90 esdeveniments independents.

| Mesura en la mostra retinguda de mtd | Resultat |
| --- | --- |
| Càrregues / respostes OK / shutdown / errors nuls | 2 / 2 / 2 / 2 |
| Identitat interna app de càrrega i shutdown | Coincidix en els dos cicles; valors omesos |
| Mida de resposta registrada | 32 en els dos cicles; no es veu 64 en esta mostra |
| Crides registrades de desassignació | 4: dues per cicle |
| Cicles amb desassignació abans i després de shutdown | 2 de 2 |
| Temps càrrega → error nul | 6 i 11 ms |
| Temps shutdown → error nul | 1 i 3 ms |
| Candidats de fallada previs dins del cicle capturat | 0 |
| PID de mtd en les tres consultes ps | El mateix; sense publicar-lo |

Seqüència genèrica, reconstruïda sense contingut de peticions ni respostes:

```text
QSEECom_get_handle → App is not loaded in QSEE → Loaded image
→ MTService-TEE: càrrega OK → Response OK
→ QSEECom_dealloc_memory → QSEECom_shutdown_app
→ QSEECom_dealloc_memory → priv handle is NULL
```

La doble entrada de desassignació és informació nova respecte del resum
inicial. **No demostra dos alliberaments efectius del mateix objecte**:
no tenim arguments, retorns, identitat del recurs privat ni caller.
L'error descriu un handle privat nul; no demostra una desreferència nul·la
ni corrupció de heap. La primera desassignació podria formar part del
mateix shutdown: l'ordre dels missatges no determina la pila de crides.

El [contracte públic AOSP de QSEEComAPI.h](https://android.googlesource.com/platform/hardware/qcom/keymaster/+/master/QSEEComAPI.h)
(blob consultat `a96cda3a2e3e9dd01fcf2c63eca898391e692916`, comentari de
`QSEECom_shutdown_app`) atribuïx al shutdown la descàrrega de l'aplicació
i la desassignació de memòria de peticions. Això fa **compatible** una
neteja redundant posterior amb l'ordre observat. És un contracte històric,
no la implementació Xiaomi instal·lada: no confirma que l'error siga
inofensiu, que el shutdown retorne zero ni qui passa el handle nul.
No s'usen logs d'altres models com a prova d'esta implementació.

`App is not loaded in QSEE` és de nivell `D` i va seguit de càrrega i
resposta OK: en estos cicles no és una càrrega fallida demostrada.
Hi ha quatre registres de nivell `E` en `mtd`, però només dos expressen
l'error nul. Els altres dos són diagnòstics que imprimixen un identificador
de propietat, **contingut omés**; el nivell `E` no els convertix en errors
d'assignació. No s'ha trobat una fallada anterior que explique l'error nul
en els tags i la finestra capturats. No s'inferix absència global d'errors.

**Freqüència mesurada:** zero activitat nova visible en aproximadament
208 s de mostreig passiu. Dos errors en dos cicles retinguts descriuen eixa
mostra minúscula, no una probabilitat general ni una taxa sostinguda.
L'interval d'1,340 s dels registres tampoc és la duració de l'observació.
En una consulta posterior, el registre més recent tenia uns 20,6 minuts
segons el rellotge del dispositiu: la captura llegia història del buffer.
Sense garantia de logging complet, no es prova que el servei mai falle,
que no hi haja pèrdues de logs ni que no es reinicie entre mostres.

L'altre procés mostra càrrega, una desassignació i shutdown, sense error
nul visible. És un contrast contextual limitat: no té una resposta
`MTService-TEE` ni prova que use el mateix caller, biblioteca o recursos.

## Contrast amb els defectes estàtics

| Hipòtesi | Decisió basada en les dades |
| --- | --- |
| El missatge prové d'un cicle del client Android mtd | Confirmat observacionalment per PID/TID, init i VINTF, amb el límit de mapatge indicat. |
| Neteja redundant o ownership incorrecte després del shutdown | Compatible i més concreta per les dues entrades de dealloc; causa exacta encara no confirmada. |
| Fallada prèvia de càrrega o reserva explica el NULL | Sense evidència en els cicles capturats; no assumir-la. |
| Cada línia E o coincidència QSEE és un error nou | Descartat: diagnòstics informatius i solapament íntegre entre captures. |
| Fuga acumulativa, double-free efectiu, corrupció o fallada de TrustZone | No demostrats; no s'han mesurat ownership, memòria segura ni retorns. |
| És el mateix defecte que la cache ShmBridge/Tz o el free de keystore | Descartada la identificació per similitud: allí hi ha assignadors, llistes i callers UEFI diferents, verificats estàticament. |
| Aporta el NULL necessari per al fals èxit VerifiedBoot | No: no hi ha camí Android → allocator UEFI ni precondició establits. |
| Confirma la neteja parcial SCM, GetInfo/FreePool(NULL) o consumidor MiToken +0x18 | No: no aporta error EFI, caller UEFI, productor ni fase d'execució corresponents. |
| qseelogd/StrongBox expliquen causalment este cicle | No hi ha correlació demostrada; la notícia històrica no es reutilitza com a causa. |

No canvia la classificació de defectes UEFI ni les seues precondicions.
Continuen absents una cadena d'autenticació eludida, execució privilegiada
controlada, canvi de política, token generat o desbloqueig.

## Prova addicional Android i següents proves útils

Després de l'anàlisi inicial, `dumpsys -l` mostra `oem_lock` i
`persistent_data_block`. S'ha consultat **només** `dumpsys oem_lock`:
retorn zero i eixida buida, sense denegació impresa. Això no equival a
estat favorable ni a disponibilitat de totes les operacions.
`ro.oem_unlock_supported` no ha proporcionat un valor reconegut;
`sys.oem_unlock_allowed=1`. Esta última és una propietat Android observada,
**no** el resultat de `fastboot flashing get_unlock_ability`, ni prova
d'autorització Xiaomi o d'estat unlocked. Coexistix amb `green/locked`.
No s'ha llegit contingut de FRP, comptes, claus o tokens.

| Prova posterior | Valor i risc |
| --- | --- |
| Col·lector passiu durant ús quotidià decidit per l'usuari | Pot trobar cicles nous i errors previs; risc baix de lectura, amb risc de privacitat en els logs crus. No activar funcions de seguretat per provocar-los. |
| Anàlisi offline de mtd i libQSEEComAPI del paquet exacte ja autoritzat, si estan disponibles | Millor prova per distingir caller redundant, guard nul i contracte de retorn. Sense risc per al telèfon; no substituïr per binaris d'un altre model ni eludir permisos Android. |
| Fastboot: `getvar is-userspace`, `getvar unlocked`, `getvar secure`, `getvar current-slot` | Contrast directe dels estats reportats per eixe entorn, sense escriure. Requerix canvi de mode manual i interromp Android; no executat. Capturar només estes respostes, no `getvar all`. |
| Seguiment estàtic de consumidor/notificació Tz i productor SMEM 0x192 | Més útil per al projecte de bootloader que comptar nous errors QSEE: resol precondicions concretes ja pendents, sense risc al dispositiu. |

**Següent prioritat:** reprendre el subscriptor Tz `f250/f428` o el caller
QSEE UEFI `+0x20`, i després el productor SMEM `0x192`, segons els punts
exactes de l'[auditoria](audit-session-2026-11-10.md#punt-de-represa-exacte-i-tres-prioritats).
La línia Android es reobri amb un caller/retorn verificat, un error previ
nou o canvi funcional correlacionat; no simplement amb més còpies del
mateix missatge. Fastboot no és necessari per tancar esta fase i no
s'ha enviat cap ordre fastboot, reinici, escriptura o estímul de fallada.

## Eines i reproducció

```sh
# Proves completament sintètiques, sense ADB:
python3 scripts/test-qsee-logcat.py

# Només lectura; entrades crues en memòria, eixida agregada per revisar:
python3 scripts/collect-qsee-diagnostics.py --samples 3 --interval 30

# Anàlisi offline de captures privades en format epoch:
python3 scripts/analyze-qsee-logcat.py captura1.txt captura2.txt \
  --ps processos1.txt processos2.txt
```

L'analitzador emet només etiquetes fixes, recomptes i duracions relatives;
els missatges desconeguts no s'imprimixen. Conserva internament PID/TID i
app-id per comprovar ordre i identitat, sense serialitzar-los. No accepta
formats arbitraris silenciosament: compta les línies no interpretades.
Cal revisar eixe recompte abans d'usar el resultat.

Una seqüència requerix mateix PID/TID, una càrrega, un shutdown, resposta
intermèdia, app-id compatible i com a màxim cinc segons. No ajunta cicles
entre captures. La diferència de multiconjunts evita recomptar el mateix
buffer i conserva duplicats dins d'una captura. Sense solapament, marca
continuïtat desconeguda. Un PID absent de `ps` queda sense atribuir.
Les finestres i tags acoten l'evidència, no proven causalitat.

Les 22 proves noves cobrixen privacitat, errors previs, tags desconeguts,
solapament, duplicats, truncament, PID/TID i app-id diferents, regressió
de temps, captures buides, dispositiu absent, consultes fixades i canvi
d'uptime. No executen firmware ni injecten errors de memòria.
Els marcadors d'app-id redactat no compten com a prova d'identitat, i un
missatge de consulta de servei amb text de fallada conserva eixa classificació.

Validació real del col·lector: tres mostres durant **62,735 s** (delta
uptime **62,74 s**), 30 registres en cada una, zero registres nous, mateix
PID mtd i propietats seleccionades sense canvis. És una segona finestra
d'observació, no s'ha de sumar a la primera com si fóra mostreig continu.
Els [agregats revisats](device-qsee-aggregate-2026-11-10.json) conserven els
recomptes, intervals i límits sense contingut cru ni identificadors.
Validació local: les 92 proves preexistents i les 22 noves passen
(114 en 18 scripts); la reanàlisi final conserva els agregats reals.
JSON i enllaços locals verificats, `git diff --check` net i revisió dels
valors identificadors dels logs sense coincidències en els nous fitxers.
