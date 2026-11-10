# Observacions ADB/QSEE en dispositiu real — 2026-11-10

> Evidència aportada per l'usuari i **anonimitzada abans de publicar**. No és una prova de vulnerabilitat ni de desbloqueig. No s'inclouen logs complets, identificadors, números de sèrie, digestos, PARTUUID, comptes, noms de xarxa o tokens.

## Entorn i estat observat

- Dispositiu: Xiaomi Redmi 12 5G, codename `river`, firmware `OS2.0.218.0.VMWEUXM`.
- Via: `adb shell getprop`, `adb shell ps -A` i `adb shell logcat -d`; sense root ni escriptures.
- `ro.boot.verifiedbootstate=green`; `ro.boot.flash.locked=1`; `ro.boot.vbmeta.device_state=locked`; `ro.boot.secureboot=1`; `ro.boot.veritymode=enforcing`.
- `ro.boot.slot_suffix=_b`; `ro.boot.avb_version=1.2`; `ro.boot.keymaster=1`.
- `/proc/cmdline`: lectura denegada; `/proc/bootconfig`: cap contingut retornat en la consulta provada. `readlink /proc/<pid>/exe`: eixida buida amb estat d'eixida 1 (causa no establida).
- Propietats del servei: `init.svc.qseecom-service=running`, `init.svc.qseelogd=stopped`, `persist.sys.qseelogd=true`.

## Observacions dels registres Android

Filtre textual ampli inicial d'AVB/QSEE/Keymaster/KeyMint/SCM/TrustZone: **1.092 línies**. El recompte de coincidències de paraules (no d'errors ni esdeveniments diferents): `qsee=642`, `keymaster=509`, `avb=46`, `keymint=29`, `scm=12`, `trustzone=9`, `vbmeta=1`. Filtre sensible a les paraules i possibles repeticions.

`ps -A` identifica el PID que emet la seqüència com el procés `mtd@1.3` (usuari `root`; PID omés ací deliberadament perquè és efímer).

Seqüència representativa **redactada i sense identificadors de sessió**:

```text
D QSEECOMAPI: Loaded image: APP id = [redactat]
D MTService-TEE: Response OK, size: 32  # o 64
D QSEECOMAPI: QSEECom_shutdown_app, app_id = [redactat]
E QSEECOMAPI: Error::Cannot de-alloc memory. priv handle is NULL!!.
```

- Esta seqüència es repetix en diverses operacions, incloses les posteriors a l'inici del sistema; el procés es manté actiu.
- En el context observat també consta `QSEECom_get_handle sb_length = 0x8080`, `App is not loaded in QSEE` i càrrega posterior d'una aplicació QSEE.
- `MTService-TEE: Response OK` és una resposta registrada pel servei; **no prova** que totes les operacions siguen correctes ni que l'alliberament final haja funcionat.
- L'error `priv handle is NULL` es registra després de `QSEECom_shutdown_app` en les seqüències examinades. Hipòtesi: intent redundant o incorrecte d'alliberar un recurs. **No** es demostra corrupció, fuga, reutilització, impacte en TrustZone o explotabilitat.
- Altres logs: `qseelogd` té denegacions SELinux de lectura d'una propietat; una entrada antiga de `keystore2` informa d'error en obtenir dispositiu StrongBox KeyMint. No s'ha establit relació causal amb QSEE ni amb el bootloader.

## Interpretació respecte a l'auditoria estàtica

- El procés `mtd@1.3` és un servei d'Android relacionat en els logs amb `MTService-TEE` i QSEECom. **No es pressuposa** identitat de mòdul/assignador amb `MiTokenDxe`, `TzDxeLA`, `ShmBridgeDxe`, `VerifiedBootDxe` ni els defectes UEFI documentats.
- Els valors `green/locked/enforcing` indiquen que l'estat de bloqueig continua vigent en la mostra.
- Una coincidència lèxica o un error d'alliberament durant Android no establix una cadena de desbloqueig. Mantindre separades evidència runtime Android i hipòtesis UEFI.

## Pla de comprovacions reals — només lectura

1. Capturar una nova mostra acotada de `logcat -d` (tags `QSEECOMAPI`, `MTService-TEE`, `MTService`) en repòs, i comparar freqüència, parelles `Response OK/shutdown/error` i temps, **sense estimular el servei ni activar funcions de seguretat**.
2. Consultar `getprop` exclusivament per a l'estat de bloqueig i els serveis i `ps -A` per a correlacionar el procés; no recopilar identificadors personals.
3. Elaborar un script local d'anàlisi **offline**, que accepte logs proporcionats per l'usuari, elimine timestamps absoluts, PIDs, identificadors d'aplicacions i tokens, i genere només agregats i seqüències genèriques. Exigir revisió humana abans de publicar-ne la sortida.
4. Validar si els errors apareixen en el mateix ordre i si hi ha errors previs en els logs *ja capturats*. No inferir les causes a partir de les cadenes soles.

### Límits operatius

No executar `fastboot flashing unlock`, `fastboot oem`, ordres de flash, proves de corrupció/pressió de memòria, `setprop`, eines per manipular la TEE, instrumentació invasiva, modificació de particions ni reinicis forçats. No recollir claus, tokens, continguts de particions ni dades d'altres apps. Qualsevol prova nova sobre el dispositiu necessita autorització explícita de l'usuari per a l'ordre concreta, i ha de ser preferentment de lectura.

## Tasca suggerida a Codex

Revisar este informe i comparar-lo amb `docs/audit-session-2026-11-10.md` i `docs/candidate-triage.md`, **sense fusionar defectes diferents per similitud de noms**. Crear, si és útil, un analitzador local de logs anonimitzats i tests sintètics. Separar resultats verificats, hipòtesis i dades absents. Fer commit dels canvis que siguen únicament documentació i eines d'anàlisi de només lectura. No modificar ni provar el telèfon automàticament.
