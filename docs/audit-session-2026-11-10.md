# Auditoria estàtica SM4450 — tancament de la sessió autònoma

Firmware Xiaomi Redmi 12 5G, HyperOS `OS2.0.218.0.VMWEUXM`.
Branca `main`, base `a566643`, 2026-11-10. Les quatre fases sol·licitades
estan completades amb revisió dirigida addicional. **No és una auditoria
exhaustiva del firmware ni una demostració d'explotabilitat.**

## Conclusions principals

| Àmbit | Conclusió verificada | Frontera que es conserva |
| --- | --- | --- |
| ScmDxeLA | Error ordinari del pool de taules pot entrar en neteja parcial amb accessos a base nul·la; errors tardans ometen recursos. | Fallada efectiva, mapatge de zero, CurrentEL i handlers desconeguts. No afirmar crash, underflow executat ni esgotament. |
| TzDxeLA: diagnòstic i propietat | Portes de diagnòstic reconstruïdes; política sense free; cache compartida alliberada però conservada; keystore passa el punter a l'assignador equivocat. | Seqüència QSEE finita identificada, però activació/retorns/mides no observats. Defecte local no equival a fuga acumulativa. |
| TzDxeLA: inicialització | Error de l'última publicació no desfà protocols anteriors; DxeCore pot descarregar la imatge. Primera publicació precedix la preparació del punter SCM. | Referències pendents i reentrada per notificació condicionades. Falta ús posterior o subscriptor concret; QSEE intermèdia amb error arriba a ASSERT. |
| TzDxeLA: fitxers | Handles sense Close segons eixida/proveïdor; FreePool(NULL) en errors GetInfo; recompte Read substituït per FileSize. | Fat reserva arrel per crida, FV la reutilitza. Ruta exterior de fitxers no demostrada. Amb DxeCore local intacte la cua del pool és 0xAF. |
| Configuració | Origen FFS → parser TE → registre compartit/HOB → getter SCM reconstruït. Temporal del getter estret, overflow perdut del getter ampli i guard de capacitat del parser delimitats. | Recurs 43/64 no activa frontera; valors seleccionats sense overflow; SCM comprova estat i conserva defaults. No certificar configuració efectiva. |
| Taula RAM UEFI | Via v1 usa dos índexs distints per camps del mateix descriptor; dues vies escriuen entrada 33 abans del guard de 32. | Versió/ordre/comptes SMEM 0x192 desconeguts. No s'han generat descriptors ni demostrat corrupció física accessible. |

MiToken manté la neteja local omesa i els candidats condicionals de
recompte/inicialització; falta caller +0x18 i productor admissible.
VerifiedBoot manté fals èxit només sota NULL del seu allocator, que els
errors ordinaris no proporcionen. **No hi ha cadena d'autenticació eludida,
token/clau generats, canvi de proteccions o estat de bloqueig demostrat.**

La matriu completa i vigent és [candidate-triage.md](candidate-triage.md).
Informes principals: [SCM](scm-initialization-analysis.md),
[TzDxeLA](tzdxe-policy-consumer.md),
[fitxers](tzdxe-file-resource-contracts.md),
[configuració](uefi-configuration-provenance.md),
[RAM](uefi-ram-table-analysis.md).

## Hipòtesis restringides o descartades durant esta sessió

- Getter estret amb error no convertix l'error en èxit; els dos callers
  SCM revisats no consumixen el word com a configuració vàlida.
- DecompressionRequired absent manté el seu default1 en les dues branques
  possibles del temporal indeterminat. No s'ha provat desactivació.
- Nom `uefiplatLA.cfg` és informació de versió en la ruta identificada;
  no substituïx el literal `uefiplat.cfg` del carregador reconstruït.
- FreePool(NULL) de DxeCore retorna error2, però no repara els accessos
  nuls que SCM fa abans de cridar el free.
- ShmBridge amb error ordinari passa per ASSERT/espera. La pèrdua del
  temporal de fitxers quan el caller rep NULL no té encara productor
  ordinari establit; no és una cadena d'esgotament demostrada.
- El creixement fallit de cache, si torna NULL, no conserva la cache
  antiga: posa punter/capacitat a zero.
- La lectura curta perd comptatge, però el pool DxeCore té ompliment
  local 0xAF activat. No inferir dades antigues per absència de zero-fill.
- Ni un protocol publicat ni un despatx de notificacions possible proven
  un consumidor efectiu. La reentrada Tz requerix subscriptor i TPL.

## Proves i reproducció

**92 proves en 17 scripts**, totes correctes en la regressió final:
54 anteriors i 38 afegides en quatre scripts de models de recursos,
fitxers, configuració i índexs RAM. Els tests existents de monitor/RSA
s'han executat com a regressió; no s'han repetit investigacions del
monitor EL3, censos GUID ni experiments criptogràfics.

Els inspectors actuals verifiquen 12 PE, 137 llocs d'instrucció TE, taules,
GUIDs a adreces fixes i el recurs local de configuració. No constituïxen
proves funcionals dels executables ni validació d'un entorn runtime.
`git diff --check` net en cada fase; revisions de JSON, enllaços locals,
tipus de fitxers i patrons de secrets sense incidències en els canvis.
La regeneració final dels inspectors no ha canviat els informes.

Precondició local: proporcionar l'`uefi.elf` autoritzat com a
`work/uefi-provider-source.elf`, SHA-256
`0543144c7f583d7e870019d95206be2b864eae1fff878dcf9bcee52c063ecc50`.
Els scripts rebutgen una font amb hash diferent; no descarreguen firmware.
Els tests anteriors també usen els manifests versionats corresponents.

```sh
python3 scripts/extract-selected-uefi.py DxeCore ArmCpuDxe MiTokenDxe VerifiedBootDxe EnvDxe Ebl QcomBds TzDxeLA ScmDxeLA ShmBridgeDxe Fat FvSimpleFileSystem
python3 scripts/inspect-reviewed-pe-evidence.py
python3 scripts/inspect-uefi-config-contract.py
python3 scripts/inspect-scm-static-config.py
for test in scripts/test-*.py; do
  python3 "$test" || exit 1
done
git diff --check
```

No usar `unittest discover` com a substitut: els noms amb guions no es
descobrixen amb el patró per defecte. Les proves són models simbòlics i
parsers acotats; no executen firmware, provoquen errors de memòria en un
entorn UEFI ni fabriquen payloads. Ghidra 12.2 s'ha usat només com a
desassemblador/decompilador estàtic; procediment TE en l'informe de
configuració. Els binaris i exportacions completes romanen en `work/`,
ignorat per Git.

## Commits d'anàlisi publicats a origin/main

| Commit | Contingut |
| --- | --- |
| `b9aa80f` | Contractes de neteja SCM, pool DxeCore i límits d'accés nul. |
| `91fa1cd` | Diagnòstic Tz i propietat de cache compartida. |
| `d1d8d72` | Procedència de configuració, getter i frontera de parser. |
| `2f67b93` | Consolidació inicial de candidats i límits. |
| `7b1fa3f` | Seqüència QSEE/caller VerifiedBoot i free de keystore incorrecte. |
| `eb5d2d0` | 25 callsites de configuració i propagació d'overflow. |
| `032dcdf` | Frontera del mapa nul i estat SCM de selecció de càrregues. |
| `c78744a` | Índex i capacitat dels descriptors RAM. |
| `332be4f` | Publicació parcial i referències pendents condicionals. |
| `69cc878` | Contractes de fitxers contra Fat/FvSimpleFileSystem locals. |
| `1a1c1fa` | Finestra de reentrada de notificació durant publicació Tz. |
| `f9ead78` | Restricció dels errors ShmBridge: ASSERT no és retorn NULL. |
| `641b99f` | Ompliment de pool DxeCore i límit de la cua de lectura curta. |

Este informe i el punt de represa es guarden en un commit de consolidació
posterior. Cap force-push ni reescriptura d'historial; només documents,
scripts i evidència textual seleccionada. No s'ha contactat el dispositiu
ni serveis d'autenticació. L'única xarxa usada ha sigut Git autoritzat.

## Punt de represa exacte i tres prioritats

Correcció posterior des de `3ec36af`: QSEE+0x20 força x2=0 i no activa
fitxers. FeatureEnablerDxe n'és un caller real de partició. Per a fitxers,
seguir `f250` +0x20 amb x2 no nul o +0x38; detall en el
[seguiment Tz](tzdxe-policy-consumer.md#consumidor-featureenabler-i-correcció-de-la-ruta-de-fitxers).

1. **Consumidors/notificacions Tz:** partir de la primera taula `f250`
   publicada a `0x2a28`, SCM global `f428` omplit a `0x2a50`, i primera
   taula Tz +0x20=`0x279c` / +0x38=`0x27a8`. Buscar caller/subscriptor dins
   d'artefactes locals ja inventariats; registrar TPL i arguments. No usar
   VerifiedBoot+8 com a prova de la ruta de fitxers. No repetir un cens.
2. **Productor de RAM SMEM 0x192:** el TE `0xa70230c4` és la frontera
   concreta; cal versió, ordre i recompte admissibles des d'un productor
   local autoritzat per decidir els defectes de `0xa7023300/0xa70234d4`
   i l'efecte de la mescla en el mapa. Sense eixa evidència, mantindre
   condicionals el mapa zero i les conseqüències SCM.
3. **Consumidors/alteracions de configuració:** seguir un caller real
   de la biblioteca+0x20 o una escriptura posterior a la taula compartida.
   Punt conegut: TE `0xa701d728 → 0xa701d5b8`, taula `a703c428`;
   la lectura de 32 bits de SCM ja està acotada i no s'ha de repetir.

Projectes locals per reprendre: Providers (SCM/Tz/Shm), UefiEnvironment
(DxeCore/ArmCpu), ConfigTeLayout (TE correctament mapat), ConfigPeAudit
(EnvDxe), FileProviderAudit i FileProviderFvAudit (Fat/FV). ConfigTeAudit
és l'intent antic de mapatge incorrecte: no usar-lo com a evidència.
Exports/refs rellevants: `work/ConfigTeLayout.c/.asm`,
`work/tz-publication-reentry-refs.txt`, `work/te-image-unload-refs.txt`,
`work/dxecore-pool-fill-refs.txt`, `work/Fat.c/.asm` i
`work/FvSimpleFileSystem.c/.asm`. Tot això queda fora de Git.

## Actualització posterior a3ec36af — XBL/SMEM i diagnòstic autoritzat

Este apartat actualitza el punt de represa històric anterior. La fase Tz
`a0f2df0` ja està publicada: FeatureEnabler és caller QSEE verificat,
però QSEE+0x20 força x2=0 i no arriba al lector de fitxers2630.

La segona fase identifica **1485c584** en el component AArch64 del MELF
XBL, amb caller1481bf6c i etiqueta boot_update_ram_partition_table.
[Informe complet i reproducció](xbl-ram-producer-analysis.md): productor
v3, header0x18, stride0x48, reserva0x918 i límit32 comprovat abans dels
stores. Tres appends després de DDR impliquen <=29 DDR en camí completat.
El postprocessador1485c938 manté la cota des d’un recompte intacte.
Els candidats TE v1/entrada33 no s’activen per esta cadena normal;
no s’ha demostrat absència de tots els altres writers ni taula runtime.

El selector0x52 té definició estàtica a148c38b8→148c7be0; getter+8
copia148c7bd0. Inicialitzador consulta0x51 i un registre MMIO. Despatx
real de fases, continguts DDR/exclusions i valors runtime continuen oberts.
No es proposa llegir memòria física del telèfon per resoldre-ho.

ADB executat realment en esta continuació: propietats específiques de
plataforma/build/bootstate, soc_id/family; existència de nodes memory,
driver qcom-smem i dos paths debugfs. Lectures device-tree denegades:
cap dada SMEM obtinguda i cap circumval·lació de permisos. Originals en
work/ privat i ignorat; només resultats no personals en l’informe.
No s’han repetit captures QSEE, ni usat fastboot o provocat reinicis.

Validació completa: **128 tests en19 scripts** correctes. Inspector XBL
verifica3 components i72 instruccions; inspector PE13 correcte. CLI
extractora XBL contrastada amb el paquet local i hash fixat. JSON vàlid,
canvis revisats per dades sensibles i `git diff --check` net.
Prioritats vigents: f250/subscriptor/TPL, fonts DDR/exclusions i consumidor
Config+0x20. Els projectes existents es mantenen; nou ELF en Providers,
exports xbl-ram-helpers.c, xbl-mode-interface-refs.txt i XblAarch64.asm
només en work/. No hi ha nova evidència d’elusió d’autorització ni desbloqueig.
