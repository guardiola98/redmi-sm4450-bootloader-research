# Productor XBL de SMEM 0x192 — 2026-11-10

Continuació des de `3ec36af` i la fase Tz `a0f2df0`, sobre el paquet
local `OS2.0.218.0.VMWEUXM`. **Productor concret identificat: versió 3,
stride 0x48, capacitat total 32.** La seua construcció reeixida i
l'actualitzador estudiat no aporten les precondicions dels defectes v1
o entrada33 del TE. Açò restringix eixes hipòtesis; no prova quina taula
ha consumit efectivament el telèfon ni absència de tots els altres writers.

## Procedència i mapatge verificats

`xbl_s.melf`, SHA-256
`cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1`,
reutilitza la procedència de `bootchain-local.json` i el mapatge conegut
a `xbl_a`. Sense lectura de particions o firmware de tercers.

Les dades posteriors als segments del primer ELF **no són només un
tràiler desconegut**: tres components ELF consecutius ocupen exactament
el fitxer. Les seues fronteres s'obtenen de les capçaleres i de l'extensió
màxima dels segments, contrastades amb límits i hashes; no es carrega
tot el MELF amb el mapatge del primer ELF.

| Offset MELF | Longitud | Classe / e_machine |
| --- | --- | --- |
| `0` | `0x1c2f4` | ELF32 / 1 |
| `0x1c2f4` | `0x2eca0` | ELF32 / 243 |
| `0x4af94` | `0xd2bb0` | ELF64 / 183, AArch64 |

Component analitzat: SHA-256
`426cc7176df1b5417d97ee3269841db14012fc455da7c645f8435eac80c99128`,
entrada preferida `0x14819fa8`. Import ELF natiu en el projecte existent
Providers; offsets i VAs contrastats amb program headers. La funció
`0x1485c584` està en el segment de codi; les signatures `0x148b6930`
en rodata. No són adreces observades en el mòbil.

L'[inspector](../scripts/inspect-xbl-ram-producer.py) i el
[manifest d'evidència](xbl-ram-producer-evidence.json) fixen 72 instruccions,
els literals i l'entrada de la taula de fases. L’ampliació posterior inclou
28 instruccions ChipInfo i metadades de família, documentades separadament. No s'ha repetit el cens
de GUID, descompilació del monitor EL3 ni anàlisi RSA.

## Entrada efectiva en el codi i portes encara condicionals

La taula `0x148c3b60` associa `0x1481bf6c` amb la cadena de firmware
`boot_update_ram_partition_table`. En eixa taula apareixen abans
`boot_smem_init` i els passos de preparació de dades DDR; no es deduïx
només d'això el despatx efectiu de totes les fases.

El wrapper `0x1481bf6c` obté la interfície local `0x52` mitjançant
`0x148411cc`. El seu +8 escriu un selector: només estat zero i selector
zero arriben a **`0x1481bfc8 → 0x1485c584`**. No s'ha equiparat eixe
selector a una propietat Android. Error del productor es propaga a
`0x1481bfd0`; no es continua amb el postprocessament en eixa branca.

La definició estàtica de la interfície0x52 és a `0x148c38b8`, amb taula
`0x148c7be0` referenciada a `0x148c38d0`. +8=`0x14857928` copia el global
`0x148c7bd0` a l'out i retorna zero amb out vàlid. El global comença en5.
L'inicialitzador +0=`0x148578b8` consulta interfície0x51+8 amb selector5:
si retorna estat zero i valor no nul, guarda2; si el valor és nul, guarda
el resultat booleà de `0x14822494`. Esta última llig un registre MMIO
amb màscara0x30. Per tant el productor requerix inicialització reeixida,
valor de consulta nul i eixos bits a zero, sota esta definició intacta.
No s'ha llegit MMIO ni executat l'inicialitzador al mòbil; els significats
nominals dels modes i el registre efectiu de la taula continuen sense
validació runtime. La cadena `boot_mode_interface.c` només contextualitza
el codi, no certifica el mode actual d'Android.

El constructor obté les interfícies `0x28` (assignació/lookup SMEM),
`0x1c` (llista de rangs DDR) i `0x1b` (metadades DDR). `0x148411cc`
exigix context vàlid, índex <0x5e, out-pointer vàlid i estat de registre2.
Els retorns/taules efectius i el nombre de rangs DDR no s'han llegit del
dispositiu. No s'ha reconstruït tot l'inicialitzador d'eixos proveïdors.

## Constructor: estructura, ordre i límits

`0x1485c5c0/5c4/5cc` demana item **0x192**, **0x918 bytes**, pel +0x20
de la interfície0x28. Rebutja NULL i comprova que la reserva estiga dins
del rang SMEM esperat abans d'escriure. Reinicia count a zero (`0x1485c608`).

| Camp | Evidència local |
| --- | --- |
| Signatures +0 / +4 | `0x9da5e0a8`, `0xaf9ec4e2`, literal de 64 bits a `0x148b6930`; coincidixen amb el lector TE `0xa70230c4`. |
| Versió +8 | **3**, escrita a `0x1485c654/658`. |
| Count +0x10 | Inicialització zero, increment de 32 bits. |
| Primer descriptor | +0x18; stride **0x48**. |
| Capacitat de la reserva | `(0x918−0x18)/0x48 = 32`. |
| Base / longitud / longitud disponible del descriptor | +0x10 / +0x18 / +0x40. El TE de via no-v1 usa la darrera per a RAM normal. |

Ordre de construcció:

1. Recorre la llista DDR en l'ordre retornat pel getter de la interfície
   0x1c+0x20. No ordena per adreça. Copia bases; convertix mides amb
   `LSL #20`; marca categoria0xe, tipus1. Les conversions i metadades
   reals són precondicions del proveïdor, no una lectura de hardware feta ací.
2. Abans de cada escriptura, `0x1485c7ac/7b0` comprova count<=31.
   En arribar a32 deixa el bucle; no escriu entrada33.
3. Afig tres registres via `0x1485c894`: dos amb categories4/5 i tipus1,
   i un amb categoria obtinguda per lookup i tipus2. El helper comprova
   **count<32 abans dels stores** (`0x1485c898/89c`); si no, retorna4.
   Els callers comproven cada retorn. En una construcció completada
   sense estes fallades, D rangs DDR requerixen **D<=29**, count final D+3.
4. Només la via final sense error escriu versió3 i signatures
   (`0x1485c648..65c`). Això no prova actualització atòmica: els errors
   poden deixar camps parcials i no s'ha establit l'estat d'una reserva
   prèviament existent ni un consumidor que continue després d'eixos errors.

El tercer registre no aporta un tipus5..8. El constructor estudiat genera
tipus1/2; l'actualitzador següent copia el tipus original, no crea nous tipus.
Per tant **esta parella de rutes no ompli la taula UEFI de precàrrega**,
sota les dades intactes descrites. No generalitzar-ho a productors alternatius.

## Actualització posterior: excloure rangs sense superar 32

Després del constructor, el wrapper obté una llista d'exclusions per
interfície0x1b+0xd8. Amb estat zero i recompte no nul,
`0x1481c074` invoca **`0x1485c938(context, &llista, count)`**.
El tercer argument està confirmat a `0x1481c064`; no s'ha confiat en el
pseudocodi del caller que inicialment l'ometia.

El postprocessador recupera l'item0x192 (`0x1485c98c/994`) i busca,
des del final, un descriptor que continga el rang sol·licitat. Pot:

- Retallar un extrem, sense canviar count.
- Eliminar un descriptor complet, desplaçant els següents i decrementant count.
- Dividir-lo en dos, desplaçant els posteriors i incrementant count una vegada.

Amb el recompte intacte **0..32** aportat pel constructor, rebutja zero
i32 abans de buscar/desplaçar (`0x1485c9c0/9c8`). Per a una divisió,
la primera destinació del desplaçament és l'índex count, per tant <=31.
El guard intern `0x1485ca60/64`, encara que posterior al desplaçament,
no és una còpia fora de límits sota el guard exterior. L'increment de
`0x1485ca80` deixa com a màxim32. Una petició posterior amb32 es rebutja.
La versió de capçalera no es modifica en esta rutina.

**No s'ha provat seguretat amb count ja corrupte >32**: el primer guard
és d'igualtat amb32. Tampoc s'ha certificat tot l'aritmètic de rangs ni
l'atomicitat davant de fallades posteriors. El resultat verificat ací és
la conservació del límit a partir de l'estat produït per la ruta normal.
No s'han construït descriptors, exclusions malformades ni payloads.

## Conseqüències per als candidats UEFI

| Candidat / hipòtesi | Estat després del productor |
| --- | --- |
| Mescla d'índexs del TE v1 | Defecte estàtic es conserva. **No activat per la versió3 d'este productor**; no és correcte presentar v1 com a dada habitual d'esta ruta. |
| Entrada33 abans del guard TE | Defecte local es conserva. Constructor/actualitzador estudiats mantenen total<=32 en les vies indicades; cada subconjunt filtrat també té <=32. Esta cadena ordinària no aporta l'excés necessari. |
| Ordre arbitrari de descriptors | Ara es coneix l'ordre de construcció i el tipus de modificacions. Continuen desconeguts la llista DDR inicial i les exclusions efectives. |
| Qualsevol versió no-v1 és el mateix ABI | No s'ha provat globalment. El **productor3 concret** sí té el stride i camps consumits per la via no-v1 local. |
| Estat de la taula en el Redmi actual | Encara sense observació directa. Coincidència de build Android no és un hash/atestació de cada imatge arrancada. |

No s'ha demostrat mapa zero, crash SCM, alteració MMU, autenticació eludida
ni desbloqueig. El productor dona motiu per **rebaixar la prioritat
d'activació RAM en esta ruta**, no per esborrar els defectes condicionals
del consumidor ni declarar tot el firmware segur.

## Validació Android efectivament executada

Pregunta1: contrastar plataforma sense identificadors personals.
ADB autoritzat; `getprop` individual retorna SM4450, parrot,
OS2.0.218.0.VMWEUXM, verified boot green i flash locked1.
`/sys/devices/soc0/soc_id` retorna **568**, `family` retorna `Snapdragon`.
Estos camps no són serials; tampoc són l'enumeració ChipFamily UEFI
que restringix FeatureEnabler. No s'inferix que eixe caller estiga activat.

Una consulta posterior del camp específic `chip_family` sí retorna141,
exclosa per FeatureEnabler: [cadena i límits](featureenabler-chip-family.md).
La diferència entre soc_id i família es manté; no es deduïx141 només de568.

Pregunta2: Android exposa descriptors o només nodes del mapa final?
`ls -d` troba `/proc/device-tree/memory` i el seu àlies sysfs, però
les lectures de `#address-cells`, `#size-cells` i `memory/reg` són
**Permission denied**. `adb exec-out cat` torna estat host0 amb el text
de denegació en stdout: s'ha descartat com a dades, no interpretat com
un reg binari vàlid. Cap intent d'eludir permisos o llegir l'àlies després.

`/sys/bus/platform/drivers/qcom-smem` existix; els dos paths de diagnòstic
`/sys/kernel/debug/smem` i `/sys/kernel/debug/qcom_smem` retornen
No such file. L'existència del driver no exposa l'item0x192 ni prova
que no hi haja cap altre diagnòstic. No s'ha usat `/dev/mem`, root,
logs crus, dades privades, fastboot, reinicis o estímuls de memòria.
Captures originals només en `work/platform-diagnostics-2026-11-10/`,
privat i ignorat per Git. No es repetixen captures QSEE sense pregunta nova.

## Reproducció i pròxima frontera útil

```sh
python3 scripts/extract-audit-images.py /ruta/al/paquet-local.tgz --images xbl_s.melf
python3 scripts/inspect-xbl-ram-producer.py --extract
python3 scripts/test-xbl-component-layout.py
python3 scripts/test-uefi-ram-index-model.py
```

Ghidra12.2, import ELF de `work/audit-images/xbl-aarch64.elf` a Providers.
Scripts existents `DumpAddressReferences.java` amb objectius `148b6930`,
`148b02a5`, `1485c584`, `1485c938`; `DumpSelectedFunctions.java` per
`1485c894`, `1485c8d4`, `1485c938`, `148411cc`; desassemblatge contrastat
en `work/XblAarch64.asm`. Les exportacions completes queden fora de Git.

Nou proves RAM d'índexs/comptes (cinc noves), cinc proves de metadades ELF
i inspector de72 llocs correctes. Els models usen només comptes/índexs
i capçaleres ELF sintètiques, **cap descriptor SMEM o execució de firmware**.

Per avançar: seguir el despatx de fases i la consulta0x51 si es necessita
provar selecció de productor; seguir getter DDR/exclusions amb dades locals
autèntiques; o reprendre una altra precondició oberta Tz. La mateixa
cadena v1/entrada33 no justifica proves de fallada sobre el telèfon.
