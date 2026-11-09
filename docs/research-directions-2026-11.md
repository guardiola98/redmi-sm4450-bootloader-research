# Repositoris actuals i direcció d'investigació — 2026-11-09

## Evidència del firmware propi

Última execució local de `scripts/inspect-xbl-structure.py` aportada per l'investigador:

- `xbl_s.melf`, 1.170.244 bytes, SHA-256 `cff40b3a88565100c0d640381b3ba12940a5b4b91bc0313cb8e83cf7ccce49f1` (verificat).
- Capçalera ELF32, `e_machine=0x1`, `e_entry=0x2211c000`, dos program headers; `PH0` offset `0x74`, mida `0x1c000`, `PH1` offset `0x1c074`, mida `0x280`. Cap signatura literal `_FVH`.
- El fitxer és considerablement major que la suma dels segments indicats; hi pot haver dades fora dels segments declarats. **No interpretar la falta de `_FVH` com a prova que no hi ha firmware UEFI comprimit, ni anomenar definitivament l'arquitectura executable a partir d'un `e_machine` inusual.**
- Els dos GUID investigats (token candidat `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df`, VerifiedBoot `8e5eff91-21b6-47d3-af2b-c15a01e020ec`) no apareixen literalment en eixe fitxer, en les dues ordenacions provades.
- **Hipòtesi de treball:** `xbl_s.melf` podria correspondre a una fase de seguretat XBL-SC o a un component associat, i no al nucli UEFI on es registren els protocols consultats per ABL. Encara cal confirmar la correspondència exacta **en esta ROM**.

## Repositoris i fonts contrastats

| Font | Troballa útil | Aplicabilitat a SM4450/HyperOS 2 | Proposta |
| --- | --- | --- | --- |
| [qualcomm-linux/qcom-ptool](https://github.com/qualcomm-linux/qcom-ptool) i [qcs/qcm partition example](https://github.com/qualcomm-linux/qcom-ptool/blob/main/platforms/iq-x7181-evk/spinor/partitions.conf) | Plataformes Qualcomm modernes distingixen imatges `xbl_s.melf`, `uefi.elf` i `xbl_config.elf`. | Evidència de particions en *altres* plataformes, no inventari de la ROM sky. | Localitzar fitxers i mapatges reals de la ROM. |
| [linux-msm/xbltools](https://github.com/linux-msm/xbltools) | En certes generacions, XBL inclou carregador, nucli UEFI i component de seguretat; `xbl_core` allotja EDK II. | Heurístiques útils, però poden no descriure la nova divisió XBL-SC. | Aplicar eines de lectura únicament a la imatge correcta, no assumir que `xbl_s.melf` és `xbl_core`. |
| [OpenHandheldCollective/OpenABL](https://github.com/OpenHandheldCollective/OpenABL) | Projecte amb suport de compilació **SM4450** en 2026 i codi ABL Qualcomm públic com a referència. | Molt interessant per **comparar fluxos i estructures d'ABL**; no és prova de clau OEM vàlida ni d'execució en Redmi bloquejat. | Consultar font i símbols rellevants sense flashejar-ne binaries. |
| [lrh2000/Xiaomi-bootloader](https://github.com/lrh2000/Xiaomi-bootloader) | Investigació Xiaomi clàssica: ABL delega a Mi-Token; implementació d'eixe protocol localitzada en XBL del dispositiu de referència. | Redmi Note 8T / 2020; no extrapolar criptografia ni localització a sky 2026. | Guia de mètode, no substitut de l'anàlisi del nostre XBL. |
| [TheAirBlow/HyperSploit](https://github.com/TheAirBlow/HyperSploit) | El projecte indica que el bypass d'associació es va corregir en noves builds HyperOS 2 i a HyperOS 3; repositori arxivat en agost 2026. | No hi ha evidència que funcione en OS2.0.218.0.VMWEUXM. | Prioritat baixa; no confondre binding de compte amb VerifiedBoot. |
| [MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass) | Bypass de restriccions d'associació comunitària; l'intent anterior de l'investigador ja fallà amb dades del seu compte. | No evita necessàriament firma del token ni cadena de VerifiedBoot. | Prioritat baixa en la ruta offline actual. |
| [kasnria001/qualcomm_gbl_exploit_poc](https://github.com/kasnria001/qualcomm_gbl_exploit_poc) i [Android Authority (març 2026)](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/) | PoC de GBL + altres errors amb dispositius molt més nous, especialment Snapdragon 8 Elite Gen 5 / Android 16. | El Redmi 12 5G de l'estudi és Android 15 / SM4450 i els marcadors Fastboot esperats no s'han trobat. | Prioritat baixa llevat que l'inventari mostre component GBL aplicable. **No reutilitzar payloads de flash.** |
| [Jz8Root/xiaomi-hyperos-bootloader-unlock](https://github.com/Jz8Root/xiaomi-hyperos-bootloader-unlock) | Estudi 2026 de desbloqueig HyperOS mitjançant **MediaTek LK / BROM / seccfg / RPMB**. | **No aplicable directament al Qualcomm SM4450**, que usa ABL/XBL. Un Redmi 12 (sense 5G) pot ser altre SoC. | Descartar este vector per al mòbil investigat. |
| [Qualcomm secure boot design](https://www.qualcomm.com/media/documents/files/secure-boot-and-image-authentication-technical-overview-v2-0.pdf) i [U-Boot mkmbn 2025](https://lists.u-boot-project.org/pipermail/u-boot/2025-June/592308.html) | Les imatges Qualcomm ELF firmades poden contindre capçaleres, taules hash, signatures i altres dades no evidents com a FV. | Context estructural, especialment per diferenciar envoltoris signats de payloads UEFI. | Parsejar correctament els segments i les dades addicionals, en mode només lectura. |

**Nota de prudència:** etiquetes `signed` en fitxers de tercers, inclòs OpenABL, no demostren que la firma siga acceptada pel maquinari Xiaomi amb secure boot. No executar ni flashejar.

## Decisió tècnica

**No continuar provant el mateix GUID en `xbl_s.melf` una altra vegada.** Primer inventariar totes les imatges del paquet Fastboot i els mapatges reals de `rawprogram*.xml`. El nostre repositori **ja té** un script preparat que ho fa: `scripts/analyze-bootchain.py`. Evitem duplicar ferramentes sense necessitat.

Executar a Debian, únicament lectura:

```bash
cd ~/redmi-sm4450-bootloader-research
git pull
python3 scripts/analyze-bootchain.py \
  ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
```

Amb l'eixida, prioritzar:
1. Si hi ha `xbl.elf`, `uefi.elf`, `imagefv.elf` o algun equivalent que es correspon amb les particions rellevants del model.
2. En la imatge UEFI més plausible, analitzar el volum FV/FFS (incloent descompressió *offline* si cal) i els GUID de protocol o noms de mòdul. *No* esperar signatures literals en payloads comprimits.
3. Si no hi ha cap imatge UEFI evident, caracteritzar amb més rigor l'estructura del firmware signat sense cap càrrega al dispositiu.
4. Amb evidència real del mòdul responsable, seguir el callback del protocol token `+0x10` que ABL crida a `0x57E48`.

**Estat:** cap exploit ni desbloqueig verificat. No tocar el telèfon ni dades FRP/tokens.
