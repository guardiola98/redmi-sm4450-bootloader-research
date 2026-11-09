# Exact firmware identification — OS2.0.218.0.VMWEUXM

Identified through public firmware indexes on 2026-11-09. **Metadata is third-party indexed and must be verified against the downloaded archive before use.** This document does not authorize flashing.

## Important naming distinction

The device reports `ro.product.device=river` but public Xiaomi distribution archives for the Redmi 12 5G / POCO M6 Pro 5G family use **`sky`** as their firmware codename. Do not assume arbitrary `sky` partitions are interchangeable: verify model/region/build and firmware metadata.

## EEA Fastboot package (best candidate for offline boot-chain analysis)

- Build: `OS2.0.218.0.VMWEUXM`
- Android: 15
- Package: `sky_eea_global_images_OS2.0.218.0.VMWEUXM_20261021.0000.00_15.0_eea_330e013f7f.tgz`
- Indexed size: ~7.3 GB
- Indexed MD5: `330e013f7fc6acc15e7f17e8edb4d6a8`
- Indexed release: 2026-10-21
- Source indexes:
  - https://mirom.ezbox.idv.tw/en/phone/sky/
  - https://xmfirmwareupdater.com/hyperos/sky/stable/OS2.0.218.0.VMWEUXM/

## EEA Recovery package

- Package: `sky_eea_global-ota_full-OS2.0.218.0.VMWEUXM-user-15.0-24f347146e.zip`
- Indexed size: ~5.0 GB
- Indexed MD5: `24f347146e578cff0898dbd5d23925b9`
- Indexed release: late October–early November 2026
- Source indexes:
  - https://mirom.ezbox.idv.tw/en/phone/sky/
  - https://miuirom.org/phones/redmi-12-5g

## Offline analysis plan

1. Obtain the archive from a URL hosted by Xiaomi (not an unknown repackaged executable), and record the final download URL and file SHA-256.
2. Verify the *whole archive* against the **indexed MD5** and verify its name/build/region.
3. List the archive's contents first; identify ABL/XBL/vbmeta/boot/vendor_boot images, if present. Do not execute `flash_all.sh` or use Mi Flash.
4. Use offline image inspection tools and build a file-hash inventory, without flashing or extracting private data.
5. Compare relevant versions and public kernel source tags. Establish security patch applicability before any claim of vulnerability.

Do **not** upload binary ROMs, raw memory dumps, credentials or private logs to this repository. The hash checks above confirm correspondence to the indexed filenames; MD5 is not a cryptographic authenticity guarantee.
