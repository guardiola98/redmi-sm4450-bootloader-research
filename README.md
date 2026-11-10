# Redmi SM4450 bootloader research

Community-oriented, reproducible research on the boot chain of Xiaomi devices built on Qualcomm **SM4450** (platform **parrot**), initially focused on a **Redmi 12 5G** running HyperOS 2.

**Status: research only. No unlock, exploit, or root method has been demonstrated.**

The current static/offline audit is summarized in [candidate triage](docs/candidate-triage.md)
and the [2026-11-10 session report](docs/audit-session-2026-11-10.md), with
published commits, reproduction steps and an exact resume point in [PROGRESS.md](PROGRESS.md).
This audit phase uses local artifacts and synthetic tests only; it does not use
the device collection workflow described in the historical baseline below.
The current evidence covers [SCM cleanup contracts](docs/scm-initialization-analysis.md),
[TzDxeLA resource ownership](docs/tzdxe-policy-consumer.md),
[file resource contracts](docs/tzdxe-file-resource-contracts.md),
[UEFI configuration provenance](docs/uefi-configuration-provenance.md) and
[RAM descriptor conversion](docs/uefi-ram-table-analysis.md).
The [identified XBL producer](docs/xbl-ram-producer-analysis.md) emits version 3
and bounds intact tables to 32 entries; the studied normal path does not
activate the conditional v1/index or 33rd-entry defects.
[FeatureEnabler](docs/tzdxe-policy-consumer.md#consumidor-featureenabler-i-correcció-de-la-ruta-de-fitxers)
is a verified QSEE partition-loading consumer, not evidence of the file route.
Confirmed programming defects are distinguished from conditional activation
and unproven security impact.

The later [read-only Android/QSEE validation](docs/device-qsee-validation-2026-11-10.md)
correlates `mtd@1.3` with the observed cleanup messages. Repeated passive
captures contained the same historical events; no new unlock evidence was
found. A [passive ADB collector](scripts/collect-qsee-diagnostics.py) and
[offline analyzer](scripts/analyze-qsee-logcat.py) emit only aggregates.
Raw logs must remain private, even when restricted to these tags.

## Goals

- Document device identity, kernel configuration, security patch levels, and boot state using **read-only ADB**.
- Compare public Xiaomi/Qualcomm kernel sources, firmware versions, Android security advisories, and public code.
- Study why existing HyperOS account-binding bypass tools fail on this device.
- Develop **reproducible, non-destructive** test cases, with sensitive values redacted.
- If a genuine issue is discovered, validate responsibly and coordinate disclosure before publishing any dangerous proof of concept.

## Tested device snapshot — 2026-11-09

| Field | Observation |
| --- | --- |
| Device | Redmi 12 5G |
| Model | 23076RN8DY |
| Device codename | `river` |
| SoC | Qualcomm SM4450 |
| Board platform | `parrot` |
| Firmware | `OS2.0.218.0.VMWEUXM` |
| Android | 15 |
| Kernel | `5.10.246-android12-9-00012-g730d06ec05ff-ab15159037` |
| Kernel build | 2026-04-07 14:07:39 UTC |
| Android patch level | 2026-10-01 |
| Vendor patch level | 2026-04-05 |
| SELinux | Enforcing |
| Verified Boot | green |
| Bootloader state | locked |
| Slot | _b |
| Kernel config | CONFIG_BPF=y; CONFIG_KALLSYMS=y; CONFIG_KPROBES=y; CONFIG_SECURITY_SELINUX=y |

The above values were obtained from one device. **Patch-level differences, config options, and an older kernel version do not establish exploitability**. OEM patches may be backported. Root in Android does not necessarily permit unlocking the bootloader.

## Start: safe local inventory

With Android debugging authorised, run:

```bash
bash scripts/collect-device-info.sh
```

The script makes no changes to the device, does not save sensitive identifiers, and prints a redacted summary for review. Please inspect the output before sharing it publicly.

## Research tracks

1. **Firmware and boot chain:** compare publicly distributed ABL, XBL, vbmeta, and version metadata offline; do not flash anything.
2. **Kernel and vendor modules:** identify matching published source branches and applicable patches before considering tests.
3. **HyperOS binding:** document a known incompatible encrypted-argument format without logging tokens or contacting Xiaomi.
4. **Recovery planning:** understand A/B slots, official firmware availability and device-specific recovery limitations before attempting anything destructive.

See [the baseline investigation](docs/baseline.md) and [research references](docs/references.md).

## Safety

- **Do not upload** raw `logcat`, `args`, HTTP headers, Xiaomi account cookies, unlock tokens, IMEI, serial numbers, or unredacted dumps.
- Do not flash partitions, modify AVB, or attempt EDL programming merely to reproduce this baseline.
- Even a successful kernel privilege escalation is not proof of a persistent bootloader unlock.
- Treat third-party bypass claims as unverified until reproducible on the exact firmware.

## License

Documentation and scripts are provided for research and educational purposes. No warranty; device operations are performed at the owner's risk.
