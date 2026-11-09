# Baseline observations

Device measurements taken **2026-11-09**, reported by the device owner.

## Android and boot

```text
Model: 23076RN8DY
Device: river
Build: OS2.0.218.0.VMWEUXM
Android: 15
SoC: SM4450
Board: parrot
Kernel: 5.10.246-android12-9-00012-g730d06ec05ff-ab15159037
Kernel built: Tue Apr 7 14:07:39 UTC 2026
Android security patch: 2026-10-01
Vendor security patch: 2026-04-05
SELinux: Enforcing
ro.boot.verifiedbootstate: green
ro.boot.flash.locked: 1
ro.boot.vbmeta.device_state: locked
ro.boot.slot_suffix: _b
```

The device reported `CONFIG_BPF=y`, `CONFIG_KALLSYMS=y`, `CONFIG_KPROBES=y`, and `CONFIG_SECURITY_SELINUX=y`. These kernel *build* features do **not** imply that an unprivileged app can access privileged BPF, kallsyms, or kprobes.

The AVB digest was intentionally **not** included in this public baseline. Firmware hashes can be recorded later when there is a concrete, verified matching image.

## HyperOS binding experiment (redacted)

Testing the upstream [Xiaomi-HyperOS-BootLoader-Bypass](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass) against this device showed that its captured `CloudDeviceStatus: args` value is **not a single Base64 string**.

Non-sensitive structural metadata only:

```text
Args length: 1292
Contains whitespace: no
Non-Base64 delimiter character codes: 23 26 5E 21 (hex)
Base64-like segments: 2
Segment #1: 344 chars -> 256 bytes; 16-byte-aligned
Segment #2: 940 chars -> 704 bytes; 16-byte-aligned
Segment #1: OpenSSL AES-128-CBC decryption failed with upstream static key/IV
Segment #2: OpenSSL AES-128-CBC decryption failed with upstream static key/IV
Whole args: invalid strict Base64
```

**Interpretation:** neither segment can be directly decrypted with the upstream routine as tested. Alignment alone does not establish AES format. Exact delimiters, internal framing, authenticity and algorithm are unknown. No functional bypass or server acceptance has been demonstrated.

Related reports:
- [Upstream issue #155](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass/issues/155)
- [Upstream issue #264](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass/issues/264)
- [Upstream issue #323](https://github.com/MlgmXyysd/Xiaomi-HyperOS-BootLoader-Bypass/issues/323)

## Outstanding evidence

- Identify the *exact* vendor kernel source tag/branch and matching patch provenance.
- Examine matching official firmware metadata and offline images without flashing.
- Establish affected-component and exact-build applicability for any public security bulletin.
- Determine whether any candidate affects **bootloader locking** rather than only Android user-space/kernel privileges.
