# Fastboot unlock handlers — offline PE analysis


> Nota de vigència: informe històric. Les conclusions posteriors i correccions
> estan en [contractes MiToken](mitoken-provider-contracts.md) i
> [VerifiedBoot](verifiedboot-failure-analysis.md), inclosa la falta de ruta
> demostrada de reserva nul·la i la identitat confirmada de MiToken.

**Date:** 2026-11-09  
**Firmware:** OS2.0.218.0.VMWEUXM  
**Input:** LinuxLoader.pe SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`  
**Method:** LLVM AArch64 disassembly, read-only. No Fastboot commands sent and no partitions changed.

## Distinguish the two features

### `flashing get_unlock_ability` — reporting

- A command string is present in the PE at file offset `0xADD1D`.
- Code near `0x57C18..0x57C54` loads the global data base `0xCB5A8`, reads `w3=[0xCB5A8+0x18]` at **`0x57C50`**, and passes it to a formatting routine `0x4488`.
- The format string at `0xAEAC7` is `get_unlock_ability: %d`.
- This supports that one handler **reports** the FRP-derived flag. Reporting it is not the same as granting permission.

### Unlock / lock state change routes

- Code at **`0x57E34..0x57F1C`** checks a prior callback return, uses `0x5A1FC` and on success invokes **`0x43D88`** twice.
- Examples of the calls seen in AArch64:
  - `0x57E90`: `mov w1,#1`; `0x57E94`: `bl 0x43D88` (the value in `w0` comes from the preceding path, not yet semantically proven).
  - `0x57EC0`: `mov w0,#1`; `0x57EC4`: `mov w1,#1`; `0x57EC8`: `bl 0x43D88`.
  - An alternate branch `0x57F2C..0x57F68` invokes `0x43D88` with `w1=0` and variable `w0`.
- Following these calls are explicit failure messages **`Error Set Device Unlock: %r`** (`0xAEB8D`), **`Error Set Device UnlockCritical: %r`** (`0xAEBCD`) and failure to update lock state (`0xAEBAA`, `0xAEBF2`).
- `0x43D88` is **not a simple bit assignment**. It is a larger routine with two separate subpaths selected by `w0` (`0` vs `1`) and an argument `w1`; it delegates to `0x440B0` or `0x44188`, and has additional operations and failure exits. The complete calling convention, object identity and persistence mechanism have not yet been formally typed.
- **Important:** the relationship of any MiToken response to this handler has not been established.

### Further inspection of the state-persistence helpers

- The two subroutines `0x440B0` and `0x44188` are strongly parallel: the first compares the requested byte with the current result of `0x43B60`, then writes the new byte at `0xC294D` (base `0xC2940` + `0xD`); the second compares against `0x43B70` and writes at `0xC294E` (+ `0xE`).
- In both changed-value paths they invoke **`0x2D728`** with `w0=1`, `x1` referencing a configuration buffer near `0xC2940`, and `w2=0x998` (2,456 bytes). They propagate the return value. **These are not just RAM assignments**: the common helper appears to commit configuration data.
- `0x2D728` uses a GUID pointer `0xB1790` with an indirect service call at `0x2D7B0`, then calls the located interface through an indirect function at `0x2D840` with the previously supplied arguments. It returns a status. We have not yet typed the GUID or its actual persistence backend. **Do not label it FRP or a specific secure storage mechanism without verifying the protocol.**
- Thus the examined lock-state routine has **two distinct state fields** and a separate persistence interface. This supports the distinction between *FRP-derived reporting* and *device lock-state update*. No conclusion about remotely available authorization, authentication bypass or hardware fuse state.

### Qualcomm VerifiedBoot protocol — GUID identified

**Directly verified against the owner-provided PE** (SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`):

- The 16 bytes at PE file offset/RVA `0xB1790` are `91 ff 5e 8e b6 21 d3 47 af 2b c1 5a 01 e0 20 ec`.
- Interpreted with UEFI GUID byte ordering, these are **`8e5eff91-21b6-47d3-af2b-c15a01e020ec`**.
- Public Qualcomm-related sources identify this as **`QCOM_VERIFIEDBOOT_PROTOCOL`**, used for verified-boot/device-state operations, e.g. [public PoC's QcomVerifiedBootProtocol documentation](https://github.com/kasnria001/qualcomm_gbl_exploit_poc) and [external discussion](https://blog.xzr.moe/archives/541/). Those public claims and their exploitability are not equivalent to validation on this device.
- At `0x2D7A4..0x2D7B0`, the routine `0x2D728` calls a UEFI service with this GUID, and at `0x2D82C..0x2D840`, after a successful status result, it calls a function pointer at `[protocol + 8]` with `w1` (operation), `x2` (configuration buffer), and `w3` (length). This strongly supports that **`0x2D728` wraps a VerifiedBoot state/configuration operation**.
- Observed **`0x998` (2456 bytes)** at the two state-update call sites. Do not assume that other Qualcomm models using larger buffers have the same exact layout or operation semantics.
- A separate GUID at offset `0xB1800` decodes to `0c00a314-11a1-4d7a-a5c8-70bd5f88e7df`; its interface identity has **not** been independently established here. Don't conflate it with VerifiedBoot.

**Security consequence:** finding a privileged VerifiedBoot protocol **does not establish that untrusted code can invoke it**. Qualcomm's boot chain and Xiaomi authorization may restrict code execution and access; no reachable exploit path or persistent unlock is demonstrated. Do not attempt to write/configure the protocol on the live device.

### Other lock enforcement

- A separate code path with the string `Flashing is not allowed in Lock State` references `0x5668C..0x56694`.
- Another path references `Fastboot boot command is not available in locked device` near `0x58018..0x58024`.
- These correspond to separate restrictions; they do not show a bypass.

## Additional validation — token gating before state write (2026-11-09)

Rechecked directly using LLVM 17 `llvm-objdump` on the owner-provided PE, hash verified.

- `0x57CCC` starts a Fastboot handler. Within it, `0x57D1C: bl 0x59F90` performs an indirect UEFI service call after setting a protocol GUID pointer; the nearby error messages are `Error Locate Token Protocol`, `Error Get Token Length`, and `Error Get Token`.
- `0x57DD8..0x57DE4`: `ldr x9,[x8,#8]; mov x0,x8; blr x9; cbz x0,0x57E34`. The branch on return status leads to the next validation step only on zero; failure produces the messages `Error Verify Token: %r` and `Token Verify Failed, Reboot the device`. This is **strong evidence of a token verification callback**, though we have not fully identified the vtable implementation or token format.
- `0x57E34..0x57E4C`: after preparing `x1=x20`, `x2=x22`, `w3=w21`, the call `bl 0x5A1FC` executes a second indirect callback. The veneer `0x5A1FC` loads `x0=[x24-0x10]`, `x8=[x0+0x10]`, then `br x8`. The handler proceeds to `0x57E90` **only when its return value is zero**; on error it logs `Error Verify Token`/the reboot message and exits the success path.
- Only **after both zero-status checks** does the `0x57E90` branch call `0x43D88` (which in turn delegates to VerifiedBoot persistence). Thus a bare reference to the VerifiedBoot GUID is **not** an authorization bypass.
- `0x57F24` appears to be a distinct alternate handler path that calls `0x43D88` with zero-valued arguments (likely lock); dispatch still requires confirmation before definitively naming it.
- The blob contains text `Error Locate Token Protocol` at file offset `0xAEB07`, `Error Get Token Length` at `0xAEB24`, `Error Get Token` at `0xAEB3C`, `Error Verify Token: %r` at `0xAEB4D`, and `Token Verify Failed, Reboot the device` at `0xAEB65`.
- The GUID at `0xB1800` is **not identified by a reliable public definition**; the proximity to token-related code makes it a candidate for a Xiaomi token protocol, not proof.

**Scope:** these observations show *control-flow conditions* leading to a state-change call, not the full cryptographic verification or an exploitable flaw. There is no demonstrated way for a locked SM4450 handset to execute an arbitrary EFI app.

### Public GBL research applicability

The publicly reported 2026 GBL exploit chain involved Android 16-era devices and privileged code execution in an EFI boot path, plus additional device-specific vulnerabilities. This PE is from Android 15, and our marker scan did not identify the two GBL fastboot command anchors. That does **not** prove the firmware is patched or invulnerable; it only leaves the chain's relevance to this model unverified. Sources: [Android Authority's March 2026 report](https://www.androidauthority.com/qualcomm-snapdragon-8-elite-gbl-exploit-bootloader-unlock-3648651/) and [Qualcomm's patch statement](https://www.androidauthority.com/qualcomm-gbl-exploit-fix-statement-3649176/).

## Current conclusions

1. The FRP-derived global bit is observed by a reporting routine (get_unlock_ability).
2. A lock-state change path invokes a separate larger routine and checks its return; it is **not** simply writing the FRP flag.
3. It remains **unverified** whether the FRP bit is required, sufficient, or even directly read in the actual persistent unlock transition; or whether MiToken provides independent authorization.
4. No vulnerability or repeatable unlock procedure has been found.

## Next research (offline)

- Determine precise callers and interfaces of `0x43D88`, `0x440B0`, `0x44188` and the precondition `0x5A1FC`; identify whether persistent state uses UEFI variables, security world, storage, or an abstraction.
- Resolve command dispatch routing to `0x57E90` / `0x57F24` before labelling particular functions as `oem unlock` or `oem lock`.
- Trace the MiToken callback and whether it supplies arguments to the unlock-state transition.
- Compare the exact functions with an authentic older same-model firmware, if available.

Do **not** write FRP, bypass user authentication, flash ABL/XBL, or run non-vetted exploits on a locked phone.

## Refined token protocol data flow — 2026-11-09

**Important correction to the preceding "two checks" description:** the callback at `0x57DE0` most likely **retrieves the token**, rather than independently verifying it. Only the subsequent callback at `0x57E48` has the argument structure expected of **signature/token verification**. The zero-status branches mean both stages must succeed; they do not imply two cryptographic verifications.

AArch64 evidence from the verified `LinuxLoader.pe`:

1. `0x57CE0: bl 0x5A214`; the helper assigns `w21=w2` and `x22=x1` then branches onward, preserving the incoming payload pointer and length for later verification. This explains the apparently unexplained `x21/x22` registers in the handler.
2. `0x57D0C..0x57D1C`: request a UEFI protocol identified by a GUID stored at `0xB1800` (`0c00a314-11a1-4d7a-a5c8-70bd5f88e7df`). Its precise symbolic name is **not confirmed**. On error the code uses `Error Locate Token Protocol`.
3. `0x57D58..0x57D64`: invoke the function pointer at protocol offset `+0x08` with `x1=0` and a pointer to an integer length. This matches a *query required token length* operation.
4. `0x57DB8..0x57DE0`: allocate `length + 1` bytes in `x20`; invoke **the same `+0x08` callback** with `x1=x20`, `x2` pointing to the length field. This matches *read/get token*. A zero status branches to `0x57E34`; a non-zero status goes through `Error Get Token` handling.
5. `0x57E34..0x57E48`: terminate token buffer at the declared length and call the function pointer at protocol offset **`+0x10`**, via veneer `0x5A1FC`, with `x1=x20` (retrieved token), `x2=x22` (incoming payload), `w3=w21` (payload length). A zero status proceeds to the state-transition call `0x43D88`; failure reaches `Error Verify Token` and `Token Verify Failed, Reboot the device`.
6. The `0x43D88` / Qualcomm VerifiedBoot configuration update is invoked **after** successful retrieval and verification in this path. The incoming payload's origin in the host Fastboot command is not fully typed here.

**External precedent, not proof of same implementation:** [lrh2000/Xiaomi-bootloader](https://github.com/lrh2000/Xiaomi-bootloader) reconstructs an older Xiaomi implementation where ABL handles the token protocol and XBL contains its implementation, and the device verifies a server-signed token. Its reference device (Redmi Note 8T, 2020) is different from this SM4450/2026 firmware. Therefore verifying **where this device implements the `+0x10` callback likely requires analysing its matching XBL image**, not just `LinuxLoader.pe`.

**No vulnerability or independent unlock method has been demonstrated**. Never upload live tokens, credentials, device identifiers or operate on locked phone partitions for this study.
