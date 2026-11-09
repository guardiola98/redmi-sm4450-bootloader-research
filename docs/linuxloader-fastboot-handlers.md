# Fastboot unlock handlers — offline PE analysis

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
