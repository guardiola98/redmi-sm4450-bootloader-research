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
