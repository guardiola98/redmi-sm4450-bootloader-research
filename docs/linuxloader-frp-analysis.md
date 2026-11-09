# Anàlisi estàtica de LinuxLoader — partició FRP i IsAllowUnlock


> Nota de vigència: informe històric. Les conclusions posteriors i correccions
> estan en [contractes MiToken](mitoken-provider-contracts.md) i
> [VerifiedBoot](verifiedboot-failure-analysis.md), inclosa la falta de ruta
> demostrada de reserva nul·la i la identitat confirmada de MiToken.

**Data:** 2026-11-09  
**Origen:** binari `LinuxLoader.pe` adjunt per l'investigador, extret del paquet `OS2.0.218.0.VMWEUXM`; **no distribuïm el PE**.

## Verificació del fitxer

- `file`: PE32+ executable for EFI (application), ARM64, 3 sections
- SHA-256: `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`
- Grandària: 843.776 bytes
- Binari inspeccionat offline amb `llvm-objdump`; cap execució ni canvi del dispositiu.

## Troballa central (verificada per desassemblatge)

A `FUN_00054980`, el missatge `IsAllowUnlock is %d` mostra un flag global de 32 bits en `0x000cb5c0`. El flux en aquesta mateixa funció és:

1. A `0x55a74`–`0x55a84`, passa una cadena de partició UTF-16 i un punter de sortida a `0x59fc8`. La cadena a `0xAF508` és **`frp`** (UTF-16LE); `0x59fc8` deriva a `0x56148`, que busca un objecte de partició i guarda el resultat al punter de sortida. Aquesta evidència dona suport fort a una cerca de la partició FRP, però la signatura completa de cada helper encara no està reconstruïda.
2. A `0x55ae8`, recupera a `x22` el descriptor/handle obtingut de la cerca (`[x29,#-0x90]`) i comprova si és nul.
3. A `0x55af0`–`0x55b04`, consulta un camp a `[x22+8]+0xc`, el passa a `0x5950` (rutina que sembla reservar un búfer) i copia el resultat de `x0` a `x23`. **`x23` és un punter de búfer, no el valor final del flag.**
4. A `0x55b08`–`0x55b24`, prepara una crida indirecta `blr x9` emprant un callback a `[x22+0x18]`, amb destí `x23` i altres camps del descriptor; en cas d'error se salta el càlcul del flag. Tot apunta a un accés de lectura a partició, però falta tipar formalment el protocol/callback.
5. En el camí d'èxit, a `0x55b2c`–`0x55b40`:

   ```asm
   ldr  x8, [x22, #0x8]
   ldr  w8, [x8, #0xc]
   sub  w8, w8, #0x1
   ldrb w8, [x23, w8, uxtw]
   and  w8, w8, #0x1
   str  w8, [x28, #0x18]
   ```

   És a dir: calcula un índex `N-1` a partir d'un camp de la partició, recupera el bit menys significatiu del byte `buf[N-1]`, i guarda el resultat a `DAT_000cb5c0`. **No està demostrat que `N` siga la mida total real de la partició**, ni quina validació de rang es fa; no descriure'l encara com 'últim byte de tota la partició'.
6. A `0x55aa8`–`0x55ab4`, una altra branca mostra el valor amb `IsAllowUnlock is %d`, en passar `w2=[x28+0x18]` a una rutina de log. **Precaució temporal important:** en la funció, eixe log apareix **abans** de la lectura del búfer de FRP (`0x55b20`) i de l'escriptura del bit (`0x55b40`), i la rutina pot tornar a la regió del log després de l'escriptura (`0x55b4c` salta a `0x55a90`). Per tant, no és correcte presentar-lo com una única seqüència lineal de lectura FRP → missatge.

Cadenes contextuals del **mateix** PE:
- `0xAE085`: `IsAllowUnlock is %d`
- `0xAE09A`: `Error Reading FRP partition: %r`
- `0xAE0BB`: `Error Locate MiToken Protocol: %r`
- `0xAE0DE`: `Error Get Token Length: %r`

### Ruta MiToken inspeccionada addicionalment

- Després del camí FRP, el flux pot arribar a `0x55b50`: prepara `x0=0xb1800` (punter a dades que semblen un GUID de protocol) i `x2=[x29-0xe0]`, i crida `0x59f48`.
- `0x59f48` posa `x1=0` i delega mitjançant un salt indirecte `[x8+0x228]+0x140`. El patró és **compatible amb una crida de localització de protocol UEFI**, però la taula de protocol encara no s'ha tipat ni verificat formalment.
- Si el retorn de `0x59f48` és zero, `0x55be0..0x55bf0` carrega el protocol recuperat i crida `0x59fe0` amb `x1=0` i un punter local `x2`; `0x59fe0` salta a un callback de `[x0+8]`. La seqüència i les cadenes `Error Get Token Length` / `Token Length` són compatibles amb consultar la **longitud del token**.
- Després `0x55c70..0x55c94` prepara una altra crida al mateix callback, amb més paràmetres, i pot emetre `Error Get Token`. Això apunta a obtenció de token en una ruta separada de FRP.
- **Pendent:** provar la identitat exacta del GUID/protocol, el format del token i si intervé en `oem unlock`; no deduir-ho només del text ni de la proximitat de les instruccions.

La presència de **MiToken** suggereix una interfície d'autorització diferent de la lectura FRP, però **encara no està demostrat** que les dues vies siguen suficients ni necessàries per desbloquejar el dispositiu.

## Interpretació i límits

- El binari **conté un mecanisme de lectura FRP que acaba determinant un bit de `IsAllowUnlock`** en una branca concreta.
- Açò **no** indica que es puga escriure el flag mentre el bootloader està bloquejat, ni que siga suficient per desbloquejar-lo.
- `oem unlock` i `flashing get_unlock_ability` existeixen en el PE, però encara no s'ha comprovat exactament quin dels molts estats consulta cadascuna d'eixes comandes.
- **No hi ha vulnerabilitat o bypass funcional confirmat.** Evitar modificar `frp` o fer proves d'escriptura; les dades FRP també es relacionen amb funcionalitats de protecció del dispositiu.

## Següent pas

Des de Ghidra (o amb eines estàtiques pròpies), resoldre les **referències de codi** a les cadenes `Error Reading FRP partition`, `Error Locate MiToken Protocol` i `Error Get Token Length`; reconstruir per separat:
1. Quina interfície utilitza el callback indirecte a `0x55b20` i què signifiquen els camps del descriptor i `N`.
2. Quina funció fa servir el flag `DAT_000cb5c0` en la decisió efectiva de `oem unlock` o `flashing get_unlock_ability`.
3. Si `MiToken` és obligatori per a la decisió o només una ruta auxiliar.

Només després val la pena comparar els fragments de funcions entre firmwares anteriors **verificats**. Cap flash, esborrat o ordre de desbloqueig en esta fase.
