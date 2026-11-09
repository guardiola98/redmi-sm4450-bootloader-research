# Efectes del fals èxit de VerifiedBoot en ABL

Anàlisi local del 2026-11-09. Firmware no executat; dispositiu no utilitzat.
LinuxLoader SHA-256 `60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`.
VerifiedBootDxe SHA-256 segons [manifest](protocol-pe-manifest.json).
RVA amb base zero; pseudocodi i instruccions Ghidra en `work/LinuxLoader.c`,
`work/LinuxLoader.asm` i `work/VerifiedBootDxe.{c,asm}`. Exportadors existents
`DumpFunctions.java` i `DumpInstructions.java`, Ghidra 12.2.

## Resultat

El defecte de propagació d'error pot deixar discrepància entre RAM i
emmagatzematge. No demostra un desbloqueig sense autorització. A més, la
lectura inicial considera vàlid l'èxit sense comprovar que s'hagen rebut
bytes: pot conservar dades prèvies o inicialitzar valors per defecte.

## Escriptura i retorn al caller

- VerifiedBoot `0x17bc` (escriptura) / `0x185c` (lectura), reserva nul·la:
  salt al log, `0x1950: mov x22,xzr`, retorn zero a `0x1640` sense copiar
  dades ni enviar les peticions de lectura/escriptura keymaster d'esta operació.
  Selecció segura i inicialització QSEE anteriors es donen per superades.
- ABL `0x2d728` propaga l'estat del callback VerifiedBoot +8.
- Setters `0x440b0` / `0x44188`: comparen amb RAM; si és igual, retornen
  zero sense persistir. Si canvia, escriuen primer `+0xd` / `+0xe` del búfer
  `0xc2940` (`0x440e4` / `0x441bc`) i criden `0x2d728`, op=1, mida=0x998
  (`0x440f0` / `0x441c8`). No restauren el byte dins del setter, tampoc
  quan reben un error real. Un fals èxit deixa el nou byte en RAM.
- `0x43d88` continua, en cas de zero, amb `0x2e5f0` (`0x43e88`). Si esta
  operació falla, intenta el setter amb el valor booleà contrari i retorna
  error; no és una restauració universal del valor anterior. Si funciona,
  prepara el missatge recovery/wipe i operacions posteriors, que també poden
  fallar. El fals èxit del primer setter no garantix èxit final Fastboot.
- `0x2e5f0` pot retornar directament o invocar VerifiedBoot +0x30, segons
  altres consultes. Efectes interns d'eixe callback fora del model.
- Una escriptura posterior reeixida passa **tot** el búfer de 0x998 bytes:
  podria persistir també un canvi anterior que només estava en RAM.
  Per això «no persistix esta crida» no equival a «mai podrà persistir».

## Lectura inicial

`0x44640` consulta la configuració quan el flag `0xb2908` és no nul.
A `0x44670` crida op=0. Si retorna zero, posa el flag a zero
(`0x446e8..0x446f0`) i compara la capçalera amb `ANDROID-BOOT!` (13 bytes).
No comprova independentment si la lectura ha copiat dades.

Si la capçalera del búfer preservat és vàlida, conserva els camps existents.
Si no ho és, buida el búfer, posa la capçalera i consulta `0x2e4c0`.
`0x44814..0x44848` usa només el byte baix del retorn: no zero → bits
normal/crític a zero; zero → tots dos a u. Després intenta persistir el
búfer (`0x4486c`). Un altre fals èxit ací deixa només la RAM inicialitzada.

`0x2e4c0` consulta `0x10284`: en èxit normalitza el byte d'estat a 0/1;
en error retorna el byte baix de l'estat. No s'ha demostrat que en este
mòbil bloquejat puga retornar zero incorrectament. No atribuïm un estat
segur concret a tots els errors possibles ni assumim el contingut de RAM
abans de la primera crida. El model prova explícitament ambdues capçaleres.

## Autorització

La instrucció `0x57e48` invoca MiToken +0x10; `0x57e4c` només passa a
`0x57e90` si retorna zero. En eixe punt x0 continua sent zero i w1=1:
`0x57e94` crida `0x43d88(0,1)`. Després d'èxit, `0x57ec8` crida
`0x43d88(1,1)`. La fallada de reserva dins de la persistència succeïx
**després** d'esta comprovació i no l'elimina. Això descriu esta ruta;
no és una auditoria de totes les entrades possibles al protocol.

## Model i taula de resultats

Executar `python3 scripts/test-verifiedboot-failure-model.py`: **9 tests passen**.
Model de flux i efectes amb fallades proporcionades com a dades; no emula
instruccions, RSA, QSEE, RPMB, el reset posterior ni el handler Fastboot complet.
Les comprovacions d'instruccions anteriors són evidència separada del model.

| Escenari modelat | RAM | Persistència | Retorn local |
| --- | --- | --- | --- |
| Setter canvia bit, reserva nul·la | Nou bit | Sense canvi | Èxit fals |
| Repetició del mateix setter | Nou bit | Sense canvi, ni nova crida | Èxit |
| Un altre setter provoca escriptura reeixida | Dos bits nous | Búfer complet actualitzat | Èxit |
| MiToken retorna error | Sense canvi del setter | Sense canvi del setter | Error abans del setter |
| Lectura nul·la amb capçalera vàlida prèvia | Conservada | Sense canvi | Èxit fals; flag de lectura es neteja |
| Lectura nul·la, capçalera invàlida | Defaults segons consulta separada | Depén de l'escriptura següent | Depén de l'escriptura següent |
| Lectura normal posterior | Estat llegit | Sense canvi | Èxit |

## Decisió i següent comprovació

Mantindre el defecte com a candidat de consistència i propagació d'errors,
amb impacte de seguretat pendent. No hi ha evidència d'una manera de forçar
la reserva nul·la des d'una entrada accessible al dispositiu bloquejat.

Prioritzar l'anàlisi de `0x10284` i dels callers de `0x44640` per aclarir
els errors de la consulta segura, l'estat inicial i la gestió del retorn;
després el callback VerifiedBoot +0x30 i els efectes posteriors a `0x43d88`.
No cal executar firmware ni provocar esgotament de memòria al telèfon.

## Continuació: consulta segura i caller inicial

Revisió de les exportacions locals C/ASM el 2026-11-09:

- `0x10284`, amb punter no nul: `0x10294..0x10298` compara el resultat
  de `0x100b4` amb `0xffffffff`. Eixe sentinella retorna exactament
  `0x8000000000000001` (`0x102f4..0x102f8`); el byte baix és **1**.
  Per tant, este error concret, passat per `0x2e4c0`, no selecciona els
  defaults desbloquejats. Això acota la incertesa expressada abans.
- Per a qualsevol altre resultat, `0x1029c..0x102b0` escriu el booleà
  `(resultat & 0x47) == 0x40` i retorna zero. Cal verificar encara com
  `0x100b4` obté el resultat en cada fallada SCM: el pseudocodi presenta
  registres `unaff_*` i un retorn `void`, insuficients per concloure-ho.
  La branca de punter nul no és la usada pel caller `0x2e4c0`.
- Hi ha una sola instrucció de crida directa a `0x44640` en l'exportació
  ASM: `0x173c`. Les dues ocurrències C corresponen a representacions
  solapades del mateix codi, no a dos callers independents. No descarta
  referències indirectes que l'exportació no identifique.
- `0x1740` continua cap a `0x17a4` només si el retorn és zero; altrament
  passa pel log opcional i l'epíleg `0x1770..0x17a0`. Un fals èxit supera
  este control, però això no prova l'estat dels camps ni un desbloqueig.

Següent pas acotat: reconstruir el retorn real de `0x100b4`, inclosos els
helpers compartits, amb instruccions; després callback VerifiedBoot +0x30.

## Retorn SCM reconstruït amb instruccions

`0x100b4` sí que retorna un valor de 32 bits. La signatura `void` del
pseudocodi no representa el flux real a través dels helpers compartits.

| Condició | Evidència RVA | Retorn w0 |
| --- | --- | --- |
| Localització retorna no zero | 0x100e8 → 0x10140 → 0x1016c | 0xffffffff |
| Localització retorna zero però punter nul | 0x100ec..0x100f0 → 0x10140 | 0xffffffff |
| Callback SCM +0x38 retorna no zero | 0x10110..0x1013c → 0x1016c | 0xffffffff |
| Callback retorna zero però resposta[0] != 1 | 0x1018c..0x10194 → 0x101a0 | 0xffffffff |
| Callback retorna zero i resposta[0] == 1 | 0x10198 → 0x10170 | 32 bits baixos de resposta[1] |

La crida usa identificador `0x02000604`. `0x10acc` inicialitza a zero els
quatre words de 64 bits de resposta; `0x10b50` inicialitza el punter de
protocol i el búfer d'arguments. Els logs de fallada convergixen en
`0x1016c`, que sobreescriu w0 amb el sentinella. L'epíleg `0x10af4`
restaura x19..x24 i conserva x0; el retorn passa per `0x10184..0x10188`.
Una fallada de canari va a `0x14f44`, sense retorn normal modelat.

En conseqüència, totes les fallades locals enumerades arriben a `0x2e4c0`
com a byte **1**. Amb capçalera invàlida i lectura falsament reeixida,
seleccionen defaults bloquejats. El zero encara pot vindre d'una resposta
SCM acceptada el word de la qual no satisfà `(word & 0x47) == 0x40`;
no s'ha demostrat que el dispositiu bloquejat produïsca eixa resposta.
No s'inferix el significat individual dels bits ni la correcció interna de TZ.

Model ampliat: **9 tests passen**, incloent localització fallida, punter nul,
error del callback, resposta inesperada, sentinella i respostes acceptades.
Són comprovacions del model, no execució del firmware. El callback
VerifiedBoot +0x30 continua pendent d'anàlisi interna.


## Callback VerifiedBoot +0x30: reset delegat a keymaster

Revisió estàtica local del 2026-11-09, hash del PE verificat contra el
manifest. Lectura de la taula PE a RVA `0xd180`: l'entrada `+0x30`
apunta a `0x1c44`. La rutina acaba a `0x1d88`; les instruccions següents
pertanyen a una altra rutina. No depenem d'una signatura del descompilador.

- `0x1c80..0x1c88`: localitza QSEE; si falla, conserva l'estat en x19
  i el retorna via `0x1d74`. El text a `0x9122` identifica Reset_State i
  gQcomQseecomProtocolGuid.
- `0x1cac..0x1d20`: reutilitza l'identificador global `0xd268` si no és
  zero. Altrament intenta recuperar-lo mitjançant un servei a offset +0x48;
  si falla, invoca QSEE +8 amb el nom ASCII `keymaster` (`0x8d0c`).
  Un error d'esta segona crida es propaga sense convertir-lo en èxit.
- `0x1d28..0x1d44`: envia comanda **0x10e**, petició de 4 bytes,
  resposta de 4 bytes, via QSEE +0x18 amb l'identificador de l'aplicació.
- `0x1d48..0x1d70`: retorna zero només si el transport i el word de
  resposta són zero. Qualsevol error d'estos dos valors retorna `0x50`.
  El text a `0x9191` confirma que el log mostra status i resposta.

En esta rutina no hi ha una reserva de pàgina ni la branca de reserva
nul·la observada en +8. El restabliment és una operació separada de la
persistència 0x202/0x203: l'èxit fals d'una escriptura anterior no força
que 0x10e tinga èxit. ABL `0x2e5f0` propaga este resultat quan invoca el
callback; també té camins que retornen zero sense invocar-lo, condicionats
per les consultes `0x9dbc` i `0x9db4`. La seua semàntica queda pendent.

La implementació interna de 0x10e en keymaster no està en este PE; el nom
Reset_State no prova quines dades persistents modifica. El word de resposta
local no s'inicialitza explícitament abans de la crida: la conclusió sobre
resposta zero pressuposa que el transport reeixit escriu la resposta segons
el seu contracte. No s'ha provat cap incompliment d'eixe contracte.

Validació: 9 proves del model existent passen; no modelen este callback.
Següent pas: resoldre les consultes `0x9dbc`/`0x9db4` que condicionen
la invocació i després contrastar el contracte del transport QSEE.
