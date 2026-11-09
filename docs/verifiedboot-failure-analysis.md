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


## Condicions ABL 0x9dbc / 0x9db4 resoltes — 2026-11-09

Comprovat contra els bytes del PE LinuxLoader SHA-256
`60d4bd50574f2fc469489d52a2672b3146ec0c862907907c494efcb86d89f9f7`
i l'exportació ASM local. En esta imatge, RVA i offset de fitxer
coincidixen en esta regió de `.text`.

| Rutina | Bytes | Instruccions | Resultat |
| --- | --- | --- | --- |
| `0x9db4` | `40 00 80 52 c0 03 5f d6` | `mov w0,#2; ret` | Sempre 2 |
| `0x9dbc` | `20 00 80 52 c0 03 5f d6` | `mov w0,#1; ret` | Sempre 1 |

No lligen estat, memòria ni protocols. Escriure w0 també posa a zero
els 32 bits superiors de x0. Els noms simbòlics originals i el significat
de l'enumeració 2/3 no queden establits per estos bytes; no cal atribuir-los
una semàntica de plataforma per resoldre les branques.

En `0x2e5f0`, el retorn anticipat zero de `0x2e658` exigix:

```c
((query_9dbc() & 0xff) == 0) || (query_9db4() == 3)
// (1 == 0) || (2 == 3) == false
```

- `0x2e638..0x2e640`: el byte 1 no pren `cbz`.
- `0x2e648..0x2e650`: 2 és diferent de 3; pren `b.ne 0x2e664`.
- `0x2e664..0x2e684`: intenta localitzar VerifiedBoot amb GUID a
  `0xb1790`. Si falla, retorna l'error per `0x2e6f0..0x2e6f8`.
- Si la localització té èxit, `0x2e700..0x2e708` invoca el callback
  `+0x30`; el seu resultat es conserva a `0x2e70c` i es propaga.

Per tant, en el binari analitzat sense modificar, estos dos controls
**no proporcionen un camí de retorn zero que ometa el callback**.
Arribar al callback continua requerint una localització reeixida i el
retorn normal pressuposa les comprovacions de canari habituals.
Un fals èxit anterior de persistència tampoc altera estes constants.
Açò resol el pendent de les condicions, però no el contracte QSEE ni
l'efecte intern de la comanda keymaster `0x10e`.

Validació: hash i 16 bytes contrastats directament amb el PE; branques
contrastades amb ASM i pseudocodi. Cap execució de firmware ni accés al mòbil.

## Contracte QSEE observat pel caller — 2026-11-09

El contracte té dos canals independents: retorn del servei en **x0**
(64 bits) i resposta específica de keymaster en un **word de 32 bits**
escrit al búfer del caller. Èxit del transport no equival a èxit de
l'aplicació. Esta conclusió descriu el consumidor VerifiedBoot; no prova
la implementació interna del proveïdor QSEE.

Per a 0x10e, `0x1d28..0x1d44` reconstruïx els arguments següents:

| Registre | Valor |
| --- | --- |
| x0 | Punter al protocol QSEE |
| w1 | Identificador de keymaster |
| x2 | Punter a la comanda 0x10e, a sp+0x28 |
| w3 | Mida de petició: 4 |
| x4 | Punter al word de resposta, a sp |
| w5 | Mida de resposta: 4 |

La destinació és el callback +0x18. No hi ha un argument de longitud
retornada: el caller no comprova quants bytes s'han escrit.

| Retorn del servei x0 | Resposta w3 | Retorn VerifiedBoot |
| --- | --- | --- |
| 0 | 0 | 0 |
| 0 | No zero | 0x50 |
| No zero | Qualsevol contingut | 0x50 |

`0x1d48` carrega la resposta **abans** de comprovar x0 a `0x1d50`.
Si el transport falla sense escriure el búfer, el word mostrat al log
pot ser contingut preexistent de pila; no es pot interpretar com un error
real retornat per keymaster. Això no canvia el resultat: x0 no zero força
0x50 independentment del word. Si x0 és zero, `0x1d54` exigix resposta zero.
El caller no inicialitza eixe word: el zero escrit a `0x1c78` és a
sp+0x2c, on es recupera l'identificador, no a sp.

Els errors de localització i d'inici de l'aplicació es propaguen tal qual
via x19; només els errors de l'enviament/resposta es col·lapsen a 0x50.
Este 0x50 és literal, sense el bit alt d'error EFI: no s'ha d'atribuir
un nom EFI estàndard ni assumir que un consumidor que use només EFI_ERROR
el detectaria. El caller ABL analitzat comprova retorn no zero.

Precisió sobre la descripció anterior: el servei +0x48 de `0x1cd8`
s'obté del global 0xd3c0, mentre QSEE s'obté de 0xd278. No és una crida
al slot +0x48 de QSEE; s'ha de mantindre separat del contracte SendCmd.

Com a contrast públic, la [capçalera QSEECom de Linux](https://github.com/torvalds/linux/blob/master/include/linux/firmware/qcom/qcom_qseecom.h)
documenta retorn zero/no zero i un búfer escrit per l'aplicació.
El [client uefisecapp](https://github.com/torvalds/linux/blob/master/drivers/firmware/qcom/qcom_qseecom_uefisecapp.c)
comprova primer el retorn de l'enviament i després l'estat dins de la
resposta. Són fonts primàries d'una altra implementació: corroboren la
separació conceptual, però no establixen els codis EFI del nostre proveïdor
ni garantixen que keymaster 0x10e escriga sempre quatre bytes.

Validació local: SHA-256 del PE torna a coincidir amb el manifest;
GUID a 0xd0f8 = a74862ce-680f-4fe1-a311-df41f4030391; bytes de
0x1d28..0x1d74 contrastats amb l'exportació ASM. Sense executar firmware.
Queda pendent verificar el proveïdor QSEE concret: errors que retorna,
condicions de còpia de resposta i garantia d'escriptura completa en èxit;
també la semàntica interna de keymaster 0x10e. No hi ha evidència ací
d'un transport que retorne èxit sense produir resposta.

## Precondicions de 0x17bc / 0x185c: revisió de l'assignador

**Correcció de l'abast anterior:** el fals èxit és demostrat si l'assignador
retorna nul; no està demostrat que una fallada ordinària de reserva arribe
al caller. La implementació real passa per una aturada ASSERT. El model
injecta el retorn nul i no modela esta precondició.

### Condicions comunes per arribar a les crides

1. Entrada a 0x15ac: x2 (búfer) no nul i w3 (mida de 32 bits) no zero
   (`0x15e4..0x15ec`). No hi ha límit superior de mida abans de reservar;
   el primer argument x0 no es valida ni s'utilitza com a protocol ací.
2. `0x390c(&flag)` retorna zero i escriu flag=1. Exactament, el resultat
   de 32 bits S de `0x37e4` ha de satisfer S != 0xffffffff i
   `(S & 0x8703) == 0` (`0x3920..0x3968`). `0x37e4` consulta SCM
   0x02000604: callback amb retorn zero i primer word de resposta igual
   a 1; S és el word baix de resposta[1]. La localització prèvia comprova
   el bit 63 d'error (`0x3828`), no qualsevol retorn no zero. Es pressuposen
   punters de protocol vàlids i retorn normal dels serveis.
3. Conversió del literal `devinfo` a UTF-16 via 0x281c reeixida
   (`0x1698..0x169c`). No és una consulta de partició: amb els dos búfers
   locals vàlids i longitud 7, el helper copia i termina amb zero.
4. LocateProtocol QSEE retorna exactament zero (`0x16c8..0x16cc`).
5. Identificador global 0xd268 ja no zero, o bé el servei +0x48 del
   global 0xd3c0 retorna zero, o bé, després que este falle, QSEE +8
   StartApp retorna zero. El caller no comprova que l'identificador
   recuperat/iniciat siga no zero abans de continuar.
6. w1 original, conservat en w19, és **1 per a escriptura**
   (`0x176c..0x177c`) o **0 per a lectura** (`0x1828..0x182c`).
   Altres operacions i flag=0 no arriben a estes reserves.

L'escriptura crida 0x5620 a **0x17b4** i comprova el retorn a **0x17bc**;
la lectura crida a **0x1854** i comprova a **0x185c**. Totes dues passen
literalment x0=1. El thunk 0x5620 transforma això en
`0x5364(type=4, pages=1, alignment=0x1000)`: una pàgina de 4096 bytes,
independent de la mida del búfer del caller. La signatura decompilada que
mostra `IMAGE_DOS_HEADER... + 1` no reflectix l'argument de les instruccions.

### Quan pot tornar nul el helper real?

Amb estos arguments, la branca pages=0 de 0x537c i l'assert per alineació
invàlida de 0x5438 són inaccessibles. Primer busca en la llista 0xd1d8
un bloc lliure, de tipus 4, base alineada a 4096 i almenys una pàgina.
Reutilitza un bloc exacte o un de major, sense invocar AllocatePages.
Per arribar als errors de reserva nous no ha d'existir cap bloc elegible.

| Condició en la via de reserva nova | Camí |
| --- | --- |
| AllocatePages(1,4,1,&addr) amb bit 63 d'error, i reintent AllocatePages(0,4,1,&addr) també amb error | 0x5490 → 0x54ac → 0x5598 |
| Reserva acceptada, servei del global 0xd3c8 +0x38 amb bit 63 d'error | 0x54cc → 0x557c; intenta alliberar la pàgina |
| Reserva acceptada i +0x38 acceptat, però +0x40(addr,4096,2) amb bit 63 d'error | 0x54f8 → 0x557c; intenta alliberar la pàgina |

L'adreça màxima inicial és 0xffffffff (`0x5380..0x538c`). Els serveis
ací comproven **bit 63**, no retorn diferent de zero. Les tres vies
convergixen en log i `0x55c4: bl 0x5200`, abans del `mov x0,xzr` de 0x55c8.
`0x5200` crida incondicionalment 0x8098: després d'altres helpers,
`0x80bc` posa zero a sp+8 i `0x80c0..0x80c4` espera que deixe de ser zero,
sense cap escriptura local que ho faça. Si excepcionalment continuara,
0x5200 cridaria també 0x8724, amb un altre bucle equivalent a 0x8738..0x8740.
Per tant, **sense intervenció externa sobre l'estat, estos errors no
retornen nul al caller en el flux normal analitzat**.

La reserva del descriptor de 0x30 bytes a 0x5534 té una altra via:
si retorna nul, ASSERT a 0x55f8 i bucle incondicional a 0x55fc; tampoc
produïx el retorn nul. L'error de 0x5898 només es registra i continua.
Una base física zero retornada com a reserva reeixida o present en la
llista també seria interpretada com nul pel caller; és un cas límit
condicional, no una fallada EFI ni una situació observada.

### Conseqüència i validació

Si efectivament rep x0=0, cada caller posa x19=0, salta a 0x1934/0x1940,
registra l'error i posa x22=0 a 0x1950. Omet alliberament, còpies i
comandes 0x202/0x203, i retorna zero si el canari es conserva. Tampoc
intenta el fallback devinfo: este és posterior a l'enviament QSEE.

La hipòtesi «esgotament de memòria → fals èxit» requerix ara demostrar
com se supera l'aturada de l'assignador; no queda establida per la branca
nul·la del caller. SHA-256 del PE verificat contra el manifest; arguments,
branques i bucles contrastats amb ASM i bytes del PE. Sense dispositiu
ni execució del firmware.
