# MiToken 0x1784: longitud i capacitat en ASM

Revisió estàtica 2026-11-09. MiTokenDxe SHA-256
`5960ae5e4b2ae712f8ef1e854cb37e3fcaf0ecb1427aa40eeebd733829be68b9`
verificat contra el PE i el manifest. RVA base zero, exportació
`work/MiTokenDxe.asm`. La taula de 0x9648 conté versió 1 i callbacks
0x1784, 0x1a58, 0x1ac0: el callback estudiat és +8.

## Interfície exterior

x1 és el destí D; x2 és el punter L a un word de longitud de 32 bits.
`0x17a0` conserva L en x19. **No hi ha cap lectura de *L ni comprovació
de L nul** en tot el callback. Per tant, *L no funciona com a capacitat
d'entrada, encara que el caller l'haja inicialitzat.

| Camí | Condició i ASM | Escriptura i longitud informada |
| --- | --- | --- |
| Consulta | D=0, 0x17b0 → 0x17d4 | *L=128, retorn 0, sense generar token |
| Cache | D!=0 i byte[0x9910]!=0, 0x17bc..0x17d0 | Copia cadena incloent NUL; després *L=128 i retorn 0 |
| Primera generació reeixida | Cache buida; serveis i encoder reeixits | 0x1a40 copia cadena incloent NUL; 0x1a48 calcula strlen; 0x1a50 escriu longitud real sense NUL |
| Error de servei | RNG/ChipInfo/localització fallen | Propaga estat; no actualitza *L |
| Error d'encoder | w0!=0 a 0x1a14 | Log i retorn 0 a 0x1a28, sense copiar D ni actualitzar *L |

Un L nul no produïx un error controlat: les vies que escriuen *L el
desreferencien. No hi ha cap comparació entre la mida de la cadena i la
capacitat real de D. La consulta/cache i la primera generació tampoc
retornen la mateixa magnitud: 128 és una mida anunciada, no strlen.

## Helper de còpia 0x2508

`0x2518` rebutja destí nul amb ASSERT i bucle. Calcula strlen(S) via
0x25d8 i compara, **sense signe**, `(D-S)` i `(S-D)` amb strlen(S)
a 0x2530/0x2544. `b.ls` deriva a ASSERT/bucle. Estes són comprovacions
de solapament de cadenes, no de capacitat: no rep cap argument de mida.
`0x2560..0x2568` copia bytes fins al NUL i `0x256c` escriu el terminador.
El requisit de memòria del destí és strlen(S)+1 bytes escrivibles.

0x25d8 comprova punter no nul i aplica un límit global de longitud a
0x61e4 (`0x25f8..0x2604`); el valor del PE és 1.000.000. En superar-lo
atura amb ASSERT. Este límit no descriu la capacitat del destí.

## Capacitat interna de l'encoder 0x1d20

El caller passa origen 0x99b0, longitud N, destí 0x9910 i un punter a
capacitat **de 64 bits** inicialitzada a 128 (`0x19e4..0x1a10`). No és L.

- `0x1d24..0x1d2c`: origen, destí i punter de capacitat no nuls;
  si algun és nul, retorna 1 sense escriure capacitat.
- `0x1d34..0x1d50`: calcula R = 4*ceil(N/3)+1 i compara capacitat >= R
  sense signe. La multiplicació alta per 0xaaaaaaaaaaaaaaab i el shift
  implementen divisió per 3. Fórmula vàlida per les longituds acotades ací;
  no s'afirma absència d'overflow per a arguments arbitraris de 64 bits.
- Si capacitat < R: retorna 2 i escriu R a *capacitat a 0x1e78;
  no escriu la cadena de destí.
- Si hi cap: genera Base64 sense padding; els fragments finals tenen
  2 o 3 caràcters (`0x1e08..0x1e68`). `0x1e74` escriu NUL i
  `0x1e78` informa caràcters efectius, excloent NUL; retorna 0.

El control és conservador: reserva espai com si hi haguera padding,
encara que l'eixida no n'inclou. Protegix la cache interna, no D.

## Cota de longitud en este build

La capçalera 0x02010155 posa el comptador de payload inicial a 2.
El camp RNG ocupa 2+16 bytes; el camp placa 2+B; el camp ChipInfo 2+8.
El payload final és 30+B i N=34+B (`0x19f8..0x1a08`). Les longituds
intermèdies es desen com bytes i alguns offsets usen UXTB, sense un
control explícit d'overflow; amb la cota següent no hi ha truncament.

El nom de placa es copia amb recompte 15 a 0x90e8, tant per al default
com a 0x1774..0x1780. El helper 0x2660 copia fins a NUL o recompte i
ompli la resta amb zeros (`0x2728..0x2758`); no afegix NUL si exhaurix
els 15 bytes. El byte següent, 0x90f7, és zero al PE. Estes còpies no el
modifiquen. Amb eixe estat preservat, B<=15, incloent noms de 15 bytes.
Els helpers tenen comprovacions de punter/solapament i límit global;
no reben la capacitat del búfer destí. El recompte 16 del camp RNG és
fix encara que la còpia de cadena trobe un zero abans.

En conseqüència N<=49, R<=69 i l'eixida real té com a màxim 66 caràcters
més NUL: **67 bytes**. Les capacitats internes 128 superen esta cota.
No es demostra accessible l'error 2 de Base64 amb estos camps i memòria
preservada; tampoc l'error 1, perquè els tres punters són globals/locals
no nuls. Un error o corrupció anterior que impedisca arribar normalment
no és una prova d'esta via de fals èxit.

## Caller ABL i correcció de la nota anterior

ABL `0x55be8..0x55bf0` consulta amb D=0. A `0x55c78` carrega la
longitud i crida 0x58dc: 0x58f0 passa eixa mateixa mida en x1, tipus 4
en w0, i 0x5b9c → 0x5888 invoca AllocatePool +0x40. **No s'hi veu
cap increment +1**: la reserva nova és de 128 bytes, no 129 com deia
la nota anterior. Després `0x55c88..0x55c90` passa destí i L al callback.
128 ja cobrix el màxim normal de 67 bytes incloent NUL. Si ja existix
el punter global, omet la reserva; la capacitat d'eixe objecte preexistent
no queda provada només per este fragment. Tampoc es comprova nul després
de reservar: un destí nul tornaria a prendre la via de consulta.

Conclusió: falta validació de capacitat en l'API exterior, però el caller
amb reserva nova de 128 bytes és suficient per a la generació acotada.
No s'ha demostrat un desbordament accessible des del dispositiu bloquejat.
Validació: ASM dels helpers i caller, hash i dades globals del PE;
aritmètica contrastada per B=0,7,15 (N=34,41,49; R=49,57,69;
longitud efectiva=46,55,66). Sense executar firmware ni llegir identificadors.
