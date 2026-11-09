# MiTokenDxe i VerifiedBootDxe — extracció i primera anàlisi

Sessió 2026-11-09. Cap firmware executat, cap dispositiu connectat.
Manifest: [protocol-pe-manifest.json](protocol-pe-manifest.json).

## Reproducció

```bash
python3 scripts/extract-protocol-pe.py ~/Baixades/sky_eea_global_images_OS2.0.218.0.VMWEUXM_*.tgz
python3 scripts/test-extract-protocol-pe.py
python3 scripts/inspect-linuxloader.py work/protocols/MiTokenDxe.pe
python3 scripts/inspect-linuxloader.py work/protocols/VerifiedBootDxe.pe
```

L'extractor comprova el hash conegut d'uefi.elf, reutilitza el lector GZIP/FFS
existent i exigix GUID, nom UI i PE únics. Limitació: el lector exterior heretat
encara usa FV a 0x1000, admissible per a esta entrada fixada per hash; no és un
parser general ni valida tots els checksums PI. Tres tests negatius passen;
l'extracció real dels dos mòduls també passa.

Els dos PE són ARM64 PE32+, subsistema 11, base zero i entrada RVA 0x1000.
MiToken: .text 0x1000–0x9000, .data 0x9000, .reloc 0xa000.
VerifiedBoot: .text 0x1000–0xd000, .data 0xd000, .reloc 0xe000.
En estes seccions RVA i offset de fitxer coincidixen; no confondre'ls amb
els offsets del contenidor documentats al manifest.

## MiToken: evidència inicial de Ghidra

Anàlisi headless finalitzada; pseudocodi local en `work/MiTokenDxe.c`.
Els tipus reconstruïts automàticament requerixen comprovació en desassemblatge.

- La rutina RVA 0x1ac8 passa GUID a 0x90a8 i taula a 0x9648 al callback
  Boot Services +0x148, compatible amb InstallMultipleProtocolInterfaces.
- Valors de 64 bits a 0x9648: `1, 0x1784, 0x1a58, 0x1ac0`.
  Això relaciona el callback ABL +0x08 amb 0x1784 i +0x10 amb 0x1a58.
  El primer camp és compatible amb una revisió; pendent tipatge formal.
- 0x1a58 calcula longitud de cadena via 0x25d8 i crida 0x1b0c;
  0x1b0c crida 0x1e84 amb clau a 0x9668 i transforma qualsevol error en 0x50.
- 0x1e84 exigix firma de 256 bytes i missatge de longitud 1..245;
  valida punters i fa aritmètica modular. La clau té 64 limbs de 32 bits
  i exponent 65537 a 0x9870. Inferència forta: RSA-2048.
- El pseudocodi comprova bloc `00 01 FF…00` seguit del missatge literal.
  Compatible amb padding tipus PKCS#1 v1.5 sobre missatge cru; encara cal
  corroborar instruccions i construir vectors sintètics. No atribuir SHA-256
  ni una altra funció hash a esta ruta sense proves.
- 0x1d20 implementa alfabet Base64 URL-safe, sense padding `=`.
- 0x1b4c consulta SCM +0x38 amb identificador 0x2001401 i paràmetre 0x22,
  llig política de depuració i compara identificadors. Això no demostra que
  SCM faça la verificació RSA ni que eixa ruta autoritze el desbloqueig.

## Auditoria i límits

No hi ha vulnerabilitat demostrada ni desbloqueig reproduïble.
La crida de longitud a 0x1a58 mereix revisar terminació del búfer al caller;
no és encara una vulnerabilitat candidata demostrada: accessibilitat i límits
reals pendents. La clau fixa i la presència de callbacks privilegiats no són bugs.
No s'han usat tokens reals ni identificadors de dispositiu.

## Fonts i pròxim experiment

Consultades les pàgines de [OpenABL](https://github.com/OpenHandheldCollective/OpenABL),
[Xiaomi-bootloader](https://github.com/lrh2000/Xiaomi-bootloader) i
[xbltools](https://github.com/linux-msm/xbltools). La comparació de codi i versions
queda pendent; no s'ha extrapolat cap exploit històric.

Pròxim: definir explícitament 0x1784 en Ghidra (no apareix com a funció independent
en l'exportació automàtica), verificar els branches de 0x1e84 en desassemblatge,
i reconstruir VerifiedBootDxe des del registre del protocol. Després seguir
el callback invocat per LinuxLoader 0x43d88 fins a la persistència segura.
Queden pendents: generació del token, cadena completa d'autorització, estat
normal/crític, RPMB/TEE, vectors offline i comparació pública detallada.

## Continuació: desassemblatge verificat

Els offsets següents són RVA del PE indicat, amb base zero. Scripts Ghidra
reproduïbles en `scripts/ghidra/`; l'exportació completa queda en `work/`.
No cal crear una funció a 0x1784 per llegir les instruccions: l'exportador
anterior només exportava funcions reconegudes, però el codi ja estava desassemblat.

### Generació MiToken (0x1784)

- x1 = destí, x2 = punter de longitud de 32 bits. Amb destí nul, escriu
  0x80 i retorna zero (0x17b0, 0x17d4–0x17dc).
- Cache a 0x9910; si el primer byte és no nul, copia cadena via 0x2508
  i torna a informar 0x80. No llig la capacitat proporcionada pel caller.
- Sense cache, construeix registre a 0x99b0: capçalera inicial 0x02010155,
  camp tipus 1/longitud 16; RNG callback +8 demana 16 bytes (0x1868–0x1874).
- Afig camp tipus 3 amb nom de placa obtingut per 0x1718 i camp tipus 2
  amb 8 bytes construïts des de ChipInfo +0x68 i +0x48. No hem llegit cap
  identificador real; són crides identificades estàticament.
- Base64 URL-safe a 0x1a10, cache de capacitat 128. Primera generació retorna
  longitud real (0x1a44–0x1a50), mentre consulta/cache retornen 128.
- Candidat de robustesa: si Base64 retorna error, 0x1a14–0x1a2c registra error
  però retorna zero sense copiar destí ni escriure longitud. Cal demostrar
  que es pot arribar a eixa fallada amb els camps de placa fixos d'este build.
- Candidat d'API: no hi ha comprovació de capacitat del caller ni de x2 nul.
  ABL consulta primer 128 i reserva eixa mida: este
  caller no demostra overflow. Accés arbitrari al protocol tampoc està demostrat.

### Verificació MiToken

Confirmat en instruccions: 0x1eb0–0x1ed4 exigix punters, firma 256 i longitud
1..245. 0x20a8–0x2100 comprova `00 01`, tots els FF i separador zero;
la comparació posterior és amb el missatge cru. Per tant hi ha almenys huit
FF per la cota 245. No s'ha identificat hashing en esta ruta.

`test-token-padding-model.py` comprova límits i rebutja les 256 mutacions d'un
byte d'un bloc sintètic. **És un model del contracte, no una execució del
firmware ni una validació de l'aritmètica RSA.** No genera tokens vàlids ni
usa signatures o identificadors reals.

### VerifiedBoot: persistència i política

Taula a 0xd180, revisió 0x10003; callback +8 = 0x15ac. Això completa la
relació `LinuxLoader 0x43d88 → 0x440b0/0x44188 → 0x2d728 → VerifiedBoot+8`.
Operació 0 llig; operació 1 escriu. ABL passa 0x998 bytes amb camps normal/crític
a +0xd/+0xe. El callback tracta el búfer de configuració, no interpreta
individualment eixos bits ni verifica MiToken de nou.

0x390c obté estat SCM via 0x37e4 (SCM +0x38, ID 0x2000604), i usa màscara
0x8703. Si activa la via protegida, localitza QSEE, recupera/inicia `keymaster`,
reserva una pàgina i envia comanda 0x202 (lectura) i, en escriptura, 0x203.
Les peticions són de 12 bytes amb adreça de búfer i longitud 0x1000.
El codi comprova tant status del transport com resposta de l'aplicació.

Si falla la lectura segura, 0x38a0 torna a consultar SCM i aplica màscara
0x8723: només el resultat classificat com a no segur permet fallback a
`devinfo`. La via sense RPMB també accedix a `devinfo`. Estes màscares són
fets del binari; no atribuïm noms de fusibles als bits sense font addicional.
No s'ha demostrat que un mòbil bloquejat puga seleccionar la via no segura.
La integritat interna de RPMB/keymaster queda fora d'este PE i pendent d'anàlisi.

### Candidat confirmat a nivell de codi: fals èxit per falta de memòria

VerifiedBoot 0x15ac, branches 0x17bc (escriptura) i 0x185c (lectura):
reserva nul·la → 0x1934/0x1940 → log a 0x1948 → `mov x22,xzr` a 0x1950.
0x1a4c evita alliberar nul, 0x1a5c accepta x22=0, imprimeix èxit RPMB i
0x1640 retorna x22. No s'ha llegit/escrit configuració en este camí.

Condició: fallada de reserva d'una pàgina després de superar la selecció
segura i inicialització QSEE. **Defecte de propagació d'error demostrat
estàticament; vulnerabilitat explotable no demostrada.** En escriptura podria
confirmar al caller un canvi només en RAM; persistència no aconseguida.
No s'ha demostrat control de la reserva des de Fastboot bloquejat, ni que
l'autorització MiToken es puga evitar. Validació segura següent: modelar el
CFG amb allocator nul i comprovar l'estat del caller, sense executar firmware.

## Efectes en ABL verificats

Vegeu [anàlisi del fals èxit](verifiedboot-failure-analysis.md): setters
modifiquen RAM abans de persistir; la lectura inicial neteja el flag de
lectura i pot inicialitzar defaults segons una consulta segura separada.
La ruta Fastboot examinada conserva la verificació MiToken prèvia.
Set proves sintètiques passen; accessibilitat de la fallada i impacte
explotable continuen sense demostrar-se.

Reconstrucció detallada de longituds, capacitats i helpers del callback
0x1784 en [MiToken: longitud i capacitat](mitoken-length-capacity.md).
La cota normal és 67 bytes incloent NUL; la reserva nova ABL és 128,
sense increment +1. La fallada de capacitat Base64 no es demostra accessible
amb els camps acotats i la memòria preservada.
