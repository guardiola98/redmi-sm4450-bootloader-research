# FeatureEnabler: família del xip i activació QSEE

2026-11-10, continuació de `a0f2df0` i `0439f35`. **Android exposa
chip_family=141 (0x8d)**. Esta família no està en les quatre acceptades
pel caller FeatureEnabler. El productor XBL conté una fila compatible,
però no s’ha observat l’execució de ChipInfo/FeatureEnabler dins d’UEFI.

## Cadena estàtica del camp, independent de soc_id

| Pas | Evidència local |
| --- | --- |
| FeatureEnabler | +0x30 de ChipInfo a149c; taula4350 accepta només116/127/123/130. Sense coincidència no arriba a154c→2450 ni als intents QSEE. |
| Protocol ChipInfo | Taulaa0e0, +0x30=a110→162c; wrapper164c invoca DAL+0x70. Error/handle nul no es convertixen en família vàlida. |
| DAL ChipInfo | Taula7d78, +0x70=7de8→33e4;33f4 crida51f8,3400 escriu el word d’eixida; retorna zero. |
| Global UEFI | 51f8 lliga41c. Inicialitzador5348 copia **SMEM0x89+0x6c** a eixe camp, a53a4/53b8. Getter548c demana item0x89 i comprova punter/mida no nuls. |
| Productor XBL | 14825a3c/48 reserva item0x89; escriu format0x10;14825aec/af4/af8 passa out+0x6c a DAL+0x70. |
| DAL XBL | Registre ID0x0200006f, factory148acccc, taula148bbc10, +0x70=148acea8; crida14825380, que llig14915514. |
| Inicialitzador XBL | 148321f8 calcula família amb camps de hardware i taula148b3360 de8 files; escriu14915514 a14832318. La selecció de soc_id és una cerca separada, després. |

La fila de família `148b33d0` té camps **(11,16,141,568)**: claus de
família hardware, família pública i ID de fallback. La taula de xips
`148b32b8` associa **SM_CLARENCE**, soc_id568 i part-id538. Les dimensions
són20 files de xips i8 de família, fixades per148c70d8. Només s’han seguit
estos camps de metadades; cap lectura de fusibles, MMIO, claus o identitat
única del dispositiu. Les adreces són VAs preferides del firmware local.

**Límit important:** una coincidència amb el part-id pot seleccionar soc_id
independentment del resultat de família. Per tant soc_id568, per si sol,
**no prova família141**. La consulta Android específica següent és la nova
observació que faltava. La taula local tampoc és una atestació de la imatge
que ha executat el telèfon.

## Consulta real de només lectura

Pregunta formulada abans de la prova: Android exposa directament el camp
numèric de família que permet contrastar la porta FeatureEnabler?

```sh
adb shell 'if [ -r /sys/devices/soc0/chip_family ]; then cat /sys/devices/soc0/chip_family; else echo CHIP_FAMILY_UNAVAILABLE; fi'
```

Resultat: **0x8d = 141**. Captura original exclusivament en
`work/platform-diagnostics-2026-11-10/chip-family.txt`, ignorat i privat.
La primera validació acceptava només decimal i va classificar l’eixida
com a no numèrica; després s’ha comprovat que era un hexadecimal acotat
i s’ha convertit offline. No es va repetir la consulta al dispositiu.
No és un número de sèrie ni identificador personal.

Este atribut és diferent del `family=Snapdragon` genèric i del soc_id568
ja llegits. La implementació exacta del driver vendor Android no s’ha
extret ni auditada: l’atribut observat és compatible amb la cadena local,
però no substituïx una traça UEFI ni demostra que no hi haja altres writers.
S’ha intentat contrastar codi públic primari Linux/AOSP sense obtindre
contingut accessible; no s’usa eixe intent com a evidència.

## Hipòtesis i decisió

- **Confirmat estàticament:** FeatureEnabler té caller QSEE+0x20; el wrapper
  selecciona partició, no fitxer. La porta de família exclou141.
- **Observat en Android:** chip_family141, soc_id568, build coincident i
  green/locked. No s’ha capturat execució UEFI ni una càrrega featenabler.
- **Condicionat:** si ChipInfo UEFI consumix el mateix camp intacte141,
  la branca QSEE de FeatureEnabler no s’executa. No presentar este caller
  com a activació efectiva al Redmi ni com a via de reentrada f250.
- **Descartat:** usar soc_id568 com si fora l’enumeració ChipFamily;
  atribuir a la coincidència de noms Android una prova de crida UEFI.
- **Falta:** observació UEFI directa o un altre caller/subscriptor concret.
  No justifica reiniciar o canviar el mode del telèfon per esta fase.

No hi ha evidència nova rellevant per desbloquejar. La dada nova **reduïx
la prioritat d’este consumidor com a activador**; no prova absència de
QSEE en altres mòduls ni reclassifica el missatge Android de neteja nul·la.

## Reproducció i pròxima prova amb valor

`inspect-reviewed-pe-evidence.py` inclou ara ChipInfo:14 PE amb hashes,
17 instruccions noves i els dos slots. `inspect-xbl-ram-producer.py`
afig28 instruccions de ChipInfo, la fila de xip seleccionada, les8 files
de família i3 punters; conserva les72 instruccions RAM/mode anteriors.
Tot prové dels binaris locals fixats per hash, no d’una memòria capturada.

El test nou de `test-tzdxe-resource-model.py` comprova que141 exclou la
ruta per a tots els resultats dels intents i que les quatre famílies
acceptades encara l’admeten.19 tests de recursos i5 de layout ELF passen;
regressió de128 tests anterior més este cas nou: **129 tests en19 scripts**.

La pròxima investigació útil és trobar un caller de f250 amb arguments
reals o un subscriptor amb TPL conegut. És treball estàtic, sense risc
per al mòbil. Repetir chip_family no aporta dades noves; una nova captura
QSEE només tindria valor amb un esdeveniment natural o error previ nou,
sempre filtrada i de només lectura. No cal fastboot per estes conclusions.
