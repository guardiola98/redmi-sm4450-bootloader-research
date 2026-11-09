# Cobertura ampliada des de main ce7e4f0

**Actualització:** el [lookup TZ](tz-dispatch-analysis.md) i el
[monitor EL3](tz-monitor-analysis.md) ja tenen reconstrucció funcional
parcial. Les notes anteriors de dispatcher pendent són històriques.

Treball exclusivament offline. Els scripts no executen firmware. Les imatges
extretes es desen només en work/, exclòs de Git, sense alterar els originals.

## Reproducció

```
python3 scripts/extract-audit-images.py /ruta/al/paquet.tgz
python3 scripts/inventory-additional-fvs.py
python3 scripts/test-additional-fv-codec.py
```

L'extractor comprova hash i mida quan consta al manifest, rebutja duplicats,
entrades no regulars, absències i fitxers >64 MiB. No extrau rutes del tar.
Usa bootchain-local.json i hashes de inspect-compressed-uefi.py.
El lector recursiu reutilitza els parsers existents: límit de profunditat 12,
eixida per descompressió 128 MiB, pressupost acumulat 256 MiB per imatge,
memòria LZMA 128 MiB. No valida tots els checksums PI; els lectors heretats
poden parar en dades malformades. El camp gaps registra errors explícits,
no certifica cobertura semàntica completa quan és buit.

## Resultats nous

Manifest [additional-fv-census.json](additional-fv-census.json): hash origen,
camí FFS/secció, hash de cada descompressió i mòdul, mida i offsets GUID.

| Imatge | Resultat |
| --- | --- |
| imagefv.elf | LZMA descomprimix 64.716.808 bytes. 17 seccions UI i 17 RAW, cap PE/TE. Noms de recursos gràfics BMP; contingut RAW no auditat semànticament. |
| tools.fv | 17 PE, cap TE, 24 UI i 8 RAW. Cap PE amb GUID MiToken literal little-endian. RAW fora de la cerca de consumidors executable. |
| tz.mbn | Extracció hash-pinned, 3.719.360 bytes; ELF64 AArch64, 35 program headers, sense seccions, entry 0x14680000. |

El fracàs anterior d'imagefv era el límit de 32 MiB de l'eina, no corrupció.
L'ampliació acotada permet documentar el volum. No prova que les dades RAW
siguen segures ni exclou altres formats executables que no siguen PE/TE.
17 PE addicionals + 93 anteriors = **110 ocurrències PE inventariades**
en estos tres contenidors, no 110 programes únics ni 110 auditories funcionals.
LinuxLoader d'ABL continua separat. La semàntica de noms de tools no prova
registre, accessibilitat ni efecte de cap utilitat; cap s'ha executat.

## TrustZone: frontera d'evidència

Hash TZ: f7d943b1de872d239468fe30cc4fab92c5acb0405203e9f9e38436cefd7e1a76.
`readelf -h -l work/audit-images/tz.mbn` identifica contenidor i segments.
Cerca exacta dels bytes little-endian de 0x02001401 i 0x42001401: cap
coincidència. **No descarta el servei:** ID compost en instruccions, taules
amb owner/service separats o un altre component són possibilitats pendents.
No s'ha identificat el dispatcher ni una rutina productora de política.
Ja no és correcte dir que falta el binari local: ara falta la reconstrucció
funcional. Fonts públiques pertinents no estan copiades localment i no s'ha
fet xarxa. Cap conclusió nova sobre el màxim del comptador o inicialització.

## Estat dels candidats

| Candidat | Estat actual i límit |
| --- | --- |
| MiToken neteja omesa | Confirmat al CFG, condicionat a reserva reeixida i error posterior; consumidor +0x18 i repetibilitat no demostrats. |
| MiToken recompte >=256 / >=250 | Cicle / lectura més enllà del rang declarat condicionals; contracte TZ desconegut. Models no demostren entrada real. |
| Word ChipInfo indeterminat | Descartat en ruta normal del getter concret; fallada de localització ignorada continua condicional. |
| VerifiedBoot fals èxit | Branca local confirmada si rep nul, però errors ordinaris de l'allocator passen per aturada. No equival a vulnerabilitat per esgotament demostrada. |
| MiToken capacitat i NUL ABL | Callers normals acotats i amb reserva reeixida descarten els desbordaments estudiats; no generalitzar a callers arbitraris. |

Les instruccions, precondicions i models estan als informes especialitzats.
S'han afegit notes de vigència als informes històrics sense esborrar les
hipòtesis anteriors. No s'ha identificat cap nou consumidor +0x18.

## Validació i prioritats

25 tests passen executant els sis scripts test-*.py individualment. Inclouen
3 proves noves LZMA: mida exacta, excés i truncament. `unittest discover`
no descobrix estos noms amb guions; no confondre zero tests amb validació.
No s'ha executat firmware ni cap utilitat del volum tools.

Pròxims passos: dispatcher TZ i servei de política; cobertura RAW/altres
volums amb tipus conegut; consumers +0x18 i errors reals abans d'atribuir
impacte. Esta sessió acaba després de conservar la fase per límit de recursos;
queden tasques offline útils, no es declara l'auditoria completa.

## Continuació: seccions RAW després de 1b03a74

Inventari ampliat sense tornar a cercar nous executables: 17 RAW d'imagefv
comencen amb bytes `42 4d` (signatura BMP); dels 8 RAW de tools, 7 comencen
amb `23 0a 23 20` (prefix textual de comentaris) i un és buit. Classificació
per prefix, no validació completa del format ni execució dels textos.
Cap dels 25 RAW conté el GUID MiToken literal little-endian. El manifest
ara conserva mida, hash, ruta, prefix i resultat de cerca de cada RAW.
Açò resol l'exclusió anterior d'estes seccions en la cerca literal; no
resol altres codificacions de GUID ni àlies de protocols. Cap nou consumidor.

## Cobertura funcional EL3 afegida

Identificades 16 entrades de vector, quatre stubs de context, dos handlers
i el dispatcher síncron 0x1c00f9ec. Taules de 69 comandaments segurs,
7 subtipus i 4 selectors de context extretes amb hash/límits; no són
80 serveis auditats. Reconstruïda la ruta específica d'entrada i retorn
del rebuig SCM ARMv8. L'ASM inicial ometia entrades indirectes que ara
s'han desassemblat; exportar Ghidra no certifica cobertura completa.
No s'han repetit extraccions, RSA ni escàners GUID. El cens continua
en 110 ocurrències PE més ABL separat; no hi ha nou consumidor +0x18.
Altres handlers, càrrega dinàmica i productors de política continuen
fora de la cobertura semàntica. No s'ha executat codi del firmware.

## Revisió posterior a f6672cc: TE i components

El nou cens de metadades afegix un **TE exterior** als 110 PE coneguts;
ABL continua separat. [uefi-te-structure.json](uefi-te-structure.json)
fixa origen/hash i tres seccions ARM64, delta de capçalera eliminada
0xf38; entrada RVA 0xd0b8, VA preferida 0xa700e0b8, offset TE 0xc180.
No usar RVA=offset en TE. Cap GUID MiToken literal en este component nou;
no exclou referències indirectes. L'import automàtic Ghidra ha fallat amb
«No load spec found»; no s'ha forçat una interpretació funcional incorrecta.
Queda caracteritzat estructuralment, amb quatre tests de mapatge/límits.

Ebl/QcomBds tenen ara revisió funcional acotada de vies d'interfície;
TzDxeLA aporta [un consumidor SCM independent](tzdxe-policy-consumer.md),
amb neteja prèvia de política i una omissió local d'alliberament. No són
auditories completes ni nous consumidors del callback MiToken +0x18.
