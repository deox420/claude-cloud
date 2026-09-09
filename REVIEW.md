# Revisión de `clone-cert.sh`

Revisión de uso y de código completa de la herramienta `clone-cert/clone-cert.sh`
(v1.0, 2086 líneas de Bash), evaluada frente al objetivo de ser un
[SySS-Research/clone-cert](https://github.com/SySS-Research/clone-cert)
mejorado y frente a las pautas concretas que definiste.

> **Nota de uso legítimo.** `clone-cert` es una herramienta de pentesting/educación
> para demostrar por qué no se debe confiar ciegamente en certificados
> (auto-firmados o cadenas sin validar). Toda esta revisión asume uso autorizado:
> sistemas propios, laboratorio, CTF o engagement documentado.

---

## 1. Veredicto rápido

La herramienta está **muy por encima** del original de SySS en ingeniería:
subcomandos, captura con STARTTLS/DTLS, manifiestos, perfiles con hash de
integridad, `set -euo pipefail`, `umask 077`, validación de entradas y suite de
auto-test. El estilo de Bash es cuidado y defensivo.

Pero tiene **dos defectos que la dejan sin funcionar tal cual se entrega**, y
**no cumple las pautas centrales** que pediste (modificar *cualquier* parámetro
de *cualquier* certificado, reclonar cadenas de varios niveles).

| Severidad | Hallazgo | Estado |
| --- | --- | --- |
| 🔴 Bloqueante | `clone` falla **siempre** por su propio chequeo de integridad (bug de round-trip del perfil) | Verificado, determinista |
| 🔴 Bloqueante | El `--self-test` **no pasa** (falla en T-013); `release.yml` lo ejecuta ⇒ los releases no se construyen | Verificado (exit 1) |
| 🟠 Pauta incumplida | Sólo se puede modificar el **leaf**, no intermedias ni CA | Por diseño actual |
| 🟠 Pauta incumplida | No se pueden modificar "todos los parámetros": sólo Subject, SAN-DNS y validez (1..90 días) | Por diseño actual |
| 🟠 Pauta incumplida | No reclona cadenas de varios niveles (leaf→int→CA); sólo reemite el leaf bajo **un** emisor | Por diseño actual |
| 🟠 Fidelidad | Extensiones como AIA, CRL DP, Certificate Policies se **descartan en silencio**; algoritmo de firma forzado a SHA-256 | Por lectura de código |
| 🟠 Alcance | Certificados **caducados o con < 1 día** de validez no se pueden clonar | Verificado |
| 🟡 Interop | `validate`/`clone` **rechazan cadenas válidas** según RFC si un emisor no lleva `keyUsage: Certificate Sign` | Verificado |
| 🟡 Menor | Puerto 4433 mapeado a DTLS; validez con granularidad de día; JSON hecho a mano; etc. | Ver §6 |

---

## 2. Cómo lo probé

- `bash -n clone-cert.sh` → OK (sin errores de sintaxis).
- `bash clone-cert.sh --self-test` → **exit 1**, falla en `T-013`.
- Fixtures propios con OpenSSL 3.0: cadena `leaf→intermedia→root` de larga
  validez (años) y con `keyUsage` correcto, más un leaf con SAN de tipo IP y
  extensiones AIA/CRLDP/Certificate Policies, y una cadena con la intermedia sin
  `keyUsage`.
- Reproducción aislada del round-trip del "clone profile" (embed + `awk` de
  extracción + `sha256`), para confirmar que el fallo de integridad es
  determinista e independiente del certificado.

---

## 3. Revisión de uso (UX / interfaz)

**Lo bueno**

- Subcomandos claros: `inspect`, `fields`, `validate`, `clone`, captura por
  `host:port` posicional, `--self-test`, `--help`, `--version`.
- `inspect` (inventario compacto) + `fields` (volcado `openssl x509 -text`)
  cubren tu pauta de "identificar": muestran los parámetros de origen.
- `validate` comprueba enlaces DN, restricción CA del emisor, firma y vigencia.
- `--dry-run` para revisar un clon sin escribir nada. Muy buen detalle.
- Manifiestos JSON (`manifest.json`) y perfil con SHA-256 → trazabilidad.

**Fricciones**

1. **Captura y clonado están separados.** Para clonar un certificado web hay que
   (1) capturar a un directorio y (2) `clone --chain <capture>/...-chain.pem`.
   No existe `clone host:port` directo. Es defendible (revisar antes de clonar),
   pero conviene documentarlo como flujo de 2 pasos.
2. **El `identify` no está alineado con lo que `clone` puede cambiar.** `fields`
   enseña todo, pero `clone` sólo modifica un subconjunto minúsculo. El operador
   ve campos que luego no puede tocar. La pauta pedía que "identificar imprima
   los parámetros que la herramienta pueda modificar": hoy no hay esa relación.
3. **Sin `--transport` explícito.** El transporte se deduce del puerto
   (`transport_for_port`, líneas 512-524) sin forma de sobreescribirlo. Un
   servicio TLS normal en 4433 fallará (se fuerza DTLS); un TLS directo en 25
   fallará (se fuerza STARTTLS-SMTP).
4. **Rango de validez 1..90 días** en `--set-validity-days` (líneas 893-896).
   Muy limitado si se quiere reproducir la validez real del original.
5. **`--set-field` sólo acepta `subject.<attr>`, `san.dns`, `validity.days`**
   (líneas 837-861) y siempre sobre el leaf. No hay índice de certificado.

---

## 4. Hallazgos bloqueantes (SEV-1)

### 4.1 `clone` falla siempre: round-trip del "clone profile" roto

**Síntoma:** cualquier clon real aborta con
`error: clone profile SHA-256 does not match its canonical payload`.
(Verificado con dos cadenas distintas; sólo `--dry-run` se salva porque retorna
antes de ejecutar, línea 1797.)

**Causa raíz.** `prepare_clone_profile` incrusta el payload canónico así
(líneas 967-971):

```bash
printf '{\n  "canonical_payload": '
append_file "${payload}"                 # el payload termina en una línea "}" pelada
printf ',\n  "profile_sha256": "%s"\n}\n' "${profile_hash}"
```

y `extract_clone_profile` lo vuelve a extraer con este `awk` (líneas 978-982):

```bash
awk '
  /^  "canonical_payload": \{$/ { print "{"; in_payload=1; next }
  in_payload && /^},$/ { print "}"; exit }   # <-- nunca coincide
  in_payload { print }
' "${profile}" >"${destination}"
```

El payload que escribe `write_clone_profile` **termina en una línea `}` pelada**
(línea 779, `printf '}\n'`), no en `},`. El `awk` sólo corta en una línea que sea
exactamente `},` (`/^},$/`), que nunca aparece (la que cierra `"fields"` es
`  },`, con sangría, y tampoco casa). Resultado: la extracción sigue leyendo
hasta EOF e incluye la coma, la línea `profile_sha256` y el `}` final. El
SHA-256 recalculado nunca coincide con el esperado → `verify_clone_profile_integrity`
mata el proceso (líneas 987-1003), tanto en `execute_clone` (1508) como en
`execute_self_signed_clone` (1627).

**Reproducción aislada (determinista):**

```
expected(hash of payload): dd33e15c...cf647
actual  (hash of extracted): 4ef0d5cc...50f7c
MISMATCH -> integrity check would FAIL
```

**Arreglo (mínimo y robusto).** No confíes en el `awk` frágil: extrae el payload
tal cual se incrustó. La forma más simple es hacer el marcado inequívoco. Opción
A — delimitar el payload con marcadores y extraer entre ellos:

```bash
# al escribir el perfil:
{
  printf '%s\n' '--- BEGIN CLONE PROFILE PAYLOAD ---'
  append_file "${payload}"
  printf '%s\n' '--- END CLONE PROFILE PAYLOAD ---'
  printf 'profile_sha256=%s\n' "${profile_hash}"
} >"${profile}"

# al extraer:
awk '/^--- BEGIN CLONE PROFILE PAYLOAD ---$/{f=1;next}
     /^--- END CLONE PROFILE PAYLOAD ---$/{f=0}
     f' "${profile}" >"${destination}"
expected="$(awk -F= '/^profile_sha256=/{print $2; exit}' "${profile}")"
```

Opción B (si se quiere mantener el JSON envolvente): guardar el payload en un
**fichero aparte** y hashearlo directamente, en vez de re-extraerlo con `awk`
de un JSON concatenado a mano. En cualquier caso, **añade un caso de self-test
que verifique que un clon real se produce y vuelve a validar** (ahora no existe;
sólo se prueba el `--dry-run`).

### 4.2 El `--self-test` no pasa (y bloquea releases)

**Síntoma:** `bash clone-cert.sh --self-test` sale con **exit 1** en `T-013`
(`automatic generated-issuer clone failed`) con
`error: source certificate expires in less than one day`. El README afirma
"fifteen passing cases"; no es reproducible.

**Causa raíz.** Las fixtures se crean con `-days 1` (leaf e intermedia, líneas
1892 y 1902) y `-days 2` (root, 1880), pero `remaining_validity_days`
(1164-1183) devuelve **días enteros** por búsqueda binaria de `-checkend`.
Un certificado con 1 día de validez, unos segundos después de emitirse, tiene
**0 días enteros** restantes. El modo generated-issuer exige `source_days >= 1`
(línea 1809) y aborta. Lo mismo ocurriría con `execute_clone`/self-signed
(guardas en 1543-1544 y 1652-1653) — pero además, aunque se corrigiera la
validez, el clon fallaría por el bug 4.1.

**Impacto CI:** `release.yml` ejecuta `bash clone-cert.sh --self-test` en el
push de tags `v*`; con la suite fallando, **el job de release falla y no se
publican artefactos**.

**Arreglo.** (a) Emitir las fixtures con validez holgada (p.ej. `-days 3650`).
(b) Corregir 4.1. (c) Que `remaining_validity_days` trabaje en segundos o
redondee hacia arriba, para no rechazar certificados de vida corta (ver 5.6).

---

## 5. Brechas frente a tus pautas

| Pauta | Estado | Detalle |
| --- | --- | --- |
| Clonar cert web `host:port` | ⚠️ Parcial | La captura copia bytes tal cual; el reclonado real requiere un 2º paso `clone --chain`. No hay `clone host:port`. |
| Clonar local: leaf / leaf→int / leaf→int→CA, auto-firmado o no | ⚠️ Parcial | Acepta la cadena, pero **sólo reemite el leaf**. No regenera intermedias ni root con claves nuevas. |
| Modificar **cualquier** certificado accesible | ❌ No | Todos los cambios se aplican **sólo al leaf** (`change_options`, `cmd_clone`). No hay índice de certificado. |
| `identificar` imprime parámetros modificables / `validar` valida la cadena | ⚠️ Parcial | `inspect`/`fields`/`validate` existen y están bien, pero `identify` no refleja lo que `clone` puede cambiar (que es muy poco). |
| Soportar **más de una intermedia** | ⚠️ Parcial | `inspect`/`validate` sí. Pero `clone` generated-issuer crea **un único** emisor falso; no reconstruye jerarquías multinivel. |
| Modificar **todos los parámetros** de cualquier cert | ❌ No | Sólo Subject (RFC4514 o un atributo simple), SAN **DNS** y validez **1..90 días**. Rechaza SAN no-DNS, extensiones arbitrarias, comas/escapes en Subject; serial/SKI/AKI/firma se regeneran sin control. |
| Prácticamente idéntico al original salvo lo modificado | ⚠️ Parcial | La **captura** sí (es copia). El **reclonado** sólo es idéntico si aportas la clave privada original (`--leaf-key`). Además pierde fidelidad (§5.4). |

### 5.1 Sólo se modifica el leaf
`cmd_clone` (1701-1827) enruta todos los `--set-*` a `prepare_clone_profile`,
que sólo lee/edita `CERT_FILES[0]`. No existe forma de decir "modifica la
intermedia #1" ni de reemitir la intermedia/root. Tu pauta pide exactamente eso.

### 5.2 No hay reclonado de cadena multinivel
Para `leaf→int→CA` con claves nuevas en todos los niveles habría que: regenerar
la clave del root (auto-firma), reemitir la(s) intermedia(s) firmada(s) por el
root clonado, y reemitir el leaf firmado por la intermedia clonada. La
herramienta no hace esto: o firma el leaf bajo un emisor **que aportas**
(original) o bajo **un** emisor generado. (La herramienta Python
`clonecert.py` sí implementa el reclonado top-down de N niveles; ver §8.)

### 5.3 Conjunto de cambios muy reducido
Rutas soportadas en `--set-field` (837-861): `subject.<attr>`, `san.dns`,
`validity.days`. Rechaza explícitamente `--unset-field`, `--set-extension`,
`--remove-extension` (865-867). Sin control de: serial, notBefore,
issuer del leaf, keyUsage/EKU, basicConstraints, ni cualquier extensión OID.

### 5.4 Pérdida de fidelidad en el reclonado
- **Extensiones descartadas en silencio.** `write_leaf_extension_config`
  (1318-1347) y `write_self_signed_extension_config` (1349-1386) sólo escriben
  BasicConstraints, SKI, AKI, KeyUsage, EKU y SAN-DNS. **AIA (OCSP/CA Issuers),
  CRL Distribution Points, Certificate Policies, Name Constraints, etc. no se
  reproducen** y **no se rechazan** — al contrario de lo que dice el README
  ("arbitrary extensions ... are rejected instead of silently changing them").
  Un leaf real con AIA/CRLDP/policies se clonaría **sin** esas extensiones.
- **Algoritmo de firma forzado a SHA-256** (`-sha256` en 1156, 1574, 1684). Un
  original firmado con SHA-384/512 (o PSS) sale con SHA-256 → distinto del
  original.
- **KeyUsage/EKU con lista blanca.** `source_key_usage` (1260-1287) aborta si el
  leaf tiene `Certificate Sign`/`CRL Sign`; `source_extended_key_usage`
  (1289-1316) aborta ante EKUs fuera de un set fijo. Certificados legítimos con
  EKUs poco comunes no se pueden clonar.
- **SAN no-DNS rechazado** (1330, 1360): IP, email, URI, othername → error.
  Muchos certificados de servidor llevan `IP:` en el SAN.

### 5.5 Rechaza cadenas válidas por `keyUsage`
`validate_link` (341-357) y `cmd_validate` (395-404) exigen que **todo** emisor
lleve `keyUsage` con `Certificate Sign`. Según RFC 5280 §4.2.1.3, `keyUsage` es
**opcional**: una CA con `BasicConstraints: CA:TRUE` sin `keyUsage` es válida.
Como `clone` ejecuta `cmd_validate` primero (1772), esas cadenas **no se pueden
ni clonar**. *(Verificado: una intermedia sin `keyUsage` produjo
`chain link 0: issuer certificate lacks Certificate Sign key usage`.)*

### 5.6 No se pueden clonar certificados caducados o casi caducados
`validate` usa `openssl verify` (con comprobación de tiempo) y `clone` valida
antes de operar; además `remaining_validity_days` redondea a días enteros y las
guardas exigen `>= 1` día. Resultado: un certificado **caducado** o con **< 1
día** de vida no se clona — justo un caso habitual en pentest (clonar un cert
expirado). Conviene: permitir clonar sin exigir vigencia (o `--allow-expired`),
y medir validez en segundos.

---

## 6. Revisión de código por temas

### Correctitud
- **[SEV-1]** Round-trip del perfil roto (§4.1).
- **[SEV-1]** Self-test falla (§4.2).
- **[SEV-2]** Estrictitud `keyUsage` fuera de RFC (§5.5).
- **[SEV-3]** `transport_for_port` (512-524): 4433→DTLS sorprende (4433 es el
  puerto TLS de prueba clásico de `openssl s_server`). Añade `--transport`.
- **[SEV-3]** `rfc2253_to_openssl_subject` (1061-1077) rechaza Subjects con
  `/`, `+` o `\` → RDN multivaluados y valores con `/` (p.ej. `O=Foo/Bar`) no se
  pueden clonar.
- **[SEV-3]** `certificate_dns_sans` (651-661) parsea el texto de OpenSSL con
  regex y borrado por substring; correcto en casos normales, frágil ante
  formatos raros. Mejor `openssl x509 -ext subjectAltName` en formato estable o
  parseo por ASN.1.
- **[SEV-3]** `derive_fake_issuer_subject` (1084-1120): el reemplazo del último
  carácter por espacio puede dejar dobles espacios / cambios no visibles; casos
  borde con un solo RDN.

### Seguridad (buen nivel, con matices)
- ✔️ `set -euo pipefail`, `IFS=$'\n\t'`, `umask 077`, `trap cleanup EXIT HUP INT TERM`.
- ✔️ Comprobaciones anti-symlink en entradas/salidas, `--out-dir` debe estar
  vacío, uso de `mktemp -d`, `--` antes de rutas, verificación de que
  issuer-cert e issuer-key casan por digest de clave pública (1502, 1549).
- ✔️ Verifica el leaf emitido contra la cadena del emisor (1583).
- ⚠️ **JSON hecho a mano.** `json_escape` (103-111) escapa `\ " \n \r \t` pero no
  otros caracteres de control (0x00-0x1F). Un Subject con un control byte podría
  producir JSON inválido. Riesgo bajo, pero considera `jq -Rn` o un codificador
  completo.
- ⚠️ `tag-from-script.yml` mete el token en la URL remota de `git push`. Con
  logs verbosos podría filtrarse. Preferible `git -c http.extraHeader=...` o
  credential helper.
- ⚠️ Patrón `local x="$(cmd)"` con `set -e`: `local` siempre retorna 0, así que
  enmascara fallos de la substitución. La mayoría de sitios usan `|| die`
  explícito; revisa que ninguno crítico dependa de que `set -e` corte ahí.

### Portabilidad / robustez
- `-starttls ldap`/`xmpp`, `-dtls` requieren OpenSSL relativamente moderno; sin
  fallback ni mensaje claro si no están.
- `append_file` (1838-1844) reimplementa `cat` línea a línea (lento en ficheros
  grandes; añade `\n` final). Un `cat --` basta y preserva bytes.
- `remaining_validity_days` (1164-1183) hace búsqueda binaria con muchas
  invocaciones de `openssl`; con `-enddate` + `date` se calcula directo.
- Dispatch en `main` (2080-2082): cualquier primer argumento desconocido se
  trata como `host:port` de captura → un typo de subcomando da un error confuso.

### Estilo (positivo)
Nombres descriptivos, funciones cohesivas, `readonly` para constantes,
validaciones tempranas y mensajes de error con códigos de salida diferenciados
(1=uso, 2=parseo, 3=input de cambio, 4=criptografía/emisión). Muy legible.

---

## 7. Fortalezas (a conservar)

1. Higiene de Bash y postura de seguridad de ficheros excelentes.
2. Arquitectura por subcomandos + captura con transporte automático.
3. Trazabilidad: perfil canónico + `manifest.json` + `--dry-run`.
4. Honestidad sobre límites en el README (aunque hay que corregir la afirmación
   de "rejected instead of silently changing" para AIA/CRLDP/policies y la de
   "fifteen passing cases").
5. Suite de auto-test + CI (una vez arreglada).

---

## 8. Plan de mejoras priorizado

**P0 — Que funcione (arreglos, no rediseño)**
1. Arreglar el round-trip del perfil (§4.1) y añadir un self-test que produzca y
   revalide un clon real.
2. Arreglar las fixtures del self-test y `remaining_validity_days` (§4.2) para
   que `--self-test` pase y el CI construya releases.
3. Relajar la exigencia de `keyUsage` en `validate` a lo que pide RFC 5280 (§5.5).

**P1 — Cumplir tus pautas (esto sí es rediseño del `clone`)**
4. **Modificar cualquier certificado de la cadena:** introducir un selector por
   índice (p.ej. `--target N` o `--set-field N.subject.CN=...`) y aplicar cambios
   a intermedias/root, no sólo al leaf.
5. **Reclonar cadenas multinivel:** regenerar claves por nivel y re-firmar
   top-down (root auto-firma → intermedias → leaf), soportando N intermedias.
6. **Cobertura de parámetros completa:** serial, notBefore/notAfter sin tope,
   issuer, keyUsage/EKU arbitrarios, SAN de todos los tipos (DNS/IP/email/URI),
   basicConstraints, y extensiones arbitrarias por OID (copiar verbatim +
   `--set-ext OID:crit:HEXDER` / `--del-ext OID`).
7. **Fidelidad "idéntico salvo lo cambiado":** copiar **todas** las extensiones
   verbatim por defecto (incluidas AIA/CRLDP/policies), preservar el algoritmo
   de firma del original, y sólo desviarse cuando se pida a propósito.
8. Alinear `identify` para que liste exactamente los parámetros que `clone`
   puede cambiar (y por certificado).

**P2 — Ergonomía**
9. `clone host:port` directo (captura+clona), `--transport` explícito,
   `--allow-expired`, y documentar el flujo de 2 pasos.

### Sobre el "cómo": Bash vs. reescritura

Los puntos P1 (extensiones arbitrarias, todos los tipos de SAN, re-firma
multinivel, control byte-a-byte de campos) son **muy difíciles y frágiles de
hacer con `openssl` + `.cnf` + texto**: es la misma clase de fragilidad que
tenía el `sed` del original de SySS. Reconstruir el certificado parseando ASN.1
de verdad (Python + `cryptography`) elimina esa fragilidad y hace triviales las
pautas 3, 5 y 6.

**Decisión tomada:** pasar a Python y rescatar lo bueno del Bash. La herramienta
mejorada vive en [`clonecert.py`](clonecert.py) (Python + `cryptography`), con
[`README.md`](README.md), `requirements.txt`, `selftest` integrado (12 casos
offline) y CI en `.github/workflows/ci.yml`. El `clone-cert.sh` original se
conserva en `clone-cert/` como material revisado.

`clonecert.py` implementa todas tus pautas: reclonado de cadena de **N
niveles** (re-firma top-down), modificación de **cualquier** parámetro de
**cualquier** certificado por índice (`--index N` / `--mods JSON`), incluidas
extensiones arbitrarias por OID (`--set-ext`/`--del-ext`), SAN de todos los tipos
(dns/ip/email/uri), todos los tipos de clave (RSA/EC/Ed25519/Ed448/DSA) y firma
(incl. RSA-PSS), y copiado **verbatim** de extensiones (idéntico salvo lo
cambiado, conservando también el algoritmo de firma del original). Rescata del
Bash: subcomandos, transporte por puerto (TLS/STARTTLS/DTLS) +
`--transport`, `manifest.json` del clonado con provenance, `--dry-run`,
verificación emisor↔clave y post-emisión, `--out-dir` vacío + anti-symlink,
permisos `0600` y la derivación homoglifo del emisor. Comprobado: clona cadenas
completas y **revalida** (también con `openssl verify`); un clon sin cambios es
idéntico al original en todos sus parámetros salvo clave y firma.
