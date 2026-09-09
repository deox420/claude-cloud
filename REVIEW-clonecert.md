# Revisión de código: `clonecert.py`

Revisión senior de `clonecert.py` (v2.0.0, ~1.3k líneas de Python), el sucesor
en Python de `clone-cert.sh`. Evaluada sobre cinco ejes: calidad/buenas
prácticas, errores y casos extremos, seguridad, rendimiento y mantenibilidad.

> **Uso legítimo.** `clonecert` es una herramienta de pentesting/educación. Toda
> la revisión asume uso autorizado (sistemas propios, laboratorio, CTF o
> engagement documentado). El uso de TLS sin verificar para *capturar* el
> certificado a clonar es intencional y correcto para el cometido de la
> herramienta, no un fallo.

---

## 1. Valoración general

Código **sólido y de nivel senior**. El diseño acierta en lo difícil:

- **Enfoque correcto**: parsear y *reconstruir* con `cryptography` en vez de
  cirugía de bytes con `sed`/`openssl`. Esto es lo que permite clonar cadenas de
  N niveles y re-firmar de arriba abajo de forma consistente.
- **Cobertura criptográfica amplia**: RSA (incl. RSA-PSS), EC, Ed25519, Ed448 y
  DSA, con selección de padding/hash coherente con el original.
- **Principio "idéntico salvo lo cambiado"** bien implementado: extensiones
  copiadas verbatim preservando el orden, serial/validez/firma conservados,
  SKI/AKI mantenidos por defecto para que la cadena enlace.
- **Higiene de seguridad correcta**: claves privadas escritas con `os.open(...,
  0o600)`, `--out-dir` vacío y rechazo de symlinks, `argv` fijo sin shell en la
  llamada a `openssl`, y verificación post-emisión (`sanity_check`).
- **Suite de autotest offline** (12 casos) que cubre orden de cadena, clonado
  verbatim, modificación de intermedias, CA fabricada, self-signed y reemisión
  con CA suministrada. Pasa 12/12.

Los hallazgos son de **robustez y pulido**, no de arquitectura. **No hay
bloqueantes ni vulnerabilidades críticas**. El grueso se concentra en el manejo
de entradas externas mal formadas (trazas feas en vez de errores claros) y en
un par de no-ops silenciosos que pueden confundir al usuario.

---

## 2. Hallazgos

Severidad: 🔴 Crítico · 🟠 Medio · 🟡 Menor. "Verificado" = reproducido
ejecutando la herramienta.

| # | Sev | Hallazgo | Estado |
| --- | --- | --- | --- |
| H1 | 🟠 | `--index` negativo (o fuera de rango bajo) se ignora en silencio: la modificación no se aplica y el comando sale con código 0. | Verificado → corregido |
| H2 | 🟠 | `--chain` contra un endpoint en vivo **sin `openssl`** degradaba en silencio a clonar solo el leaf (Python `ssl` solo expone el leaf), produciendo un resultado incorrecto sin avisar. | Por código → corregido |
| H3 | 🟠 | `--ca-key` cifrada produce un `TypeError` crudo con traceback en vez de un mensaje accionable. | Verificado → corregido |
| H4 | 🟠 | Entradas mal formadas lanzan tracebacks crudos en vez de errores limpios: `--set-ext` con hex inválido (`ValueError`), fichero de certificado corrupto/ausente, `--ca-cert` ilegible. | Verificado → corregido |
| H5 | 🟡 | `--sig none` sobre claves RSA/EC/DSA se sustituía en silencio por SHA-256 (solo tiene sentido en Ed25519/Ed448). | Verificado → corregido |
| H6 | 🟡 | `manifest.json` → `derived_fields` contenía código muerto (`... if False else []`): nunca reportaba SKI/AKI aunque se usara `--recompute-ski`. | Verificado → corregido |
| H7 | 🟡 | Uso de los accesores **deprecados** `not_valid_before`/`not_valid_after` (silenciados con un filtro de warnings). Serán eliminados en versiones futuras de `cryptography`; `requirements.txt` pide `>=41`. | Corregido (compat) |
| H8 | 🟡 | `-q/--quiet` es opción global y solo se acepta **antes** del subcomando; `clone ... -q` es un error de parseo. Error de usuario frecuente. | Documentado (ver §4) |
| H9 | 🟡 | `build_eku` con un nombre EKU mal escrito cae a `ObjectIdentifier(it)` y puede lanzar `ValueError` sin `die` limpio. | Documentado (ver §4) |
| H10 | 🟡 | `verify_signed_by` devuelve `(True, "unsupported...")` para tipos de clave de emisor desconocidos; `sanity_check` lo trata como verificación correcta. Solo afecta a tipos no soportados. | Documentado (ver §4) |
| H11 | 🟡 | `parse_hostport` no soporta IPv6 sin corchetes (documentado: usar `[ipv6]:port`). Aceptable, pero conviene un error explícito. | Documentado (ver §4) |

### Rendimiento

No hay cuellos de botella. La herramienta es I/O-bound (una conexión TLS o una
lectura de fichero) y hace una generación de claves por certificado, que es el
coste esperado e inevitable. `order_chain` es O(n²) en el peor caso pero n es el
largo de una cadena (≤ ~4), así que es irrelevante. **Sin cambios recomendados.**

---

## 3. Código corregido

Las correcciones H1–H7 se aplicaron en este mismo cambio sobre `clonecert.py`
(con comentarios en el punto de cada cambio). Resumen de qué se tocó:

- **H1** — `cmd_clone` ahora valida que **todos** los índices de `mods` estén en
  `0..len(certs)-1` (cubre `--index` negativo y los índices del fichero
  `--mods`), con un mensaje que indica el rango válido.
- **H2** — `fetch_certs` aborta con un mensaje accionable cuando se pide
  `--chain` en vivo y no hay `openssl`, en vez de devolver solo el leaf.
- **H3/H4** — `cmd_clone` y `load_certs_from_bytes` envuelven la carga de
  ficheros/CA y capturan `OSError`/`ValueError`/`TypeError` → `die(...)` claro.
  `build_extensions` hace lo mismo con `--set-ext`.
- **H5** — `signing_params` rechaza `--sig none` para claves no-Ed con un
  mensaje explícito, en vez de degradar a SHA-256 de forma oculta.
- **H6** — `write_manifest` recibe `recompute_ski` y reporta SKI/AKI en
  `derived_fields` solo cuando de verdad se recalcularon.
- **H7** — nuevos helpers `cert_nvb`/`cert_nva` usan los accesores `*_utc`
  cuando existen (normalizados a naive-UTC para no romper las comparaciones del
  resto del código) y caen al accesor antiguo si no.

Verificación tras los cambios:

```
selftest ........................... 12 passed, 0 failed
--sig none (RSA) ................... [x] signature hash 'none' is only valid for ed25519/ed448 keys
--index -1 --cn X .................. [x] --index/--mods references cert #-1 ... (indices 0..0)
--ca-key cifrada ................... [x] --ca-key '...' is encrypted; decrypt it first ...
--set-ext hex inválido ............. [x] invalid --set-ext '...': non-hexadecimal ... (expected OID:critical:der_hex)
fichero corrupto ................... [x] could not parse certificate data: ...
--recompute-ski → manifest ......... derived_fields incluye subject/authority_key_identifier
ed25519 + --sig none ............... OK (sigue permitido)
ruta feliz (clone + identify) ...... OK
```

---

## 4. Sugerencias menores (no aplicadas; decisión del mantenedor)

- **H8** — Aceptar `-q`/`--quiet` también *después* del subcomando (definirlo en
  cada subparser o usar un `parents=` común). Evita un error de parseo en un uso
  muy habitual.
- **H9** — En `build_eku`, envolver `ObjectIdentifier(it)` en try/except para
  emitir "EKU desconocido: ..." en vez de traceback.
- **H10** — En `verify_signed_by`, considerar que un tipo de emisor no soportado
  no debería contar como "verificado" en `sanity_check` (al menos, avisar).
- **H11** — `parse_hostport`: detectar IPv6 sin corchetes y sugerir el formato
  `[ipv6]:port` explícitamente.
- **Consistencia menor**: `manifest.generated_utc` añade un sufijo `"Z"` mientras
  que `not_before`/`not_after` de `identify` no lo llevan. Unificar el formato.

---

*Revisión generada sobre el HEAD de la rama de trabajo. Las pruebas se
ejecutaron en un entorno aislado con `cryptography` 41.x.*
