# clonecert

`clonecert.py` captura, inspecciona, valida y **clona** certificados X.509 y
cadenas completas para trabajo de PKI autorizado. Es la evolución en Python del
`clone-cert.sh` (en `clone-cert/`, incluido para referencia y revisado en
[`REVIEW.md`](REVIEW.md)) y un sucesor mejorado de
[SySS-Research/clone-cert](https://github.com/SySS-Research/clone-cert).

En lugar de hacer cirugía de bytes/texto con `sed`/`openssl`, parsea y
**reconstruye** los certificados con la librería `cryptography`. Eso permite
clonar cadenas de varios niveles, modificar **cualquier** parámetro de
**cualquier** certificado, y mantener todo idéntico al original salvo lo que
cambies a propósito.

> ⚠️ **Uso autorizado únicamente.** Clonar certificados solo es apropiado contra
> sistemas propios o que tengas permiso explícito para auditar (pentest
> documentado, laboratorio o CTF). Suplantar un servicio sin autorización es muy
> probablemente ilegal. Eres responsable del uso que le des.

## Instalación

```bash
python3 -m pip install -r requirements.txt   # solo 'cryptography'
python3 clonecert.py --help
```

## Comandos

| Comando | Para qué |
| --- | --- |
| `identify` | Imprime **todos los parámetros modificables** de un cert/cadena (texto o `--json`). |
| `validate` | Comprueba que la cadena sea válida entre sus partes (firma, enlaces DN, CA, vigencia). |
| `clone` | Clona un leaf o una cadena entera; aplica modificaciones; genera manifiesto. |
| `selftest` | Suite de regresión offline (12 casos, sin red). |

Los tres comandos toman un **argumento posicional** que es o bien un
`[sni@]host:port` (servidor en vivo) o bien un fichero PEM/DER/bundle — se
autodetecta. Opcionales comunes: `--sni`, `--timeout`, `--chain` (toda la
cadena, no solo el leaf) y `--transport auto|tls|starttls-smtp|…|dtls`.

```bash
clonecert.py identify example.org:443 --chain
clonecert.py identify chain.pem --chain --json
clonecert.py validate chain.pem
```

## Pautas cubiertas

**Clonar un certificado web** (por `host:port`, directo):

```bash
python3 clonecert.py clone example.org:443 --chain -d salida
python3 clonecert.py clone www.example.org@example.org:443 --chain -d salida  # con SNI
```

**Clonar cadenas locales** (leaf, leaf→intermedia, leaf→intermedia→CA;
auto-firmadas o no). Con `--chain` se regeneran claves en **todos** los niveles
y se re-firma de arriba abajo (soporta **N intermedias**):

```bash
python3 clonecert.py clone chain.pem --chain -d salida
python3 clonecert.py validate salida/*.chain.pem
```

**Modificar cualquier parámetro de cualquier certificado.** Las banderas de
modificación apuntan al certificado indicado por `--index N` (0 = leaf). Para
cambios en varios certificados a la vez usa `--mods fichero.json`.

```bash
# cambiar el CN del leaf, el tipo de clave y añadir un SAN
python3 clonecert.py clone chain.pem --chain \
  --cn evil.example.com --key ec:secp384r1 --add-san dns:extra.example.com -d out

# modificar la INTERMEDIA (índice 1) y re-enlazar la cadena
python3 clonecert.py clone chain.pem --chain --index 1 --cn "Rogue CA" \
  --recompute-ski -d out
```

| Bandera | Efecto (sobre `--index N`) |
| --- | --- |
| `--cn`, `--subject '/CN=…/O=…'`, `--issuer` | Subject/Issuer (atributo o DN completo). |
| `--serial <int\|0xHEX\|random>` | Número de serie. |
| `--not-before`, `--not-after` (ISO / `now` / `+30d`), `--days N` | Vigencia. |
| `--key rsa[:bits]\|ec[:curva]\|ed25519\|ed448\|dsa[:bits]` | Regenera la clave. |
| `--sig sha256\|sha384\|sha512\|…` | Hash de firma. |
| `--san`, `--add-san`, `--clear-san` (`dns:`/`ip:`/`email:`/`uri:`) | SAN de cualquier tipo. |
| `--set-ca BOOL`, `--path-len N` | BasicConstraints. |
| `--set-ku`, `--set-eku` | Key Usage / Extended Key Usage. |
| `--set-ext OID:crit:HEXDER`, `--del-ext OID` | Cualquier extensión por OID. |
| `--mods fichero.json` | `{ "índice": { "parámetro": valor } }` para control total multi-cert. |

**Prácticamente idéntico al original salvo lo cambiado.** Por defecto, cada
certificado clonado copia **todas** sus extensiones verbatim (SAN, AIA, CRL DP,
Certificate Policies, EKU, etc.), conserva serial, validez y **algoritmo de
firma** del original; solo cambian la clave pública y la firma. `identify` de un
clon sin modificaciones es idéntico al del original salvo esos dos campos.

## Emisor de la cadena

- Fuente auto-firmada → clon auto-firmado con la clave nueva.
- Fuente firmada por CA con `--ca-cert`/`--ca-key` → se reemite bajo esa CA.
- Fuente firmada por CA sin material de emisor → se genera una **CA falsa** (su
  Subject deriva del emisor original, con un carácter homoglifo, o `--fake-issuer-subject`).
- `--self-signed` fuerza salida auto-firmada; `--keep-issuer-name` no altera el
  nombre del emisor generado; `--recompute-ski` recalcula SKI/AKI desde las
  claves nuevas (por defecto se mantienen idénticos al original).

La CA generada **no** es de confianza para clientes salvo que la instales como
ancla de confianza. Es una cadena parecida para demostraciones controladas, no
un bypass de validación de PKI.

## Salida

`clone` escribe en `--out-dir` (que debe estar vacío): por cada certificado un
`*.key.pem` (permisos `0600`) y `*.cert.pem`, un bundle `*.chain.pem`, la CA
generada si aplica, y un `manifest.json` con huellas de origen/clon, campos
modificados y modo de emisor.

## Verificación

```bash
python3 clonecert.py selftest    # 12 casos, offline
```

## Qué se rescató del `clone-cert.sh` original

Subcomandos, transporte automático por puerto (TLS/STARTTLS/DTLS) y
`--transport`, `manifest.json` del clonado con provenance, `--dry-run`,
verificación emisor↔clave y post-emisión, validaciones de entrada, `--out-dir`
vacío + rechazo de symlinks, permisos `0600`, la derivación homoglifo del emisor
y una suite de auto-test. Ver [`REVIEW.md`](REVIEW.md) para el detalle de qué se
corrigió respecto al Bash.
