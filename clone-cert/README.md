# clone-cert

`clone-cert.sh` is a single Bash executable for capturing, inspecting,
validating, and reissuing X.509 TLS certificate chains for authorised PKI work.

Version: `1.0` (`./clone-cert.sh --version`).

## Use

```bash
git clone <repository-url> clone-cert
cd clone-cert
chmod +x clone-cert.sh
./clone-cert.sh --help
```

There are no installers, services, Python dependencies, or additional public
executables.

## Capture a TLS chain

Capture is always `host:port`. The server's presented certificates are copied
unchanged into a new directory below `--out-dir`.

```bash
./clone-cert.sh example.org:443 --out-dir captures

./clone-cert.sh example.org:443 \
  --sni www.example.org \
  --timeout-seconds 10 \
  --out-dir captures
```

The output directory can contain earlier captures. A unique directory based on
the leaf common name, port, time, and fingerprint is created for every run:

```text
captures/
  example.org-443-20260909T120000Z-a1b2c3d4e5f6/
    example.org-chain.pem
    manifest.json
```

The captured bundle is in the order presented by TLS: leaf first, followed by
the presented intermediates. Servers normally do not present a trust root.

Standard ports select TLS, STARTTLS, or DTLS automatically. Other ports use
direct TLS.

## Inspect local certificates

Use a PEM bundle in leaf-to-root order:

```bash
./clone-cert.sh inspect --chain captures/<capture>/example.org-chain.pem
./clone-cert.sh inspect --chain chain.pem --format json
./clone-cert.sh fields --chain chain.pem
./clone-cert.sh validate --chain chain.pem
```

`inspect` provides a compact inventory. `fields` prints OpenSSL's complete
decoded representation for every certificate, including extensions, so the
operator can identify the source values before requesting a change. `validate`
checks DN links, issuer CA constraints, signatures, and current validity.

## Automatic clone mode

The capture itself is the exact public certificate clone. Any certificate with
a changed field must be signed again, so it cannot retain the original serial,
signature, SKI/AKI, or certificate bytes.

`clone` selects its output mode automatically:

- A self-issued source becomes a newly generated self-signed certificate.
- A CA-issued source with `--issuer-cert` and `--issuer-key` is reissued under
  that original direct issuer. Its Subject and signature relationship are
  verified before issuance.
- A CA-issued source without issuer material receives an automatically generated
  issuing CA. Its Subject is deterministically derived from the source Issuer,
  and its key and certificate are saved with the output.

The generated issuer is not trusted by browsers or other clients unless the
operator explicitly installs it as a trust anchor. It is a lookalike chain for
controlled demonstrations, not a PKI-validation bypass.

```bash
# Automatic generated-issuer mode for a CA-issued source.
./clone-cert.sh clone --chain chain.pem --out-dir reissued
```

To create the closest reissued leaf, provide the original direct issuer
certificate and its matching private key:

```bash
./clone-cert.sh clone \
  --chain chain.pem \
  --issuer-cert original-intermediate.cert.pem \
  --issuer-key original-intermediate.key.pem \
  --issuer-chain original-root.cert.pem \
  --out-dir reissued
```

By default, the generated leaf key follows the source public-key profile. To
reuse the original leaf public key, provide its matching private key explicitly:

```bash
./clone-cert.sh clone \
  --chain chain.pem \
  --issuer-cert original-intermediate.cert.pem \
  --issuer-key original-intermediate.key.pem \
  --leaf-key original-leaf.key.pem \
  --out-dir reissued
```

`--leaf-key` deliberately handles private key material; use it only when that
is authorised and necessary. Without it, the certificate cannot be byte-for-byte
identical to the source, even if no displayed field changes.

The output directory must be empty and receives:

```text
reissued/
  leaf.key.pem
  leaf.cert.pem
  issued-chain.pem
  manifest.json
```

Generated-issuer mode additionally writes:

```text
  generated-issuer.key.pem
  generated-issuer.cert.pem
```

Use `--self-signed` to force self-signed output, `--original-issuer-only` to
forbid generated-issuer fallback, or `--fake-issuer-subject <RFC4514-DN>` to
replace the derived generated-issuer Subject.

## Requested changes

No source field changes unless a change option is supplied. Supported changes
are applied only to the reissued leaf:

| Option | Effect |
| --- | --- |
| `--set-leaf-subject <RFC4514-DN>` | Replaces the complete leaf Subject. |
| `--set-leaf-san <DNS>` | Replaces DNS SANs; repeat for multiple values. |
| `--set-validity-days <1..90>` | Requests the new lifetime, capped by the issuer expiry. |
| `--set-field subject.<attribute>=<value>` | Changes one simple Subject attribute. |
| `--set-field san.dns=<dns;dns>` | Replaces DNS SANs with a semicolon-separated list. |
| `--set-field validity.days=<1..90>` | Alias for `--set-validity-days`. |
| `--key-algorithm <profile>` | Explicitly changes the generated leaf-key profile. |

The tool currently preserves only DNS SANs and the supported key-usage/EKU
values during reissuance. Non-DNS SANs, arbitrary extensions, escaped Subject
components, and unsupported extension codecs are rejected instead of silently
changing them. That limitation is intentional: displaying every field is safe;
claiming to reproduce arbitrary X.509 extensions without an explicit codec is
not.

Review a requested clone without creating a key, certificate, or output
directory:

```bash
./clone-cert.sh clone \
  --chain chain.pem \
  --set-field subject.O='Example Organisation' \
  --dry-run \
  --out-dir reissued
```

## Verification

```bash
./clone-cert.sh --self-test
```

The self-test uses an ephemeral local PKI and local TLS server; it does not
contact external endpoints. It should finish with fifteen passing cases.
