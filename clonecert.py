#!/usr/bin/env python3
"""clonecert - clone, inspect, validate and re-issue X.509 certificate chains.

An improved reimplementation of SySS-Research/clone-cert (original by
Adrian Vollmer, SySS GmbH) and a Python successor to the clone-cert.sh
Bash tool. Certificates are parsed and rebuilt with the `cryptography`
library instead of doing byte/text surgery with `sed`/`openssl`, which makes
it possible to:

  * read from a live TLS server (host:port, SNI, STARTTLS, DTLS) or a file,
  * clone a single leaf or a whole chain: leaf -> intermediate(s) -> CA,
    self-signed or CA-issued,
  * modify ANY parameter of ANY certificate in the chain (subject, issuer,
    serial, validity, key type, signature hash, SANs of every type, basic
    constraints, key usage / EKU, and arbitrary extensions by OID),
  * keep every field byte-for-byte equivalent to the original UNLESS you
    change it on purpose,
  * inspect ("identify") every modifiable parameter, and validate that a
    chain is internally consistent,
  * support RSA, EC, Ed25519, Ed448 and DSA keys and RSA-PSS signatures.

LEGAL / ETHICAL USE ONLY
------------------------
Cloning certificates is only appropriate against systems you own or are
explicitly authorized to test (documented penetration test, lab, or CTF).
The canonical use case is demonstrating that self-signed or blindly-trusted
certificates provide no real protection. Impersonating a service you are not
authorized to test is very likely illegal. You are responsible for your use.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, NoReturn

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import (
        dsa,
        ec,
        ed448,
        ed25519,
        padding,
        rsa,
    )
    from cryptography.x509.oid import (
        ExtendedKeyUsageOID,
        ExtensionOID,
        NameOID,
        ObjectIdentifier,
        SignatureAlgorithmOID,
    )
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "error: the 'cryptography' package is required.\n"
        "       install it with:  python3 -m pip install cryptography\n"
    )
    raise SystemExit(2)

try:  # silence naive-datetime deprecation noise on newer cryptography
    from cryptography.utils import CryptographyDeprecationWarning

    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except Exception:  # pragma: no cover
    pass

__version__ = "2.0.0"

DISCLAIMER = (
    "clonecert is for AUTHORIZED security testing and education only. "
    "Only clone certificates of systems you own or are permitted to test."
)

QUIET = False


# --------------------------------------------------------------------------- #
# Small utilities                                                             #
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    if not QUIET:
        sys.stderr.write(f"[*] {msg}\n")


def warn(msg: str) -> None:
    sys.stderr.write(f"[!] {msg}\n")


def die(msg: str) -> NoReturn:
    sys.stderr.write(f"[x] {msg}\n")
    raise SystemExit(1)


def hexs(data: bytes | None) -> str:
    return data.hex() if data else ""


def utcnow() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def safe_stem(value: str) -> str:
    """Turn an arbitrary target string into a safe output-filename stem."""
    value = re.sub(r"\.(pem|der|crt|cert|cer)$", "", value, flags=re.IGNORECASE)
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", value).strip("._-")
    stem = re.sub(r"_+", "_", stem)
    return (stem or "cert")[:96]


# --------------------------------------------------------------------------- #
# Distinguished-name helpers                                                  #
# --------------------------------------------------------------------------- #
_OID_TO_SHORT = {
    NameOID.COMMON_NAME: "CN",
    NameOID.ORGANIZATION_NAME: "O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
    NameOID.COUNTRY_NAME: "C",
    NameOID.STATE_OR_PROVINCE_NAME: "ST",
    NameOID.LOCALITY_NAME: "L",
    NameOID.EMAIL_ADDRESS: "emailAddress",
    NameOID.SERIAL_NUMBER: "serialNumber",
    NameOID.DOMAIN_COMPONENT: "DC",
    NameOID.GIVEN_NAME: "GN",
    NameOID.SURNAME: "SN",
}
_SHORT_TO_OID = {v.lower(): k for k, v in _OID_TO_SHORT.items()}


def oid_short(oid: ObjectIdentifier) -> str:
    return _OID_TO_SHORT.get(oid, oid.dotted_string)


def short_to_oid(key: str) -> ObjectIdentifier:
    k = key.strip()
    if k.lower() in _SHORT_TO_OID:
        return _SHORT_TO_OID[k.lower()]
    try:
        return ObjectIdentifier(k)
    except Exception:
        die(f"unknown name attribute: {key!r}")


def parse_dn(dn: str) -> x509.Name:
    """Parse '/CN=a/O=b' (OpenSSL) or 'CN=a,O=b' (RFC4514-ish) into a Name."""
    if dn.startswith("/"):
        parts = [p for p in dn.split("/") if p]
    else:
        parts = [p for p in re.split(r"(?<!\\),", dn) if p]
    attrs = []
    for part in parts:
        if "=" not in part:
            die(f"invalid DN component: {part!r}")
        key, _, val = part.partition("=")
        attrs.append(x509.NameAttribute(short_to_oid(key), val.strip().replace("\\,", ",")))
    if not attrs:
        die(f"empty DN: {dn!r}")
    return x509.Name(attrs)


def apply_name_overrides(name: x509.Name, overrides: dict | None) -> x509.Name:
    """Apply per-attribute overrides to a Name, preserving the rest verbatim.

    Maps a short name or dotted OID -> value (None deletes it). Key "_dn" fully
    replaces the name.
    """
    if not overrides:
        return name
    if "_dn" in overrides:
        return parse_dn(str(overrides["_dn"]))

    remaining = {k.lower(): v for k, v in overrides.items()}
    new_rdns = []
    for rdn in name.rdns:
        attrs = []
        for att in rdn:
            short = oid_short(att.oid).lower()
            dotted = att.oid.dotted_string
            key = short if short in remaining else (dotted if dotted in remaining else None)
            if key is not None:
                val = remaining.pop(key)
                if val is None:
                    continue
                attrs.append(x509.NameAttribute(att.oid, str(val)))
            else:
                attrs.append(att)
        if attrs:
            new_rdns.append(x509.RelativeDistinguishedName(attrs))
    for key, val in remaining.items():
        if val is None:
            continue
        new_rdns.append(
            x509.RelativeDistinguishedName([x509.NameAttribute(short_to_oid(key), str(val))])
        )
    return x509.Name(new_rdns)


def munge_cn_in_name(name: x509.Name) -> x509.Name:
    """Swap one character of the CN for a look-alike (the classic trick)."""
    swaps = [("l", "I"), ("I", "l"), ("O", "0"), ("0", "O")]

    def munge(value: str) -> str:
        for src, dst in swaps:
            if src in value:
                return value.replace(src, dst, 1)
        return (value[:-1] + ("_" if value[-1:] != "_" else "-")) if value else value

    new_rdns = []
    for rdn in name.rdns:
        attrs = []
        for att in rdn:
            v = att.value
            if att.oid == NameOID.COMMON_NAME and isinstance(v, str):
                v = munge(v)
            attrs.append(x509.NameAttribute(att.oid, v))
        new_rdns.append(x509.RelativeDistinguishedName(attrs))
    return x509.Name(new_rdns)


# --------------------------------------------------------------------------- #
# Key helpers                                                                 #
# --------------------------------------------------------------------------- #
_CURVES = {
    "secp256r1": ec.SECP256R1, "prime256v1": ec.SECP256R1, "p-256": ec.SECP256R1,
    "p256": ec.SECP256R1,
    "secp384r1": ec.SECP384R1, "p-384": ec.SECP384R1, "p384": ec.SECP384R1,
    "secp521r1": ec.SECP521R1, "p-521": ec.SECP521R1, "p521": ec.SECP521R1,
    "secp256k1": ec.SECP256K1, "secp224r1": ec.SECP224R1,
}
_HASHES: dict[str, Any] = {
    "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512,
    "sha1": hashes.SHA1, "md5": hashes.MD5, "none": None,
}


def key_type_name(pub) -> str:
    for typ, name in (
        (rsa.RSAPublicKey, "rsa"), (ec.EllipticCurvePublicKey, "ec"),
        (ed25519.Ed25519PublicKey, "ed25519"), (ed448.Ed448PublicKey, "ed448"),
        (dsa.DSAPublicKey, "dsa"),
    ):
        if isinstance(pub, typ):
            return name
    return type(pub).__name__


def key_details(pub) -> str:
    t = key_type_name(pub)
    if t in ("rsa", "dsa"):
        return f"{t}:{pub.key_size}"
    if t == "ec":
        return f"ec:{pub.curve.name}"
    return t


def generate_matching_key(cert: x509.Certificate):
    return generate_key_from_spec(key_details(cert.public_key()))


def generate_key_from_spec(spec: str):
    """spec: 'rsa[:bits]', 'ec[:curve]', 'ed25519', 'ed448', 'dsa[:bits]'."""
    spec = spec.strip().lower()
    typ, _, param = spec.partition(":")
    if typ == "rsa":
        return rsa.generate_private_key(public_exponent=65537, key_size=int(param or 2048))
    if typ == "dsa":
        return dsa.generate_private_key(key_size=int(param or 2048))
    if typ == "ec":
        curve = _CURVES.get(param or "secp256r1")
        if curve is None:
            die(f"unknown EC curve: {param!r} (known: {', '.join(sorted(_CURVES))})")
        return ec.generate_private_key(curve())
    if typ == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    if typ == "ed448":
        return ed448.Ed448PrivateKey.generate()
    die(f"unknown key spec: {spec!r}")


def ski_digest(pub) -> bytes:
    return x509.SubjectKeyIdentifier.from_public_key(pub).digest


def signing_params(orig: x509.Certificate, signer_key, hash_override: str | None):
    if isinstance(signer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None, None
    if hash_override is not None:
        cls = _HASHES.get(hash_override.lower())
        if cls is None and hash_override.lower() != "none":
            die(f"unknown signature hash: {hash_override!r}")
        hash_alg = cls() if cls else hashes.SHA256()
    else:
        hash_alg = orig.signature_hash_algorithm or hashes.SHA256()
    rsa_pad = None
    if isinstance(signer_key, rsa.RSAPrivateKey):
        if orig.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            rsa_pad = padding.PSS(mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH)
        else:
            rsa_pad = padding.PKCS1v15()
    return hash_alg, rsa_pad


def sign_builder(builder: x509.CertificateBuilder, key, hash_alg, rsa_pad):
    if rsa_pad is not None:
        try:
            return builder.sign(key, hash_alg, rsa_padding=rsa_pad)
        except TypeError:
            pass
    return builder.sign(key, hash_alg)


def public_der(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verify_signed_by(cert: x509.Certificate, issuer_pub) -> tuple[bool, str]:
    tbs, sig = cert.tbs_certificate_bytes, cert.signature
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            pad = (
                padding.PSS(mgf=padding.MGF1(cert.signature_hash_algorithm),
                            salt_length=padding.PSS.AUTO)
                if cert.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS
                else padding.PKCS1v15()
            )
            issuer_pub.verify(sig, tbs, pad, cert.signature_hash_algorithm)
        elif isinstance(issuer_pub, ec.EllipticCurvePublicKey):
            issuer_pub.verify(sig, tbs, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(issuer_pub, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            issuer_pub.verify(sig, tbs)
        elif isinstance(issuer_pub, dsa.DSAPublicKey):
            issuer_pub.verify(sig, tbs, cert.signature_hash_algorithm)
        else:
            return True, "unsupported issuer key type; not checked"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)
    return True, "ok"


# --------------------------------------------------------------------------- #
# Certificate loading / retrieval                                             #
# --------------------------------------------------------------------------- #
def load_certs_from_bytes(data: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        # PEM, possibly surrounded by other text (e.g. openssl s_client output)
        for block in re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", data, re.DOTALL
        ):
            certs.append(x509.load_pem_x509_certificate(block))
    else:
        certs.append(x509.load_der_x509_certificate(data))
    if not certs:
        die("no certificate found in input")
    return certs


_TRANSPORT_BY_PORT = {
    443: "tls", 636: "tls", 993: "tls", 995: "tls", 465: "tls", 990: "tls", 8443: "tls",
    25: "starttls-smtp", 587: "starttls-smtp",
    143: "starttls-imap", 110: "starttls-pop3", 389: "starttls-ldap",
    5222: "starttls-xmpp", 5269: "starttls-xmpp",
}


def transport_for_port(port: int) -> str:
    return _TRANSPORT_BY_PORT.get(port, "tls")


def parse_hostport(spec: str) -> tuple[str, int, str]:
    sni = None
    hostport = spec
    if "@" in spec:
        sni, hostport = spec.split("@", 1)
    if hostport.startswith("["):  # [ipv6]:port
        m = re.match(r"^\[([0-9A-Fa-f:]+)\]:(\d+)$", hostport)
        if not m:
            die("expected [ipv6]:port")
        host, port_s = m.group(1), m.group(2)
    else:
        if ":" not in hostport:
            die("expected 'host:port' (optionally 'sni@host:port')")
        host, _, port_s = hostport.rpartition(":")
    try:
        port = int(port_s)
    except ValueError:
        die(f"invalid port: {port_s!r}")
    if not (0 < port < 65536):
        die(f"port out of range: {port}")
    return host, port, (sni or host)


def _which_openssl() -> str | None:
    return shutil.which("openssl")


def fetch_via_openssl(host: str, port: int, sni: str, timeout: float,
                      transport: str, openssl: str) -> list[x509.Certificate]:
    args = [openssl, "s_client", "-connect", f"{host}:{port}", "-showcerts"]
    if sni:
        args += ["-servername", sni]
    if transport.startswith("starttls-"):
        args += ["-starttls", transport.split("-", 1)[1]]
    elif transport == "dtls":
        args += ["-dtls"]
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            args, input=b"", capture_output=True, timeout=timeout + 5
        )
    except subprocess.TimeoutExpired:
        die(f"{transport} connection to {host}:{port} timed out")
    except OSError as exc:
        die(f"could not run openssl: {exc}")
    certs = []
    if proc.stdout.find(b"BEGIN CERTIFICATE") != -1:
        certs = load_certs_from_bytes(proc.stdout)
    if not certs:
        err = proc.stderr.decode(errors="replace").strip().splitlines()
        die(f"no certificate captured from {host}:{port}"
            + (f": {err[-1]}" if err else ""))
    return certs


def fetch_leaf_via_python(host: str, port: int, sni: str, timeout: float) -> list[x509.Certificate]:
    ctx = ssl._create_unverified_context()  # deliberate: clone untrusted certs
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        die(f"could not retrieve certificate from {host}:{port}: {exc}")
    if not der:
        die(f"server {host}:{port} presented no certificate")
    return load_certs_from_bytes(der)


def fetch_certs(host: str, port: int, sni: str, timeout: float,
                transport: str, want_chain: bool) -> list[x509.Certificate]:
    openssl = _which_openssl()
    if openssl and (want_chain or transport != "tls"):
        return fetch_via_openssl(host, port, sni, timeout, transport, openssl)
    if transport != "tls":
        die(f"{transport} transport requires the openssl command, which was not found")
    if openssl and not want_chain:
        # python ssl gives us just the leaf, which is all that's asked for
        return fetch_leaf_via_python(host, port, sni, timeout)
    return fetch_leaf_via_python(host, port, sni, timeout)


# --------------------------------------------------------------------------- #
# Chain ordering                                                              #
# --------------------------------------------------------------------------- #
def order_chain(certs: list[x509.Certificate]) -> list[x509.Certificate]:
    """Order leaf-first (index 0 = leaf, last = root/top)."""
    if len(certs) <= 1:
        return list(certs)
    by_subject = {c.subject.public_bytes(): c for c in certs}
    issuers = {c.issuer.public_bytes() for c in certs}
    leaf = next((c for c in certs if c.subject.public_bytes() not in issuers), None)
    if leaf is None:
        return list(certs)
    ordered, seen, cur = [leaf], {leaf.subject.public_bytes()}, leaf
    while cur.subject != cur.issuer:
        parent = by_subject.get(cur.issuer.public_bytes())
        if parent is None or parent.subject.public_bytes() in seen:
            break
        ordered.append(parent)
        seen.add(parent.subject.public_bytes())
        cur = parent
    for c in certs:
        if c.subject.public_bytes() not in seen:
            ordered.append(c)
            seen.add(c.subject.public_bytes())
    return ordered


def get_ext(cert: x509.Certificate, oid) -> Any | None:
    try:
        return cert.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def get_ski(cert: x509.Certificate) -> bytes | None:
    v = get_ext(cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    return v.digest if v else None


def get_aki(cert: x509.Certificate) -> bytes | None:
    v = get_ext(cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    return v.key_identifier if v else None


# --------------------------------------------------------------------------- #
# identify                                                                    #
# --------------------------------------------------------------------------- #
def describe_extension(ext: x509.Extension) -> Any:
    v = ext.value
    if isinstance(v, x509.SubjectAlternativeName):
        out: dict[str, list[str]] = {}
        for typ, label in ((x509.DNSName, "dns"), (x509.IPAddress, "ip"),
                           (x509.RFC822Name, "email"), (x509.UniformResourceIdentifier, "uri")):
            vals = [str(x) for x in v.get_values_for_type(typ)]
            if vals:
                out[label] = vals
        return out
    if isinstance(v, x509.BasicConstraints):
        return {"ca": v.ca, "path_length": v.path_length}
    if isinstance(v, x509.KeyUsage):
        flags = [n for n in ("digital_signature", "content_commitment", "key_encipherment",
                             "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign")
                 if getattr(v, n)]
        if v.key_agreement and v.encipher_only:
            flags.append("encipher_only")
        if v.key_agreement and v.decipher_only:
            flags.append("decipher_only")
        return flags
    if isinstance(v, x509.ExtendedKeyUsage):
        return [oid._name or oid.dotted_string for oid in v]
    if isinstance(v, x509.SubjectKeyIdentifier):
        return hexs(v.digest)
    if isinstance(v, x509.AuthorityKeyIdentifier):
        return {"key_identifier": hexs(v.key_identifier)}
    if isinstance(v, x509.UnrecognizedExtension):
        return {"der_hex": hexs(v.value)}
    try:
        return {"der_hex": hexs(v.public_bytes())}
    except Exception:  # noqa: BLE001
        return repr(v)


def describe_cert(cert: x509.Certificate, index: int) -> dict:
    exts = {}
    for ext in cert.extensions:
        exts[ext.oid._name or ext.oid.dotted_string] = {
            "oid": ext.oid.dotted_string, "critical": ext.critical,
            "value": describe_extension(ext),
        }
    return {
        "index": index,
        "role": "leaf" if index == 0 else ("root" if cert.subject == cert.issuer else "intermediate"),
        "self_signed": cert.subject == cert.issuer,
        "version": cert.version.name,
        "serial": f"{cert.serial_number:x}",
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name or cert.signature_algorithm_oid.dotted_string,
        "public_key": key_details(cert.public_key()),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "extensions": exts,
    }


def cmd_identify(args) -> int:
    certs = load_input(args)
    certs = order_chain(certs) if args.chain else certs[:1]
    described = [describe_cert(c, i) for i, c in enumerate(certs)]
    if args.json:
        print(json.dumps(described, indent=2))
        return 0
    for d in described:
        print(f"=== certificate #{d['index']} ({d['role']}, "
              f"{'self-signed' if d['self_signed'] else 'CA-signed'}) ===")
        for f in ("version", "serial", "subject", "issuer", "not_before",
                  "not_after", "signature_algorithm", "public_key", "sha256_fingerprint"):
            print(f"  {f:20}: {d[f]}")
        if d["extensions"]:
            print("  extensions (all copied verbatim unless modified):")
            for name, info in d["extensions"].items():
                crit = " (critical)" if info["critical"] else ""
                print(f"    - {name}{crit} [{info['oid']}]: {info['value']}")
        print()
    if not args.json:
        print("Modifiable per certificate: subject, issuer, serial, not-before/after,")
        print("public key, signature hash, SAN (dns/ip/email/uri), basic constraints,")
        print("key usage, extended key usage, and any extension by OID (--set-ext/--del-ext).")
    return 0


# --------------------------------------------------------------------------- #
# validate                                                                    #
# --------------------------------------------------------------------------- #
def cmd_validate(args) -> int:
    certs = order_chain(load_input(args))
    now = utcnow()
    all_ok = True
    for i, cert in enumerate(certs):
        label = f"#{i} {cert.subject.rfc4514_string()}"
        if cert.not_valid_before > now:
            warn(f"{label}: not yet valid (starts {cert.not_valid_before})")
        if cert.not_valid_after < now:
            warn(f"{label}: expired ({cert.not_valid_after})")
        parent = certs[i + 1] if i + 1 < len(certs) else (
            cert if cert.subject == cert.issuer else None)
        if parent is None:
            print(f"[?] {label}: top of chain, issuer not present -> cannot verify signature")
            continue
        ok, msg = verify_signed_by(cert, parent.public_key())
        all_ok = all_ok and ok
        rel = "self-signed" if parent is cert else f"signed by #{i + 1}"
        print(f"[{'OK ' if ok else 'FAIL'}] {label}: {rel} ({msg})")
        if cert.issuer != parent.subject:
            warn(f"{label}: issuer name does not match parent subject")
            all_ok = False
        aki, ski = get_aki(cert), get_ski(parent)
        if aki and ski and aki != ski:
            warn(f"{label}: AKI does not match parent SKI (informational)")
        if parent is not cert:
            bc = get_ext(parent, ExtensionOID.BASIC_CONSTRAINTS)
            if bc is None:
                warn(f"#{i + 1}: issuer has no BasicConstraints (RFC allows, but unusual)")
            elif not bc.ca:
                warn(f"#{i + 1}: issuer is not marked CA:TRUE")
    print()
    print("chain: VALID" if all_ok else "chain: INVALID")
    return 0 if all_ok else 1


# --------------------------------------------------------------------------- #
# Modification parsing                                                        #
# --------------------------------------------------------------------------- #
def parse_datetime(value: str) -> _dt.datetime:
    v = value.strip()
    if v.lower() == "now":
        return utcnow()
    m = re.fullmatch(r"([+-]\d+)([dhmy])", v)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        return utcnow() + {"d": _dt.timedelta(days=n), "h": _dt.timedelta(hours=n),
                           "m": _dt.timedelta(minutes=n), "y": _dt.timedelta(days=365 * n)}[unit]
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%Y%m%d%H%M%SZ"):
        try:
            return _dt.datetime.strptime(v, fmt)
        except ValueError:
            continue
    die(f"could not parse date/time: {value!r}")


def validate_dns_name(name: str) -> None:
    core = name[2:] if name.startswith("*.") else name
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", core):
        die(f"invalid DNS name: {name!r}")


def parse_san_entries(items: list[str]) -> list[x509.GeneralName]:
    gns: list[x509.GeneralName] = []
    for it in items:
        typ, _, val = it.partition(":")
        typ, val = typ.strip().lower(), val.strip()
        if typ == "dns":
            validate_dns_name(val)
            gns.append(x509.DNSName(val))
        elif typ == "ip":
            gns.append(x509.IPAddress(ipaddress.ip_address(val)))
        elif typ == "email":
            gns.append(x509.RFC822Name(val))
        elif typ == "uri":
            gns.append(x509.UniformResourceIdentifier(val))
        else:
            die(f"unknown SAN type {typ!r} in {it!r} (use dns:/ip:/email:/uri:)")
    return gns


def parse_serial(value) -> int:
    v = str(value).strip().lower()
    if v == "random":
        return x509.random_serial_number()
    return int(v, 16) if v.startswith("0x") else int(v)


def build_key_usage(spec) -> x509.KeyUsage:
    if isinstance(spec, str):
        want = {s.strip().lower() for s in spec.replace(",", " ").split()}
        alias = {"digitalsignature": "digital_signature", "keyencipherment": "key_encipherment",
                 "keycertsign": "key_cert_sign", "crlsign": "crl_sign",
                 "dataencipherment": "data_encipherment", "keyagreement": "key_agreement",
                 "nonrepudiation": "content_commitment", "contentcommitment": "content_commitment",
                 "encipheronly": "encipher_only", "decipheronly": "decipher_only"}
        want = {alias.get(w, w) for w in want}
        spec = {k: True for k in want}
    fields = {n: bool(spec.get(n, False)) for n in (
        "digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
        "key_agreement", "key_cert_sign", "crl_sign", "encipher_only", "decipher_only")}
    return x509.KeyUsage(**fields)


_EKU = {"serverauth": ExtendedKeyUsageOID.SERVER_AUTH, "clientauth": ExtendedKeyUsageOID.CLIENT_AUTH,
        "codesigning": ExtendedKeyUsageOID.CODE_SIGNING, "emailprotection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
        "timestamping": ExtendedKeyUsageOID.TIME_STAMPING, "ocspsigning": ExtendedKeyUsageOID.OCSP_SIGNING}


def build_eku(spec) -> x509.ExtendedKeyUsage:
    items = spec if isinstance(spec, list) else re.split(r"[,\s]+", spec)
    oids = []
    for it in items:
        it = it.strip()
        if not it:
            continue
        oids.append(_EKU.get(it.lower(), None) or ObjectIdentifier(it))
    return x509.ExtendedKeyUsage(oids)


def collect_mods(args) -> dict[int, dict]:
    mods: dict[int, dict] = {}
    if args.mods:
        for k, v in json.loads(Path(args.mods).read_text()).items():
            mods[int(k)] = dict(v)
    cur = mods.setdefault(args.index, {})
    if args.cn is not None:
        cur.setdefault("subject", {})["CN"] = args.cn
    if args.subject is not None:
        cur.setdefault("subject", {})["_dn"] = args.subject
    if args.issuer is not None:
        cur.setdefault("issuer", {})["_dn"] = args.issuer
    for name, key in (("serial", "serial"), ("not_before", "not_before"),
                      ("not_after", "not_after"), ("days", "days"), ("key", "key"),
                      ("sig", "signature_hash"), ("set_ku", "key_usage"), ("set_eku", "ext_key_usage")):
        val = getattr(args, name)
        if val is not None:
            cur[key] = val
    if args.clear_san:
        cur["clear_san"] = True
    if args.san:
        cur["san"] = {"mode": "replace", "entries": args.san}
    if args.add_san:
        cur["san"] = {"mode": "add", "entries": args.add_san}
    if args.set_ca is not None:
        cur.setdefault("basic_constraints", {})["ca"] = args.set_ca
    if args.path_len is not None:
        cur.setdefault("basic_constraints", {})["path_length"] = args.path_len
    if args.set_ext:
        cur.setdefault("ext_set", []).extend(args.set_ext)
    if args.del_ext:
        cur.setdefault("ext_delete", []).extend(args.del_ext)
    if not cur:
        mods.pop(args.index, None)
    return mods


def modified_fields(mod: dict) -> list[str]:
    names = {"subject", "issuer", "serial", "not_before", "not_after", "days", "key",
             "signature_hash", "key_usage", "ext_key_usage", "san", "clear_san",
             "basic_constraints", "ext_set", "ext_delete"}
    return sorted(k for k in mod if k in names)


# --------------------------------------------------------------------------- #
# Cloning                                                                     #
# --------------------------------------------------------------------------- #
@dataclass
class Clone:
    cert: x509.Certificate
    key: object
    role: str


@dataclass
class CloneOutcome:
    clones: list[Clone] = field(default_factory=list)
    fake_ca: Clone | None = None


def build_extensions(orig: x509.Certificate, mod: dict, new_key, *,
                     recompute_ski: bool, own_new_ski: bytes, signer_new_ski: bytes | None):
    ext_map: dict[str, tuple[Any, bool]] = {}
    order: list[str] = []
    for ext in orig.extensions:
        ext_map[ext.oid.dotted_string] = (ext.value, ext.critical)
        order.append(ext.oid.dotted_string)
    orig_has_aki = ExtensionOID.AUTHORITY_KEY_IDENTIFIER.dotted_string in ext_map

    def put(oid, value, critical):
        key = oid.dotted_string
        if key not in ext_map:
            order.append(key)
        ext_map[key] = (value, critical)

    if mod.get("clear_san"):
        ext_map.pop(ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string, None)
    san = mod.get("san")
    if san:
        entries = parse_san_entries(list(san["entries"]))
        if san.get("mode") == "add":
            cur = ext_map.get(ExtensionOID.SUBJECT_ALTERNATIVE_NAME.dotted_string)
            if cur:
                entries = list(cur[0]) + entries
        put(ExtensionOID.SUBJECT_ALTERNATIVE_NAME, x509.SubjectAlternativeName(entries), False)

    bc = mod.get("basic_constraints")
    if bc is not None:
        cur = ext_map.get(ExtensionOID.BASIC_CONSTRAINTS.dotted_string)
        ca = bc.get("ca", cur[0].ca if cur else False)
        pl = bc.get("path_length", cur[0].path_length if cur else None)
        put(ExtensionOID.BASIC_CONSTRAINTS, x509.BasicConstraints(ca=ca, path_length=pl if ca else None), True)

    if mod.get("key_usage") is not None:
        put(ExtensionOID.KEY_USAGE, build_key_usage(mod["key_usage"]), True)
    if mod.get("ext_key_usage") is not None:
        put(ExtensionOID.EXTENDED_KEY_USAGE, build_eku(mod["ext_key_usage"]), False)

    for spec in mod.get("ext_set", []):
        if isinstance(spec, dict):
            oid, crit, der = ObjectIdentifier(spec["oid"]), bool(spec.get("critical", False)), bytes.fromhex(spec["der_hex"])
        else:
            parts = str(spec).split(":")
            if len(parts) != 3:
                die(f"--set-ext expects OID:critical:der_hex, got {spec!r}")
            oid, crit, der = ObjectIdentifier(parts[0]), parts[1].lower() in ("1", "true", "yes", "crit"), bytes.fromhex(parts[2])
        put(oid, x509.UnrecognizedExtension(oid, der), crit)

    for spec in mod.get("ext_delete", []):
        oid = str(spec) if "." in str(spec) else short_to_oid(str(spec)).dotted_string
        ext_map.pop(oid, None)
        if oid in order:
            order.remove(oid)

    if recompute_ski:
        if not isinstance(new_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
            put(ExtensionOID.SUBJECT_KEY_IDENTIFIER, x509.SubjectKeyIdentifier(own_new_ski), False)
        if orig_has_aki and signer_new_ski is not None:
            put(ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                x509.AuthorityKeyIdentifier(signer_new_ski, None, None), False)

    return [(ext_map[o][0], ext_map[o][1]) for o in order if o in ext_map]


def build_fake_ca(subject: x509.Name, ski_bytes: bytes | None, nb, na) -> Clone:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    if ski_bytes is None:
        ski_bytes = ski_digest(ca_key.public_key())
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(nb - _dt.timedelta(days=1)).not_valid_after(na + _dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                       content_commitment=False, key_encipherment=False, data_encipherment=False,
                       key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier(ski_bytes), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return Clone(cert, ca_key, "ca")


def clone_chain(certs: list[x509.Certificate], mods: dict[int, dict], *,
                ca_cert, ca_key, keep_issuer_name: bool, force_self_signed: bool,
                fake_issuer_subject: str | None, recompute_ski: bool) -> CloneOutcome:
    n = len(certs)
    subjects, keys, new_skis = [], [], []
    for i, orig in enumerate(certs):
        mod = mods.get(i, {})
        subjects.append(apply_name_overrides(orig.subject, mod.get("subject")))
        k = generate_key_from_spec(mod["key"]) if mod.get("key") else generate_matching_key(orig)
        keys.append(k)
        new_skis.append(ski_digest(k.public_key()))
        log(f"#{i}: {key_details(k.public_key())} key for {subjects[i].rfc4514_string()}")

    clones: list[Clone | None] = [None] * n
    outcome = CloneOutcome()

    for i in range(n - 1, -1, -1):
        orig, mod, new_key = certs[i], mods.get(i, {}), keys[i]
        top_self_signed = (orig.subject == orig.issuer) or force_self_signed

        if i + 1 < n:  # issuer is the next cert up (also cloned)
            issuer_name = subjects[i + 1]
            signer_key = keys[i + 1]
            signer_new_ski = new_skis[i + 1]
        elif top_self_signed:  # self-signed top signs itself
            issuer_name = subjects[i]
            signer_key = new_key
            signer_new_ski = new_skis[i]
        elif ca_cert is not None:  # externally supplied issuing CA
            issuer_name = ca_cert.subject
            signer_key = ca_key
            signer_new_ski = get_ski(ca_cert)
        else:  # fabricate an issuing CA that looks like the real one
            if mod.get("issuer"):
                issuer_name = apply_name_overrides(orig.issuer, mod["issuer"])
            elif fake_issuer_subject:
                issuer_name = parse_dn(fake_issuer_subject)
            else:
                issuer_name = orig.issuer if keep_issuer_name else munge_cn_in_name(orig.issuer)
            # Default: fake CA's SKI matches the child's verbatim AKI so the chain links.
            # With --recompute-ski: derive the CA's SKI from its own key (None) and
            # point the child's AKI at it below.
            ca_ski = None if recompute_ski else get_aki(orig)
            outcome.fake_ca = build_fake_ca(issuer_name, ca_ski,
                                            certs[i].not_valid_before, certs[i].not_valid_after)
            signer_key = outcome.fake_ca.key
            signer_new_ski = get_ski(outcome.fake_ca.cert)
            log(f"#{i}: fabricated issuing CA '{issuer_name.rfc4514_string()}'")

        serial = parse_serial(mod["serial"]) if mod.get("serial") is not None else orig.serial_number
        nb = parse_datetime(mod["not_before"]) if mod.get("not_before") else orig.not_valid_before
        if mod.get("not_after"):
            na = parse_datetime(mod["not_after"])
        elif mod.get("days") is not None:
            na = nb + _dt.timedelta(days=int(mod["days"]))
        else:
            na = orig.not_valid_after

        builder = (x509.CertificateBuilder().subject_name(subjects[i]).issuer_name(issuer_name)
                   .public_key(new_key.public_key()).serial_number(serial)
                   .not_valid_before(nb).not_valid_after(na))
        for value, critical in build_extensions(orig, mod, new_key, recompute_ski=recompute_ski,
                                                 own_new_ski=new_skis[i], signer_new_ski=signer_new_ski):
            try:
                builder = builder.add_extension(value, critical=critical)
            except (ValueError, TypeError) as exc:
                warn(f"#{i}: skipping extension: {exc}")

        hash_alg, rsa_pad = signing_params(orig, signer_key, mod.get("signature_hash"))
        cert = sign_builder(builder, signer_key, hash_alg, rsa_pad)
        role = "leaf" if i == 0 else ("root" if orig.subject == orig.issuer else "intermediate")
        clones[i] = Clone(cert, new_key, role)

    outcome.clones = [c for c in clones if c is not None]
    return outcome


# --------------------------------------------------------------------------- #
# Output, manifest, sanity                                                    #
# --------------------------------------------------------------------------- #
def write_key(path: Path, key) -> None:
    data = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def validate_output_dir(path: Path) -> None:
    if path.is_symlink():
        die(f"--out-dir must not be a symlink: {path}")
    if path.exists():
        if not path.is_dir():
            die(f"--out-dir exists but is not a directory: {path}")
        if any(path.iterdir()):
            die(f"--out-dir must be empty: {path}")


def sanity_check(outcome: CloneOutcome) -> None:
    allc = list(outcome.clones) + ([outcome.fake_ca] if outcome.fake_ca else [])
    by_subject = {c.cert.subject.public_bytes(): c for c in allc}
    for c in allc:
        if public_der(c.cert.public_key()) != public_der(c.key.public_key()):
            die(f"sanity check failed: key/cert mismatch for {c.cert.subject.rfc4514_string()}")
        issuer = by_subject.get(c.cert.issuer.public_bytes())
        if issuer is None:
            continue
        ok, msg = verify_signed_by(c.cert, issuer.cert.public_key())
        if not ok:
            die(f"sanity check failed: {c.cert.subject.rfc4514_string()} does not verify ({msg})")


def write_manifest(path: Path, *, sources, outcome, mods, ca_supplied: bool) -> None:
    manifest = {
        "tool": "clonecert", "tool_version": __version__, "operation": "clone",
        "generated_utc": utcnow().isoformat() + "Z",
        "issuer_mode": "supplied-ca" if ca_supplied else ("generated-ca" if outcome.fake_ca else "self-or-in-chain"),
        "certificates": [],
    }
    for i, (src, cl) in enumerate(zip(sources, outcome.clones)):
        manifest["certificates"].append({
            "index": i, "role": cl.role,
            "source_sha256": src.fingerprint(hashes.SHA256()).hex(),
            "clone_sha256": cl.cert.fingerprint(hashes.SHA256()).hex(),
            "subject": cl.cert.subject.rfc4514_string(),
            "key": key_details(cl.cert.public_key()),
            "modified_fields": modified_fields(mods.get(i, {})),
        })
    manifest["derived_fields"] = ["public_key", "signature"] + (
        ["subject_key_identifier", "authority_key_identifier"] if False else [])
    path.write_text(json.dumps(manifest, indent=2) + "\n")


def emit_clones(outcome: CloneOutcome, sources, mods, outdir: Path, stem: str, ca_supplied: bool) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    chain_pem = bytearray()
    for i, c in enumerate(outcome.clones):
        cert_path = outdir / f"{stem}-{i}-{c.role}.cert.pem"
        key_path = outdir / f"{stem}-{i}-{c.role}.key.pem"
        write_cert(cert_path, c.cert)
        write_key(key_path, c.key)
        chain_pem += c.cert.public_bytes(serialization.Encoding.PEM)
        print(key_path)
        print(cert_path)
    if outcome.fake_ca is not None:
        write_cert(outdir / f"{stem}-generated-ca.cert.pem", outcome.fake_ca.cert)
        write_key(outdir / f"{stem}-generated-ca.key.pem", outcome.fake_ca.key)
        print(outdir / f"{stem}-generated-ca.key.pem")
        print(outdir / f"{stem}-generated-ca.cert.pem")
        warn("the generated issuing CA is not trusted by clients unless explicitly installed")
    (outdir / f"{stem}.chain.pem").write_bytes(bytes(chain_pem))
    write_manifest(outdir / "manifest.json", sources=sources, outcome=outcome,
                   mods=mods, ca_supplied=ca_supplied)


def render_dry_run(certs, mods) -> None:
    print("Dry run - no files written. Planned result:\n")
    for i, orig in enumerate(certs):
        mod = mods.get(i, {})
        role = "leaf" if i == 0 else ("root" if orig.subject == orig.issuer else "intermediate")
        changed = modified_fields(mod) or ["(none - identical to source except key & signature)"]
        print(f"  #{i} ({role}) {orig.subject.rfc4514_string()}")
        print(f"      changes: {', '.join(changed)}")
    print()


# --------------------------------------------------------------------------- #
# Commands: capture / clone                                                   #
# --------------------------------------------------------------------------- #
def load_input(args) -> list[x509.Certificate]:
    """Read certificate(s) from the positional target: a file or [sni@]host:port."""
    target = args.target
    if os.path.exists(target):
        return load_certs_from_bytes(Path(target).read_bytes())
    host, port, sni = parse_hostport(target)
    if getattr(args, "sni", None):
        sni = args.sni
    transport = getattr(args, "transport", "auto") or "auto"
    if transport == "auto":
        transport = transport_for_port(port)
    log(f"connecting to {host}:{port} via {transport}" + (f" (SNI {sni})" if sni else ""))
    return fetch_certs(host, port, sni, args.timeout, transport, getattr(args, "chain", False))


def cmd_clone(args) -> int:
    if bool(args.ca_cert) ^ bool(args.ca_key):
        die("--ca-cert and --ca-key must be given together")
    if args.ca_cert and args.fake_issuer_subject:
        die("--fake-issuer-subject cannot be combined with a supplied CA")
    if args.ca_cert and args.self_signed:
        die("--self-signed cannot be combined with a supplied CA")
    ca_cert = ca_key = None
    if args.ca_cert:
        ca_cert = x509.load_pem_x509_certificate(Path(args.ca_cert).read_bytes())
        ca_key = serialization.load_pem_private_key(Path(args.ca_key).read_bytes(), password=None)
        if public_der(ca_cert.public_key()) != public_der(ca_key.public_key()):
            die("--ca-cert and --ca-key do not match")

    certs = load_input(args)
    certs = order_chain(certs) if args.chain else certs[:1]
    mods = collect_mods(args)
    if mods and max(mods) >= len(certs):
        die(f"--index/--mods references cert #{max(mods)} but only {len(certs)} loaded "
            f"(did you forget --chain?)")

    if args.dry_run:
        render_dry_run(certs, mods)
        return 0

    outdir = Path(args.out_dir)
    validate_output_dir(outdir)
    outcome = clone_chain(certs, mods, ca_cert=ca_cert, ca_key=ca_key,
                          keep_issuer_name=args.keep_issuer_name, force_self_signed=args.self_signed,
                          fake_issuer_subject=args.fake_issuer_subject, recompute_ski=args.recompute_ski)
    sanity_check(outcome)
    label = args.target if not os.path.exists(args.target) else Path(args.target).name
    emit_clones(outcome, certs, mods, outdir, safe_stem(label), ca_supplied=ca_cert is not None)
    return 0


# --------------------------------------------------------------------------- #
# Self-test (offline, ephemeral)                                              #
# --------------------------------------------------------------------------- #
def cmd_selftest(args) -> int:
    import tempfile

    passed = failed = 0

    def check(name, cond, detail=""):
        nonlocal passed, failed
        if cond:
            passed += 1
            print(f"PASS {name}")
        else:
            failed += 1
            print(f"FAIL {name}: {detail}", file=sys.stderr)

    nb, na = _dt.datetime(2024, 1, 1), _dt.datetime(2032, 1, 1)

    def mkname(cn, o="Selftest Org"):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                          x509.NameAttribute(NameOID.ORGANIZATION_NAME, o)])

    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = (x509.CertificateBuilder().subject_name(mkname("Selftest Root")).issuer_name(mkname("Selftest Root"))
            .public_key(rk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(rk.public_key()), False)
            .sign(rk, hashes.SHA256()))
    ik = ec.generate_private_key(ec.SECP384R1())
    inter = (x509.CertificateBuilder().subject_name(mkname("Selftest Intermediate")).issuer_name(root.subject)
             .public_key(ik.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(nb).not_valid_after(na)
             .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(ik.public_key()), False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(rk.public_key()), False)
             .sign(rk, hashes.SHA256()))
    lk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf = (x509.CertificateBuilder().subject_name(mkname("svc.lab.test", "Lab")).issuer_name(inter.subject)
            .public_key(lk.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("svc.lab.test"),
                           x509.IPAddress(ipaddress.ip_address("10.0.0.9"))]), False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(lk.public_key()), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ik.public_key()), False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .sign(ik, hashes.SHA256()))

    def pem(*cs):
        return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in cs)

    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        (tdp / "chain.pem").write_bytes(pem(leaf, inter, root))
        (tdp / "leaf.pem").write_bytes(pem(leaf))

        chain = order_chain(load_certs_from_bytes((tdp / "chain.pem").read_bytes()))
        check("T01-order", [c.subject.rfc4514_string() for c in chain][0].startswith("O=Lab") or "svc.lab.test" in chain[0].subject.rfc4514_string(), "leaf not first")

        # validate original
        rc = _run_validate(chain)
        check("T02-validate-source", rc == 0, "source chain did not validate")

        # clone whole chain, verbatim
        out1 = clone_chain(chain, {}, ca_cert=None, ca_key=None, keep_issuer_name=False,
                           force_self_signed=False, fake_issuer_subject=None, recompute_ski=False)
        sanity_check(out1)
        check("T03-clone-chain-sanity", True)
        rc = _run_validate(out1.clones and [c.cert for c in out1.clones])
        check("T04-clone-chain-validates", rc == 0, "cloned chain failed to validate")
        # leaf identical params (serial, SAN, subject) except key
        d_src, d_clone = describe_cert(leaf, 0), describe_cert(out1.clones[0].cert, 0)
        same = all(d_src[k] == d_clone[k] for k in ("serial", "subject", "issuer", "not_before", "not_after"))
        same_san = d_src["extensions"].get("subjectAltName") == d_clone["extensions"].get("subjectAltName")
        check("T05-leaf-identical", same and same_san, "leaf parameters drifted")
        check("T06-key-changed", public_der(leaf.public_key()) != public_der(out1.clones[0].cert.public_key()), "key not regenerated")

        # modify intermediate (index 1) subject + recompute ski, still valid
        out2 = clone_chain(chain, {1: {"subject": {"CN": "Evil Intermediate"}}}, ca_cert=None, ca_key=None,
                           keep_issuer_name=False, force_self_signed=False, fake_issuer_subject=None,
                           recompute_ski=True)
        sanity_check(out2)
        rc = _run_validate([c.cert for c in out2.clones])
        inter_cn = out2.clones[1].cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        check("T07-modify-intermediate", rc == 0 and inter_cn == "Evil Intermediate", "intermediate mod broke chain")
        check("T08-child-issuer-follows", out2.clones[0].cert.issuer == out2.clones[1].cert.subject, "leaf issuer did not follow parent subject")

        # leaf-only clone of a CA-signed cert -> fabricated CA
        out3 = clone_chain([leaf], {}, ca_cert=None, ca_key=None, keep_issuer_name=False,
                           force_self_signed=False, fake_issuer_subject=None, recompute_ski=False)
        sanity_check(out3)
        check("T09-generated-ca", out3.fake_ca is not None, "no fake CA generated for CA-signed leaf")

        # modify ANY parameter incl arbitrary extension + new key type + IP SAN
        mod = {0: {"key": "ec:secp256r1", "serial": "random", "days": 30, "not_before": "now",
                   "san": {"mode": "replace", "entries": ["dns:evil.test", "ip:127.0.0.1"]},
                   "signature_hash": "sha512",
                   "ext_set": ["2.5.29.99:false:0403010203"]}}
        out4 = clone_chain([leaf], mod, ca_cert=None, ca_key=None, keep_issuer_name=False,
                           force_self_signed=False, fake_issuer_subject=None, recompute_ski=True)
        sanity_check(out4)
        c4 = out4.clones[0].cert
        san_val = describe_cert(c4, 0)["extensions"].get("subjectAltName", {}).get("value", {})
        has_ip = "ip" in san_val
        has_ext = any(e.oid.dotted_string == "2.5.29.99" for e in c4.extensions)
        check("T10-modify-all",
              key_type_name(c4.public_key()) == "ec" and has_ip and has_ext
              and c4.signature_hash_algorithm.name == "sha512",
              "parameter modifications not applied")

        # self-signed clone
        sk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ss = (x509.CertificateBuilder().subject_name(mkname("selfsigned.test")).issuer_name(mkname("selfsigned.test"))
              .public_key(sk.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(nb).not_valid_after(na)
              .add_extension(x509.SubjectAlternativeName([x509.DNSName("selfsigned.test")]), False)
              .sign(sk, hashes.SHA256()))
        out5 = clone_chain([ss], {}, ca_cert=None, ca_key=None, keep_issuer_name=False,
                           force_self_signed=False, fake_issuer_subject=None, recompute_ski=False)
        sanity_check(out5)
        c5 = out5.clones[0].cert
        check("T11-self-signed", c5.subject == c5.issuer and out5.fake_ca is None, "self-signed clone wrong")

        # supplied-CA reissue
        out6 = clone_chain([leaf], {}, ca_cert=inter, ca_key=ik, keep_issuer_name=False,
                           force_self_signed=False, fake_issuer_subject=None, recompute_ski=False)
        sanity_check(out6)
        ok, _ = verify_signed_by(out6.clones[0].cert, inter.public_key())
        check("T12-supplied-ca", ok and out6.fake_ca is None, "supplied-CA reissue failed to verify")

    print(f"\nSUMMARY {passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


def _run_validate(certs) -> int:
    if not certs:
        return 1
    certs = order_chain(certs)
    all_ok = True
    for i, cert in enumerate(certs):
        parent = certs[i + 1] if i + 1 < len(certs) else (cert if cert.subject == cert.issuer else None)
        if parent is None:
            continue
        ok, _ = verify_signed_by(cert, parent.public_key())
        all_ok = all_ok and ok and (cert.issuer == parent.subject)
    return 0 if all_ok else 1


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #
def add_input_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("target", metavar="host:port|file",
                   help="a live TLS endpoint '[sni@]host:port' or a PEM/DER file/bundle")
    p.add_argument("--sni", help="override the SNI sent to a live endpoint")
    p.add_argument("--timeout", type=float, default=10.0, help="connection timeout seconds (default 10)")
    p.add_argument("--chain", action="store_true", help="operate on the whole chain, not just the leaf")
    p.add_argument("--transport", default="auto",
                   choices=["auto", "tls", "starttls-smtp", "starttls-imap", "starttls-pop3",
                            "starttls-ldap", "starttls-xmpp", "dtls"],
                   help="transport for a live endpoint (default: auto by port)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="clonecert", description=__doc__.splitlines()[0],
                                     epilog=DISCLAIMER, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"clonecert {__version__}")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress on stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    pi = sub.add_parser("identify", help="print every modifiable parameter of a cert/chain")
    add_input_args(pi)
    pi.add_argument("--json", action="store_true")
    pi.set_defaults(func=cmd_identify)

    pv = sub.add_parser("validate", help="verify a chain is internally consistent")
    add_input_args(pv)
    pv.set_defaults(func=cmd_validate)

    pc = sub.add_parser("clone", help="clone a certificate or a whole chain")
    add_input_args(pc)
    pc.add_argument("-d", "--out-dir", required=True, help="output directory (must be empty)")
    pc.add_argument("--ca-cert", help="PEM CA cert to sign under (needs --ca-key)")
    pc.add_argument("--ca-key", help="PEM CA key matching --ca-cert")
    pc.add_argument("--fake-issuer-subject", help="DN for the fabricated issuing CA")
    pc.add_argument("--keep-issuer-name", action="store_true", help="do not munge a fabricated issuer name")
    pc.add_argument("--self-signed", action="store_true", help="force self-signed output for the top cert")
    pc.add_argument("--recompute-ski", action="store_true",
                    help="recompute SKI/AKI from the new keys (default: keep identical to source)")
    pc.add_argument("--dry-run", action="store_true", help="show the plan, write nothing")
    pc.add_argument("--index", type=int, default=0, metavar="N",
                    help="which cert the modify flags below target (default 0 = leaf)")
    pc.add_argument("--cn"); pc.add_argument("--subject"); pc.add_argument("--issuer")
    pc.add_argument("--serial", help="int, 0x-hex, or 'random'")
    pc.add_argument("--not-before"); pc.add_argument("--not-after")
    pc.add_argument("--days", type=int); pc.add_argument("--key")
    pc.add_argument("--sig", help="signature hash: sha256/sha384/sha512/sha1/md5")
    pc.add_argument("--san", action="append"); pc.add_argument("--add-san", action="append")
    pc.add_argument("--clear-san", action="store_true")
    pc.add_argument("--set-ca", type=lambda v: str(v).lower() in ("1", "true", "yes", "on"), metavar="BOOL")
    pc.add_argument("--path-len", type=int)
    pc.add_argument("--set-ku", help="key usage list, e.g. digitalSignature,keyEncipherment")
    pc.add_argument("--set-eku", help="extended key usage list, e.g. serverAuth,clientAuth")
    pc.add_argument("--set-ext", action="append", metavar="OID:CRIT:HEX")
    pc.add_argument("--del-ext", action="append", metavar="OID")
    pc.add_argument("--mods", metavar="FILE", help="JSON {index: {param: value}} for full control")
    pc.set_defaults(func=cmd_clone)

    pst = sub.add_parser("selftest", help="run offline regression tests")
    pst.set_defaults(func=cmd_selftest)
    return parser


def main(argv: list[str] | None = None) -> int:
    global QUIET
    args = build_parser().parse_args(argv)
    QUIET = args.quiet
    if not QUIET and args.command != "selftest":
        warn(DISCLAIMER)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
