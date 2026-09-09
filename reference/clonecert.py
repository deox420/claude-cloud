#!/usr/bin/env python3
"""clonecert - clone an X.509 certificate for authorized TLS-interception testing.

An improved, robust reimplementation of SySS-Research/clone-cert
(Adrian Vollmer, SySS GmbH). Instead of doing byte surgery on the hex-encoded
DER with `sed` (fragile and limited to RSA/EC), this parses the certificate
properly with `cryptography` and rebuilds an equivalent certificate:

  * every field (subject, validity, serial, extensions/SANs) is copied verbatim,
  * the public key is swapped for a freshly generated key of the same type,
  * the certificate is re-signed by a generated (or supplied) issuing CA.

Supported public-key types: RSA, EC, Ed25519, Ed448, DSA.

LEGAL / ETHICAL USE ONLY
------------------------
Cloning certificates is only appropriate against systems you own or are
explicitly authorized to test (e.g. a documented penetration-testing
engagement, a lab, or a CTF). The classic use case is demonstrating that
self-signed or blindly-trusted certificates provide no real protection.
Using this to impersonate a service you are not authorized to test is very
likely illegal. You are responsible for how you use it.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import os
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from pathlib import Path

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
    from cryptography.x509.oid import ExtensionOID, NameOID, SignatureAlgorithmOID
except ImportError:  # pragma: no cover - dependency guard
    sys.stderr.write(
        "error: the 'cryptography' package is required. Install it with:\n"
        "    python3 -m pip install cryptography\n"
    )
    raise SystemExit(2)


DISCLAIMER = (
    "clonecert is for authorized security testing and education only. "
    "Only clone certificates of systems you own or are explicitly permitted "
    "to test."
)


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #
def log(msg: str, *, verbose: bool = True) -> None:
    if verbose:
        sys.stderr.write(f"[*] {msg}\n")


def die(msg: str) -> "NoReturn":  # type: ignore[name-defined]
    sys.stderr.write(f"[!] {msg}\n")
    raise SystemExit(1)


def safe_name(value: str) -> str:
    """Turn an arbitrary target string into a safe output-filename stem.

    Prevents path traversal / surprises from hostile SNI or file names.
    """
    stem = re.sub(r"[^A-Za-z0-9._-]", "_", value)
    stem = stem.strip("._") or "cert"
    return stem[:96]


@dataclass
class Target:
    is_file: bool
    path: Path | None = None
    host: str | None = None
    port: int | None = None
    sni: str | None = None

    @property
    def label(self) -> str:
        if self.is_file:
            return self.path.name  # type: ignore[union-attr]
        return f"{self.host}_{self.port}"


def parse_target(arg: str) -> Target:
    """Parse `[sni@]host:port` or a path to a PEM/DER certificate file."""
    if os.path.exists(arg):
        return Target(is_file=True, path=Path(arg))

    sni = None
    hostport = arg
    if "@" in arg:
        sni, hostport = arg.split("@", 1)

    if ":" not in hostport:
        die(
            "target must be a certificate file or 'host:port' "
            "(optionally 'sni@host:port')"
        )

    host, _, port_s = hostport.rpartition(":")
    host = host.strip("[]")  # allow bracketed IPv6
    try:
        port = int(port_s)
    except ValueError:
        die(f"invalid port: {port_s!r}")
    if not (0 < port < 65536):
        die(f"port out of range: {port}")

    return Target(is_file=False, host=host, port=port, sni=sni or host)


# --------------------------------------------------------------------------- #
# Certificate retrieval                                                        #
# --------------------------------------------------------------------------- #
def fetch_leaf_der(host: str, port: int, sni: str, timeout: float) -> bytes:
    """Grab the leaf certificate from a TLS server without validating it.

    Validation is intentionally disabled: the whole point is to clone certs
    that may be self-signed, expired, or otherwise untrusted.
    """
    ctx = ssl._create_unverified_context()  # noqa: S323 - deliberate, see docstring
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
    return der


def load_certificates(data: bytes) -> list[x509.Certificate]:
    """Load one or more certificates from PEM (possibly a bundle) or DER."""
    text = data.lstrip()
    certs: list[x509.Certificate] = []
    if text.startswith(b"-----BEGIN"):
        for block in re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            data,
            re.DOTALL,
        ):
            certs.append(x509.load_pem_x509_certificate(block))
    else:
        certs.append(x509.load_der_x509_certificate(data))
    if not certs:
        die("no certificate found in input")
    return certs


# --------------------------------------------------------------------------- #
# Key generation                                                               #
# --------------------------------------------------------------------------- #
def generate_matching_key(cert: x509.Certificate):
    """Generate a fresh private key of the same type/size/curve as `cert`."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return rsa.generate_private_key(public_exponent=65537, key_size=pub.key_size)
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(pub.curve)
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return ed25519.Ed25519PrivateKey.generate()
    if isinstance(pub, ed448.Ed448PublicKey):
        return ed448.Ed448PrivateKey.generate()
    if isinstance(pub, dsa.DSAPublicKey):
        return dsa.generate_private_key(key_size=pub.key_size)
    die(f"unsupported public key type: {type(pub).__name__}")


def signing_params(cert: x509.Certificate, signer_key):
    """Return (hash_algorithm, rsa_padding) to re-sign like the original."""
    # Ed25519/Ed448 use no external hash.
    if isinstance(signer_key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        return None, None

    hash_alg = cert.signature_hash_algorithm or hashes.SHA256()

    rsa_pad = None
    if isinstance(signer_key, rsa.RSAPrivateKey):
        if cert.signature_algorithm_oid == SignatureAlgorithmOID.RSASSA_PSS:
            rsa_pad = padding.PSS(
                mgf=padding.MGF1(hash_alg), salt_length=padding.PSS.DIGEST_LENGTH
            )
        else:
            rsa_pad = padding.PKCS1v15()
    return hash_alg, rsa_pad


def _sign(builder: x509.CertificateBuilder, key, hash_alg, rsa_pad):
    """Sign, passing rsa_padding only when supported and relevant."""
    if rsa_pad is not None:
        try:
            return builder.sign(key, hash_alg, rsa_padding=rsa_pad)
        except TypeError:
            # Older cryptography without the rsa_padding kwarg -> PKCS#1 v1.5.
            pass
    return builder.sign(key, hash_alg)


# --------------------------------------------------------------------------- #
# Issuer-name munging (mirrors the original's homoglyph trick)                 #
# --------------------------------------------------------------------------- #
def munge_cn(value: str) -> str:
    """Swap one character for a look-alike so the CA name looks inconspicuous.

    This is what makes a casual observer not notice the issuer changed. It is a
    demonstration of why users must not blindly trust certificate chains.
    """
    swaps = [("I", "l"), ("l", "I"), ("O", "0"), ("0", "O")]
    for src, dst in swaps:
        if src in value:
            return value.replace(src, dst, 1)
    if value:
        return value[:-1] + ("_" if value[-1] != "_" else "-")
    return value


def rebuild_name(name: x509.Name, munge: bool) -> x509.Name:
    new_rdns = []
    for rdn in name.rdns:
        attrs = []
        for att in rdn:
            value = att.value
            if munge and att.oid == NameOID.COMMON_NAME and isinstance(value, str):
                value = munge_cn(value)
            attrs.append(x509.NameAttribute(att.oid, value))
        new_rdns.append(x509.RelativeDistinguishedName(attrs))
    return x509.Name(new_rdns)


# --------------------------------------------------------------------------- #
# CA generation                                                                #
# --------------------------------------------------------------------------- #
def get_authority_key_id(cert: x509.Certificate) -> bytes | None:
    try:
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
        return aki.key_identifier
    except x509.ExtensionNotFound:
        return None


def build_fake_ca(subject: x509.Name, key_id: bytes | None, not_before, not_after):
    """Create a self-signed issuing CA whose subject matches `subject`.

    Its SubjectKeyIdentifier is forced to `key_id` (the clone target's
    AuthorityKeyIdentifier) so the cloned certificate still chains to it.
    """
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ski = (
        x509.SubjectKeyIdentifier(key_id)
        if key_id
        else x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before - _dt.timedelta(days=1))
        .not_valid_after(not_after + _dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


# --------------------------------------------------------------------------- #
# Core cloning                                                                 #
# --------------------------------------------------------------------------- #
@dataclass
class CloneResult:
    cert: x509.Certificate
    key: object
    ca_cert: x509.Certificate | None
    ca_key: object | None
    self_signed: bool


def clone_certificate(
    orig: x509.Certificate,
    *,
    issuer_cert: x509.Certificate | None,
    issuer_key: object | None,
    keep_issuer_name: bool,
    keep_serial: bool,
    verbose: bool,
) -> CloneResult:
    self_signed = orig.subject == orig.issuer
    log(f"self-signed: {self_signed}", verbose=verbose)

    new_key = generate_matching_key(orig)
    log(f"generated new {type(orig.public_key()).__name__} key", verbose=verbose)

    munge = (not self_signed) and (not keep_issuer_name)
    new_issuer = rebuild_name(orig.issuer, munge=munge)

    if not self_signed and not keep_serial:
        serial = x509.random_serial_number()
    else:
        serial = orig.serial_number

    # Decide who signs the clone.
    generated_ca_cert = generated_ca_key = None
    if self_signed:
        signer_key = new_key  # a self-signed clone signs itself with its new key
        new_issuer = orig.subject  # keep issuer == subject
    elif issuer_cert is not None and issuer_key is not None:
        signer_key = issuer_key
        new_issuer = issuer_cert.subject  # must match provided CA subject
        log("signing with provided issuing CA", verbose=verbose)
    else:
        key_id = get_authority_key_id(orig)
        generated_ca_key, generated_ca_cert = build_fake_ca(
            new_issuer, key_id, orig.not_valid_before, orig.not_valid_after
        )
        signer_key = generated_ca_key
        log("generated a fake issuing CA", verbose=verbose)

    builder = (
        x509.CertificateBuilder()
        .subject_name(orig.subject)
        .issuer_name(new_issuer)
        .public_key(new_key.public_key())
        .serial_number(serial)
        .not_valid_before(orig.not_valid_before)
        .not_valid_after(orig.not_valid_after)
    )

    # Copy every extension verbatim (SANs, EKU, policies, unknown ones, ...).
    for ext in orig.extensions:
        try:
            builder = builder.add_extension(ext.value, critical=ext.critical)
        except (ValueError, TypeError) as exc:
            log(f"skipping extension {ext.oid.dotted_string}: {exc}", verbose=verbose)

    hash_alg, rsa_pad = signing_params(orig, signer_key)
    cloned = _sign(builder, signer_key, hash_alg, rsa_pad)

    return CloneResult(
        cert=cloned,
        key=new_key,
        ca_cert=generated_ca_cert if not self_signed else None,
        ca_key=generated_ca_key if not self_signed else None,
        self_signed=self_signed,
    )


# --------------------------------------------------------------------------- #
# Sanity checks                                                                #
# --------------------------------------------------------------------------- #
def public_bytes(pub) -> bytes:
    return pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sanity_check(result: CloneResult) -> None:
    # 1. private key matches the certificate's public key
    if public_bytes(result.cert.public_key()) != public_bytes(
        result.key.public_key()
    ):
        die("sanity check failed: key does not match cloned certificate")

    # 2. cloned cert verifies against its issuer's public key
    issuer_cert = result.ca_cert if result.ca_cert is not None else result.cert
    verify_signed_by(result.cert, issuer_cert.public_key())


def verify_signed_by(cert: x509.Certificate, issuer_pub) -> None:
    tbs = cert.tbs_certificate_bytes
    sig = cert.signature
    try:
        if isinstance(issuer_pub, rsa.RSAPublicKey):
            pad = (
                padding.PSS(
                    mgf=padding.MGF1(cert.signature_hash_algorithm),
                    salt_length=padding.PSS.AUTO,
                )
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
            log("cannot verify signature for this key type; skipping check")
            return
    except Exception as exc:  # noqa: BLE001 - surface any verification failure
        die(f"sanity check failed: signature does not verify ({exc})")


# --------------------------------------------------------------------------- #
# Output                                                                       #
# --------------------------------------------------------------------------- #
def write_key(path: Path, key) -> None:
    data = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Create the file with 0600 from the start to avoid a world-readable window.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def write_cert(path: Path, cert: x509.Certificate) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def emit(result: CloneResult, outdir: Path, stem: str, verbose: bool) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    cert_path = outdir / f"{stem}.cert.pem"
    key_path = outdir / f"{stem}.key.pem"
    write_cert(cert_path, result.cert)
    write_key(key_path, result.key)

    if result.ca_cert is not None and result.ca_key is not None:
        ca_cert_path = outdir / f"{stem}.ca.cert.pem"
        ca_key_path = outdir / f"{stem}.ca.key.pem"
        write_cert(ca_cert_path, result.ca_cert)
        write_key(ca_key_path, result.ca_key)
        log(f"fake CA cert: {ca_cert_path}", verbose=verbose)
        log(f"fake CA key : {ca_key_path}", verbose=verbose)

    # The script's machine-readable output: the clone key and cert paths.
    print(key_path)
    print(cert_path)


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="clonecert",
        description="Clone an X.509 certificate (authorized testing only).",
        epilog=DISCLAIMER,
    )
    p.add_argument(
        "target",
        help="'[sni@]host:port' of a TLS server, or a path to a PEM/DER certificate",
    )
    p.add_argument(
        "-d",
        "--directory",
        default=".",
        type=Path,
        help="output directory (default: current directory)",
    )
    p.add_argument(
        "--ca-cert",
        type=Path,
        help="PEM CA certificate to sign the clone with (requires --ca-key)",
    )
    p.add_argument(
        "--ca-key",
        type=Path,
        help="PEM CA private key matching --ca-cert",
    )
    p.add_argument(
        "--keep-issuer-name",
        action="store_true",
        help="do not munge the issuer CN (default munges it for non-self-signed certs)",
    )
    p.add_argument(
        "--keep-serial",
        action="store_true",
        help="keep the original serial number (default randomizes it)",
    )
    p.add_argument(
        "--chain",
        action="store_true",
        help="clone every certificate in the input/chain, not just the leaf",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="TLS connection timeout in seconds (default: 10)",
    )
    p.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="suppress progress messages on stderr",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="acknowledge authorized use and skip the interactive confirmation",
    )
    return p


def confirm_authorization(assume_yes: bool) -> None:
    if assume_yes or not sys.stdin.isatty():
        return
    sys.stderr.write(DISCLAIMER + "\n")
    answer = input("Do you have authorization to clone this certificate? [y/N] ")
    if answer.strip().lower() not in {"y", "yes"}:
        die("aborted: authorization not confirmed")


def load_issuer(args) -> tuple[x509.Certificate | None, object | None]:
    if bool(args.ca_cert) ^ bool(args.ca_key):
        die("--ca-cert and --ca-key must be provided together")
    if not args.ca_cert:
        return None, None
    issuer_cert = x509.load_pem_x509_certificate(args.ca_cert.read_bytes())
    issuer_key = serialization.load_pem_private_key(
        args.ca_key.read_bytes(), password=None
    )
    return issuer_cert, issuer_key


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    verbose = not args.quiet
    confirm_authorization(args.yes)

    target = parse_target(args.target)
    issuer_cert, issuer_key = load_issuer(args)

    if target.is_file:
        certs = load_certificates(target.path.read_bytes())
    else:
        der = fetch_leaf_der(target.host, target.port, target.sni, args.timeout)
        certs = load_certificates(der)

    if not args.chain:
        certs = certs[:1]

    stem_base = safe_name(target.label)
    for idx, orig in enumerate(certs):
        result = clone_certificate(
            orig,
            issuer_cert=issuer_cert,
            issuer_key=issuer_key,
            keep_issuer_name=args.keep_issuer_name,
            keep_serial=args.keep_serial,
            verbose=verbose,
        )
        sanity_check(result)
        stem = stem_base if len(certs) == 1 else f"{stem_base}_{idx}"
        emit(result, args.directory, stem, verbose)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
