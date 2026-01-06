# pki/make_certs.py
from __future__ import annotations

import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


BASE_DIR = Path(__file__).resolve().parents[1]  # pki_mtls_demo/
OUT_DIR = BASE_DIR / "artifacts"
OUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Helpers ---

def _write_pem(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    print(f"[OK] wrote {path}")

def gen_rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

def pem_cert(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def name(common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PKI mTLS Demo"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

def build_ca(common_name: str, days_valid: int = 3650) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = gen_rsa_key()
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days_valid))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=hashes.SHA256())
    )
    return key, cert

def sign_leaf_cert(
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    common_name: str,
    *,
    is_server: bool,
    san_dns: list[str] | None = None,
    not_before: dt.datetime | None = None,
    not_after: dt.datetime | None = None,
) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = gen_rsa_key()
    now = dt.datetime.now(dt.timezone.utc)
    nb = not_before or (now - dt.timedelta(minutes=1))
    na = not_after or (now + dt.timedelta(days=365))

    builder = (
        x509.CertificateBuilder()
        .subject_name(name(common_name))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb)
        .not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,   # OK for TLS RSA key exchange; also fine with ECDHE
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,      # often used with ECDHE
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    if is_server:
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
    else:
        eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

    builder = builder.add_extension(eku, critical=False)

    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(d) for d in san_dns]),
            critical=False
        )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return key, cert


def main() -> None:
    # --- Main CA ---
    ca_key, ca_cert = build_ca("Demo Root CA")
    _write_pem(OUT_DIR / "ca.key", pem_key(ca_key))
    _write_pem(OUT_DIR / "ca.crt", pem_cert(ca_cert))

    # --- Server cert signed by main CA ---
    srv_key, srv_cert = sign_leaf_cert(
        ca_key, ca_cert,
        "demo-server",
        is_server=True,
        san_dns=["localhost"]
    )
    _write_pem(OUT_DIR / "server.key", pem_key(srv_key))
    _write_pem(OUT_DIR / "server.crt", pem_cert(srv_cert))

    # --- Good client cert signed by main CA ---
    cl_key, cl_cert = sign_leaf_cert(
        ca_key, ca_cert,
        "good-client",
        is_server=False
    )
    _write_pem(OUT_DIR / "client_good.key", pem_key(cl_key))
    _write_pem(OUT_DIR / "client_good.crt", pem_cert(cl_cert))
     # --- Second good client cert signed by main CA ---
    cl2_key, cl2_cert = sign_leaf_cert(
        ca_key, ca_cert,
        "second-client",
        is_server=False
    )
    _write_pem(OUT_DIR / "client_second.key", pem_key(cl2_key))
    _write_pem(OUT_DIR / "client_second.crt", pem_cert(cl2_cert))

    # --- Expired client cert (already expired) signed by main CA ---
    now = dt.datetime.now(dt.timezone.utc)
    expired_before = now - dt.timedelta(days=10)
    expired_after = now - dt.timedelta(days=1)  # already expired
    ex_key, ex_cert = sign_leaf_cert(
        ca_key, ca_cert,
        "expired-client",
        is_server=False,
        not_before=expired_before,
        not_after=expired_after
    )
    _write_pem(OUT_DIR / "client_expired.key", pem_key(ex_key))
    _write_pem(OUT_DIR / "client_expired.crt", pem_cert(ex_cert))

    # --- Foreign CA + client signed by foreign CA (unknown CA scenario) ---
    fca_key, fca_cert = build_ca("Foreign Root CA")
    _write_pem(OUT_DIR / "foreign_ca.key", pem_key(fca_key))
    _write_pem(OUT_DIR / "foreign_ca.crt", pem_cert(fca_cert))

    fcl_key, fcl_cert = sign_leaf_cert(
        fca_key, fca_cert,
        "foreign-client",
        is_server=False
    )
    _write_pem(OUT_DIR / "client_foreign.key", pem_key(fcl_key))
    _write_pem(OUT_DIR / "client_foreign.crt", pem_cert(fcl_cert))

    print("\nGotowe. Pliki są w:", OUT_DIR)

if __name__ == "__main__":
    main()
