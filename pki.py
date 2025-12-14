# Manages the PKI and certificates for the app 

from __future__ import annotations

from datetime import timedelta
from typing import Optional

from fastapi import HTTPException
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

import config
from crypto_utils import utcnow, b64decode_data

ROOT_CA_PRIVATE_KEY: Optional[ed25519.Ed25519PrivateKey] = None
ROOT_CA_CERT: Optional[x509.Certificate] = None

# Load root CA key and certificate from disk
def load_root_ca_material() -> None:
    global ROOT_CA_PRIVATE_KEY, ROOT_CA_CERT
    if config.ROOT_KEY_PATH.exists() and config.ROOT_CERT_PATH.exists():
        with open(config.ROOT_KEY_PATH, "rb") as key_file:
            ROOT_CA_PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None)
        with open(config.ROOT_CERT_PATH, "rb") as cert_file:
            ROOT_CA_CERT = x509.load_pem_x509_certificate(cert_file.read())
    else:
        ROOT_CA_PRIVATE_KEY = None
        ROOT_CA_CERT = None

# Tries to load variables if the variables are empty, raises if still not ready (means missing files)
def ensure_root_ready() -> None:
    if ROOT_CA_PRIVATE_KEY is None or ROOT_CA_CERT is None:
        load_root_ca_material()
    if ROOT_CA_PRIVATE_KEY is None or ROOT_CA_CERT is None:
        raise HTTPException(status_code=500, detail="Root CA is missing. Run create_root_ca.py.")

# Turns a public key into a signed certificate for a given username
def issue_certificate(username: str, public_key: ed25519.Ed25519PublicKey) -> bytes:
    ensure_root_ready()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDocs Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]
    )
    now = utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ROOT_CA_CERT.subject)  # type: ignore[union-attr]
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365 * 5))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ROOT_CA_PRIVATE_KEY, algorithm=None)  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)

# Checks if a document was signed by the person claiming to be its owner, and if the person is trusted in the system
def verify_document_signature(payload: bytes, signature_b64: str, signer_cert_pem: str) -> bool:
    ensure_root_ready()
    signer_cert = x509.load_pem_x509_certificate(signer_cert_pem.encode("utf-8"))
    now = utcnow()
    if now < signer_cert.not_valid_before or now > signer_cert.not_valid_after:
        return False
    ROOT_CA_CERT.public_key().verify(signer_cert.signature, signer_cert.tbs_certificate_bytes)  # type: ignore[union-attr]
    try:
        signer_cert.public_key().verify(b64decode_data(signature_b64), payload)
        return True
    except InvalidSignature:
        return False
