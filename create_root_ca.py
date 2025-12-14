# Creates a root CA key and self-signed certificate for signing other certificates throughout the project

import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

# Defines the filesystem paths where the Master Key and Certificate will be stored.
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")
ROOT_KEY_PATH = os.path.join(PKI_DIR, "root_ca_key.pem")
ROOT_CERT_PATH = os.path.join(PKI_DIR, "root_ca_cert.pem")


def main() -> None:
    os.makedirs(PKI_DIR, exist_ok=True)
    if os.path.exists(ROOT_KEY_PATH) or os.path.exists(ROOT_CERT_PATH):
        raise SystemExit("Root CA artifacts already exist. Remove them if you need to re-create the PKI.")

    private_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureDocs Root"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureDocs Root CA"),
    ])
    now = datetime.utcnow()
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, algorithm=None)
    )

    with open(ROOT_KEY_PATH, "wb") as key_file:
        key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(ROOT_CERT_PATH, "wb") as cert_file:
        cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

    print(f"Created new Root CA at {PKI_DIR}")


if __name__ == "__main__":
    main()
