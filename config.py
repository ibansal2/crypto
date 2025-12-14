# All constants used throughout the code

from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "secure_docs.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"
PKI_DIR = BASE_DIR / "pki"
ROOT_KEY_PATH = PKI_DIR / "root_ca_key.pem"
ROOT_CERT_PATH = PKI_DIR / "root_ca_cert.pem"
FRONTEND_DIR = BASE_DIR / "frontend"
SESSION_TTL_SECONDS = 3600
