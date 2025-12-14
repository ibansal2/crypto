# Contains all of the cryptography-focused utility functions used in the project for encryption, decryption, key management, and hashing

from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from typing import Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


def b64encode_data(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64decode_data(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def utcnow() -> datetime:
    return datetime.utcnow()


def hash_password(password: str, salt: bytes, params: Dict[str, int]) -> bytes:
    kdf = Scrypt(salt=salt, length=64, n=params["n"], r=params["r"], p=params["p"])
    return kdf.derive(password.encode("utf-8"))


def verify_password(password: str, password_hash: bytes, salt: bytes, params: Dict[str, int]) -> bool:
    kdf = Scrypt(salt=salt, length=64, n=params["n"], r=params["r"], p=params["p"])
    try:
        kdf.verify(password.encode("utf-8"), password_hash)
        return True
    except Exception:
        return False


def derive_master_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000)
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(private_data: bytes, master_key: bytes) -> str:
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, private_data, None)
    return json.dumps({"nonce": b64encode_data(nonce), "ciphertext": b64encode_data(ciphertext)})


def decrypt_private_key(serialized_payload: str, master_key: bytes) -> bytes:
    payload = json.loads(serialized_payload)
    aesgcm = AESGCM(master_key)
    nonce = b64decode_data(payload["nonce"])
    plaintext = aesgcm.decrypt(nonce, b64decode_data(payload["ciphertext"]), None)
    return plaintext


def encrypt_document(content: str, document_key: bytes) -> Dict[str, str]:
    aesgcm = AESGCM(document_key)
    nonce = os.urandom(12)
    raw_ciphertext = aesgcm.encrypt(nonce, content.encode("utf-8"), None)
    ciphertext, tag = raw_ciphertext[:-16], raw_ciphertext[-16:]
    return {"ciphertext": b64encode_data(ciphertext), "nonce": b64encode_data(nonce), "tag": b64encode_data(tag)}


def decrypt_document(encrypted_content: Dict[str, str], document_key: bytes) -> str:
    aesgcm = AESGCM(document_key)
    nonce = b64decode_data(encrypted_content["nonce"])
    ciphertext = b64decode_data(encrypted_content["ciphertext"])
    tag = b64decode_data(encrypted_content["tag"])
    plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
    return plaintext.decode("utf-8")


def wrap_document_key_for_user(recipient_public_key_b64: str, document_key: bytes) -> str:
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(b64decode_data(recipient_public_key_b64))
    ephemeral_private = x25519.X25519PrivateKey.generate()
    shared_secret = ephemeral_private.exchange(recipient_public_key)
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"doc-wrap").derive(shared_secret)
    aesgcm = AESGCM(wrapping_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, document_key, None)
    payload = {
        "ephemeral_public_key": b64encode_data(
            ephemeral_private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
        ),
        "nonce": b64encode_data(nonce),
        "ciphertext": b64encode_data(ciphertext),
    }
    return json.dumps(payload)


def unwrap_document_key_for_user(payload_json: str, private_key: x25519.X25519PrivateKey) -> bytes:
    payload = json.loads(payload_json)
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(b64decode_data(payload["ephemeral_public_key"]))
    shared_secret = private_key.exchange(ephemeral_public)
    wrapping_key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"doc-wrap").derive(shared_secret)
    aesgcm = AESGCM(wrapping_key)
    nonce = b64decode_data(payload["nonce"])
    ciphertext = b64decode_data(payload["ciphertext"])
    return aesgcm.decrypt(nonce, ciphertext, None)


def build_document_payload(
    title: str,
    content: str,
    owner_id: int,
    created_at: str,
    updated_at: str,
    expiration_timestamp: Optional[str],
) -> bytes:
    payload = {
        "title": title,
        "content": content,
        "owner_id": owner_id,
        "created_at": created_at,
        "updated_at": updated_at,
        "expiration": expiration_timestamp,
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")
