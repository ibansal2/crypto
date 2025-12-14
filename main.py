# Main functionality for the app including user registration, login, document creation, viewing, editing, sharing, and audit logging

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

import config
from crypto_utils import (
    b64decode_data,
    b64encode_data,
    build_document_payload,
    decrypt_document,
    decrypt_private_key,
    derive_master_key,
    encrypt_document,
    encrypt_private_key,
    hash_password,
    unwrap_document_key_for_user,
    utcnow,
    verify_password,
    wrap_document_key_for_user,
)
from database import get_db_connection, init_db, log_access
from pki import (
    ensure_root_ready,
    issue_certificate,
    load_root_ca_material,
    verify_document_signature,
)
from sessions import SessionData, create_session, get_session

app = FastAPI(title="Secure Collaborative Docs")
if config.FRONTEND_DIR.is_dir():
    app.mount("/frontend", StaticFiles(directory=str(config.FRONTEND_DIR)), name="frontend")

init_db()
load_root_ca_material()

def create_user(username: str, password: str) -> int:
    ensure_root_ready()

    password_salt = os.urandom(16)
    scrypt_params = {"n": 2 ** 14, "r": 8, "p": 1}
    password_hash = hash_password(password, password_salt, scrypt_params)
    master_key = derive_master_key(password, password_salt)

    signing_private = ed25519.Ed25519PrivateKey.generate()
    agreement_private = x25519.X25519PrivateKey.generate()
    private_bundle = json.dumps(
        {
            "signing": b64encode_data(
                signing_private.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
            "agreement": b64encode_data(
                agreement_private.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            ),
        }
    ).encode("utf-8")
    encrypted_private_bundle = encrypt_private_key(private_bundle, master_key)

    certificate_pem = issue_certificate(username, signing_private.public_key()).decode("utf-8")
    agreement_public_key = b64encode_data(
        agreement_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    )

    created_at = utcnow().isoformat()
    with get_db_connection() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, password_salt, scrypt_params, public_cert, "
            "encrypted_private_sign_key, key_agreement_public_key, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                username,
                b64encode_data(password_hash),
                b64encode_data(password_salt),
                json.dumps(scrypt_params),
                certificate_pem,
                encrypted_private_bundle,
                agreement_public_key,
                created_at,
            ),
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]
    return user_id


def sign_document(payload: bytes, signing_key: ed25519.Ed25519PrivateKey) -> str:
    signature = signing_key.sign(payload)
    return b64encode_data(signature)

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3)
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    username: str
    password: str


class DocumentCreateRequest(BaseModel):
    title: str
    content: str
    expiration_timestamp: Optional[str] = Field(
        default=None, description="ISO 8601 timestamp. If omitted, the document never expires."
    )


class DocumentEditRequest(BaseModel):
    content: str


class DocumentShareRequest(BaseModel):
    target_username: str


@app.get("/", response_class=HTMLResponse)
def frontend() -> HTMLResponse:
    index_path = config.FRONTEND_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=500, detail="Frontend assets missing")
    with open(index_path, "r", encoding="utf-8") as fh:
        return HTMLResponse(fh.read())


@app.post("/register")
def register_user(payload: RegisterRequest) -> Dict[str, Any]:
    with get_db_connection() as conn:
        existing = conn.execute("SELECT 1 FROM users WHERE username = ?", (payload.username,)).fetchone()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    user_id = create_user(payload.username, payload.password)
    return {"status": "created", "user_id": user_id}


@app.post("/login")
def login(payload: LoginRequest) -> Dict[str, Any]:
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (payload.username,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    password_hash = b64decode_data(row["password_hash"])
    password_salt = b64decode_data(row["password_salt"])
    params = json.loads(row["scrypt_params"])
    if not verify_password(payload.password, password_hash, password_salt, params):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    master_key = derive_master_key(payload.password, password_salt)
    private_bundle_bytes = decrypt_private_key(row["encrypted_private_sign_key"], master_key)
    private_bundle = json.loads(private_bundle_bytes.decode("utf-8"))
    signing_key = ed25519.Ed25519PrivateKey.from_private_bytes(b64decode_data(private_bundle["signing"]))
    agreement_key = x25519.X25519PrivateKey.from_private_bytes(b64decode_data(private_bundle["agreement"]))
    token = create_session(row["id"], row["username"], signing_key, agreement_key)
    return {"token": token, "expires_in": config.SESSION_TTL_SECONDS}


@app.post("/documents/create")
def create_document(payload: DocumentCreateRequest, session: SessionData = Depends(get_session)) -> Dict[str, Any]:
    expiration = validate_expiration(payload.expiration_timestamp)
    document_key = os.urandom(32)
    encrypted_content = encrypt_document(payload.content, document_key)
    created_at = updated_at = utcnow().isoformat()
    doc_payload = build_document_payload(payload.title, payload.content, session.user_id, created_at, updated_at, expiration)
    signature = sign_document(doc_payload, session.signing_key)

    with get_db_connection() as conn:
        owner_row = conn.execute("SELECT key_agreement_public_key, public_cert FROM users WHERE id = ?", (session.user_id,)).fetchone()
        if owner_row is None:
            raise HTTPException(status_code=404, detail="Owner not found")
        wrapped_key = wrap_document_key_for_user(owner_row["key_agreement_public_key"], document_key)
        conn.execute(
            "INSERT INTO documents (owner_id, title, encrypted_content, nonce, tag, encrypted_doc_key_for_owner, signature, "
            "signer_cert, expiration_timestamp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session.user_id,
                payload.title,
                encrypted_content["ciphertext"],
                encrypted_content["nonce"],
                encrypted_content["tag"],
                wrapped_key,
                signature,
                owner_row["public_cert"],
                expiration,
                created_at,
                updated_at,
            ),
        )
        conn.commit()
        doc_id = conn.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

    log_access(session.user_id, doc_id, "create")
    return {"document_id": doc_id, "signature": signature}


@app.get("/documents/{document_id}/view")
def view_document(document_id: int, session: SessionData = Depends(get_session)) -> Dict[str, Any]:
    with get_db_connection() as conn:
        document = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if document is None:
            log_access(session.user_id, document_id, "view_missing")
            raise HTTPException(status_code=404, detail="Document not found")
        enforce_not_expired(document)
        wrapped_key = resolve_wrapped_key_for_user(conn, document, session.user_id)
        if wrapped_key is None:
            log_access(session.user_id, document_id, "view_denied")
            raise HTTPException(status_code=403, detail="No access to this document")
        document_key = unwrap_document_key_for_user(wrapped_key, session.agreement_key)
        plaintext = decrypt_document(
            {"ciphertext": document["encrypted_content"], "nonce": document["nonce"], "tag": document["tag"]},
            document_key,
        )
        payload = build_document_payload(
            document["title"],
            plaintext,
            document["owner_id"],
            document["created_at"],
            document["updated_at"],
            document["expiration_timestamp"],
        )
        signature_valid = verify_document_signature(payload, document["signature"], document["signer_cert"])

    log_access(session.user_id, document_id, "view")
    return {
        "document_id": document_id,
        "title": document["title"],
        "content": plaintext,
        "owner_id": document["owner_id"],
        "signature_valid": signature_valid,
        "expiration": document["expiration_timestamp"],
    }


@app.post("/documents/{document_id}/edit")
def edit_document(document_id: int, payload: DocumentEditRequest, session: SessionData = Depends(get_session)) -> Dict[str, Any]:
    with get_db_connection() as conn:
        document = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if document is None:
            log_access(session.user_id, document_id, "edit_missing")
            raise HTTPException(status_code=404, detail="Document not found")
        if document["owner_id"] != session.user_id:
            log_access(session.user_id, document_id, "edit_denied")
            raise HTTPException(status_code=403, detail="Only the owner can edit the document")
        enforce_not_expired(document)
        document_key = unwrap_document_key_for_user(document["encrypted_doc_key_for_owner"], session.agreement_key)
        new_encrypted = encrypt_document(payload.content, document_key)
        updated_at = utcnow().isoformat()
        doc_payload = build_document_payload(
            document["title"],
            payload.content,
            session.user_id,
            document["created_at"],
            updated_at,
            document["expiration_timestamp"],
        )
        new_signature = sign_document(doc_payload, session.signing_key)
        conn.execute(
            "UPDATE documents SET encrypted_content = ?, nonce = ?, tag = ?, signature = ?, updated_at = ? WHERE id = ?",
            (
                new_encrypted["ciphertext"],
                new_encrypted["nonce"],
                new_encrypted["tag"],
                new_signature,
                updated_at,
                document_id,
            ),
        )
        conn.commit()
    log_access(session.user_id, document_id, "edit")
    return {"document_id": document_id, "signature": new_signature, "updated_at": updated_at}


@app.post("/documents/{document_id}/share")
def share_document(document_id: int, payload: DocumentShareRequest, session: SessionData = Depends(get_session)) -> Dict[str, Any]:
    with get_db_connection() as conn:
        document = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
        if document is None:
            log_access(session.user_id, document_id, "share_missing")
            raise HTTPException(status_code=404, detail="Document not found")
        if document["owner_id"] != session.user_id:
            log_access(session.user_id, document_id, "share_denied")
            raise HTTPException(status_code=403, detail="Only the owner can share the document")
        enforce_not_expired(document)
        recipient = conn.execute("SELECT id, key_agreement_public_key FROM users WHERE username = ?", (payload.target_username,)).fetchone()
        if recipient is None:
            raise HTTPException(status_code=404, detail="Target user not found")
        if recipient["id"] == session.user_id:
            raise HTTPException(status_code=400, detail="Cannot share with yourself")
        document_key = unwrap_document_key_for_user(document["encrypted_doc_key_for_owner"], session.agreement_key)
        wrapped_key = wrap_document_key_for_user(recipient["key_agreement_public_key"], document_key)
        conn.execute(
            "INSERT INTO document_sharing (document_id, user_id, encrypted_doc_key) VALUES (?, ?, ?) "
            "ON CONFLICT(document_id, user_id) DO UPDATE SET encrypted_doc_key = excluded.encrypted_doc_key",
            (document_id, recipient["id"], wrapped_key),
        )
        conn.commit()
    log_access(session.user_id, document_id, f"share_to_{payload.target_username}")
    return {"document_id": document_id, "shared_with": payload.target_username}


@app.get("/documents/{document_id}/logs")
def document_logs(document_id: int, session: SessionData = Depends(get_session)) -> Dict[str, Any]:
    with get_db_connection() as conn:
        document = conn.execute("SELECT owner_id FROM documents WHERE id = ?", (document_id,)).fetchone()
        if document is None:
            raise HTTPException(status_code=404, detail="Document not found")
        if document["owner_id"] != session.user_id:
            raise HTTPException(status_code=403, detail="Only the owner can view audit logs")
        rows = conn.execute(
            "SELECT user_id, action, timestamp FROM access_logs WHERE document_id = ? ORDER BY id DESC LIMIT 15",
            (document_id,),
        ).fetchall()
    logs = [dict(row) for row in rows]
    return {"document_id": document_id, "logs": logs}

def resolve_wrapped_key_for_user(conn: sqlite3.Connection, document: sqlite3.Row, user_id: int) -> Optional[str]:
    if document["owner_id"] == user_id:
        return document["encrypted_doc_key_for_owner"]
    row = conn.execute("SELECT encrypted_doc_key FROM document_sharing WHERE document_id = ? AND user_id = ?", (document["id"], user_id)).fetchone()
    return row["encrypted_doc_key"] if row else None


def enforce_not_expired(document: sqlite3.Row) -> None:
    expiration = document["expiration_timestamp"]
    if expiration:
        expires_at = datetime.fromisoformat(expiration)
        if utcnow() > expires_at:
            log_access(None, document["id"], "expired_access")
            raise HTTPException(status_code=410, detail="Document has expired")


def validate_expiration(expiration: Optional[str]) -> Optional[str]:
    if expiration is None:
        return None
    try:
        ts = datetime.fromisoformat(expiration)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid expiration timestamp") from exc
    if ts <= utcnow():
        raise HTTPException(status_code=400, detail="Expiration must be in the future")
    return ts.isoformat()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
