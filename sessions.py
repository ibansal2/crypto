# Manages user authentication and sessions

from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

import config
from crypto_utils import utcnow

# Container which holds all the sensitive information about the currently logged-in user
@dataclass
class SessionData:
    user_id: int
    username: str
    signing_key: ed25519.Ed25519PrivateKey
    agreement_key: x25519.X25519PrivateKey
    expires_at: datetime


security = HTTPBearer(auto_error=False)
_sessions: Dict[str, SessionData] = {}
_lock = threading.Lock()

# Remove expired sessions from the in-memory store (prevents memory bloat)
def _purge_expired_sessions() -> None:
    now = utcnow()
    with _lock:
        expired = [token for token, session in _sessions.items() if session.expires_at < now]
        for token in expired:
            _sessions.pop(token, None)

# Called right after a user successfully logs in, creates a new session and returns the session token
def create_session(user_id: int, username: str, signing_key: ed25519.Ed25519PrivateKey, agreement_key: x25519.X25519PrivateKey) -> str:
    _purge_expired_sessions()
    token = secrets.token_urlsafe(48)
    with _lock:
        _sessions[token] = SessionData(
            user_id=user_id,
            username=username,
            signing_key=signing_key,
            agreement_key=agreement_key,
            expires_at=utcnow() + timedelta(seconds=config.SESSION_TTL_SECONDS),
        )
    return token

# Dependency to retrieve the current session based on the Authorization header
def get_session(credentials: HTTPAuthorizationCredentials = Depends(security)) -> SessionData:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    token = credentials.credentials
    _purge_expired_sessions()
    with _lock:
        session = _sessions.get(token)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    session.expires_at = utcnow() + timedelta(seconds=config.SESSION_TTL_SECONDS)
    return session
