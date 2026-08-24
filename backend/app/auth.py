"""Authentication: JWT for users, API key hashing for devices."""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import User

bearer_scheme = HTTPBearer(auto_error=False)

# ─── Password hashing (PBKDF2 — no bcrypt dependency) ─────────
_ALGO = "sha256"
_ITERATIONS = 600_000
_SALT_LEN = 32


def _hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    """Returns (hash_hex, salt_hex)."""
    if salt is None:
        salt = secrets.token_bytes(_SALT_LEN)
    dk = hashlib.pbkdf2_hmac(_ALGO, password.encode(), salt, _ITERATIONS)
    return dk.hex(), salt.hex()


def _verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    dk = hashlib.pbkdf2_hmac(
        _ALGO, password.encode(), bytes.fromhex(stored_salt), _ITERATIONS
    )
    return dk.hex() == stored_hash


def hash_password(password: str) -> str:
    h, s = _hash_password(password)
    return f"{_ITERATIONS}${_ALGO}${s}${h}"


def verify_password(plain: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if len(parts) != 4:
            return False
        iters = int(parts[0])
        algo = parts[1]
        salt = parts[2]
        expected = parts[3]
        dk = hashlib.pbkdf2_hmac(algo, plain.encode(), bytes.fromhex(salt), iters)
        return dk.hex() == expected
    except (ValueError, IndexError):
        return False


# ─── JWT ──────────────────────────────────────────────────────
def create_jwt(user_id: str, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_jwt(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return None


# ─── Dependency: get current user from JWT ────────────────────
def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    # Try HttpOnly cookie first
    token = request.cookies.get("access_token")
    # Fall back to Authorization header
    if not token and credentials:
        token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = decode_jwt(token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # Check expiry
    exp = payload.get("exp")
    if exp and datetime.now(timezone.utc).timestamp() > exp:
        raise HTTPException(status_code=401, detail="Token expired")

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token: missing subject")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# ─── API key generation for devices ──────────────────────────
def generate_api_key() -> tuple[str, str, str]:
    """Returns (raw_key, key_hash, key_prefix)."""
    raw = "ids_" + secrets.token_hex(32)  # 66 chars total
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    prefix = raw[:8]
    return raw, hashed, prefix


def verify_api_key(raw_key: str, stored_hash: str) -> bool:
    return hashlib.sha256(raw_key.encode()).hexdigest() == stored_hash
