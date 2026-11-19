import secrets
import hashlib
import hmac

import jwt

from datetime import datetime, timedelta, timezone

from pwdlib import PasswordHash

from src.apps.core.config import settings


password_hash = PasswordHash.recommended()


# -----------------------------
# Password Hashing
# -----------------------------

def hash_password(password: str) -> str:

    return password_hash.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str
) -> bool:

    return password_hash.verify(
        plain_password,
        hashed_password
    )


# -----------------------------
# Access Token
# -----------------------------

def create_access_token(user_id: str) -> str:

    now = datetime.now(timezone.utc)

    expire = now + timedelta(
        minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": user_id,
        "type": "access",
        "iat": now,
        "exp": expire,
        "jti": secrets.token_urlsafe(16),
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


# -----------------------------
# Refresh Token
# -----------------------------

def create_refresh_token(user_id: str) -> str:

    now = datetime.now(timezone.utc)

    expire = now + timedelta(
        days=settings.REFRESH_TOKEN_EXPIRE_DAYS
    )

    payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now,
        "exp": expire,
        "jti": secrets.token_urlsafe(16)
    }

    return jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )


# -----------------------------
# JWT Verification
# -----------------------------

def decode_token(token: str) -> dict:

    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )


# -----------------------------
# OTP Generation
# -----------------------------

def generate_otp() -> str:

    return f"{secrets.randbelow(1000000):06d}"


# -----------------------------
# OTP Hashing
# -----------------------------

def hash_otp(otp: str) -> str:

    return hmac.new(
        settings.OTP_SECRET_KEY.encode(),
        otp.encode(),
        hashlib.sha256
    ).hexdigest()


def verify_otp(
    otp: str,
    stored_hash: str
) -> bool:

    return hmac.compare_digest(
        hash_otp(otp),
        stored_hash
    )