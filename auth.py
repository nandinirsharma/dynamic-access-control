# auth.py  -- simple salted SHA256 demo auth (no passlib/bcrypt)
import os
import hashlib
import hmac
import binascii
from datetime import datetime, timedelta, timezone
import jwt
import secrets
import uuid

# JWT settings
JWT_SECRET = os.environ.get("JWT_SECRET", "dev_jwt_secret_change_me")
JWT_ALG = "HS256"
# Default short-lived access token TTL (minutes). Use env ACCESS_TOKEN_EXP_MINUTES to override.
ACCESS_TOKEN_EXP_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXP_MINUTES", "5"))

# Hash settings
SALT_BYTES = 16   # 16 bytes salt => 32 hex chars

def _make_salt() -> str:
    return binascii.hexlify(secrets.token_bytes(SALT_BYTES)).decode()

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def hash_password(plaintext: str) -> str:
    """
    Return salted SHA256 stored format: salt$hexdigest
    """
    if plaintext is None:
        raise ValueError("plaintext required")
    salt = _make_salt()
    digest = _sha256_hex(salt + plaintext)
    return f"{salt}${digest}"

def verify_password(plain: str, stored_hash: str) -> bool:
    """
    Verify `plain` password against stored_hash (salt$hex).
    """
    if not plain or not stored_hash:
        return False
    try:
        parts = stored_hash.split("$")
        if len(parts) != 2:
            return False
        salt, hex_digest = parts
        return hmac.compare_digest(_sha256_hex(salt + plain), hex_digest)
    except Exception:
        return False

def create_token(username: str, role: str = "user", minutes: int = None) -> str:
    """
    Create a JWT containing sub, role, iat, exp and a unique jti.
    By default tokens expire in ACCESS_TOKEN_EXP_MINUTES (5 minutes).
    """
    exp_minutes = minutes if minutes is not None else ACCESS_TOKEN_EXP_MINUTES
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())
    payload = {
        "sub": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=exp_minutes)).timestamp()),
        "jti": jti
    }
    # pyjwt returns str (>= v2)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def decode_token(token: str) -> dict:
    """
    Decode and verify token. Raises jwt.ExpiredSignatureError if token expired,
    jwt.InvalidTokenError for invalid tokens.
    """
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])

def get_jti_from_token(token: str) -> str:
    """
    Read jti from token WITHOUT validating expiry/signature (useful to find session record).
    Returns None on error.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG], options={"verify_signature": False, "verify_exp": False})
        return payload.get("jti")
    except Exception:
        # As a fallback, try to parse without decode (not recommended), but return None here.
        return None
