import datetime, logging
import jwt
from config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRY_SECONDS
logger = logging.getLogger(__name__)
USERS = {
    "alice":   {"password": "password123", "role": "user"},
    "bob":     {"password": "letmein",     "role": "user"},
    "admin":   {"password": "supersecret", "role": "admin"},
}
BLACKLIST = set()

def authenticate(username, password):
    user = USERS.get(username)
    if user and user["password"] == password:
        return {"username": username, "role": user["role"]}
    return None

def create_token(username, role, expires_seconds=JWT_EXPIRY_SECONDS):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": username, "role": role, "iat": now,
        "exp": now + datetime.timedelta(seconds=expires_seconds),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_token(token):
    if token in BLACKLIST:
        raise jwt.InvalidTokenError("Token has been revoked.")
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM],
                      options={"require": ["sub", "exp", "iat", "role"],
                               "verify_exp": True, "verify_iat": True})

def revoke_token(token):
    BLACKLIST.add(token)

def decode_without_verification(token):
    return jwt.decode(token, options={"verify_signature": False},
                      algorithms=[JWT_ALGORITHM, "none"])
