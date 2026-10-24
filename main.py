import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import psycopg2
import hashlib
import random
import string
import hmac
import json
from decimal import Decimal, ROUND_HALF_UP
import resend
import time
import base64
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

app = FastAPI()

# ==================== SECURITY GATES (self-contained) ====================
# Inlined on purpose: no `from admin_gate import ...`, no extra files.
# Only the Python standard library and Starlette (installed with FastAPI).
import hmac as _hmac
import logging as _logging
from starlette.middleware.base import BaseHTTPMiddleware as _BaseMW
from starlette.responses import JSONResponse as _JSON

_log = _logging.getLogger("security_gate")

# ---- 1. Admin gate: protects every /api/admin/* route -------------------
# Fails CLOSED. If ADMIN_API_KEY is not configured on the server, all admin
# requests are denied instead of being left open.
_ADMIN_PREFIX = "/api/admin"


class AdminGate(_BaseMW):
    async def dispatch(self, request, call_next):
        path = request.url.path.rstrip("/")
        if not (path == _ADMIN_PREFIX or path.startswith(_ADMIN_PREFIX + "/")):
            return await call_next(request)

        admin_key = os.getenv("ADMIN_API_KEY", "").strip()
        if not admin_key:
            _log.warning("admin gate: ADMIN_API_KEY unset, denying %s", path)
            return _JSON(
                status_code=403,
                content={"detail": "Admin access is disabled: no admin key configured."},
            )

        given = request.headers.get("x-admin-key", "")
        if given and _hmac.compare_digest(given, admin_key):
            return await call_next(request)
        return _JSON(status_code=403, content={"detail": "Invalid or missing admin key."})


# ---- 2. Docs gate: hides /docs, /redoc, /openapi.json -------------------
# Set DOCS_ENABLED=1 in the environment to turn them back on.
_DOCS_HIDDEN = {"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"}


class DocsGate(_BaseMW):
    async def dispatch(self, request, call_next):
        path = request.url.path.rstrip("/") or "/"
        if path not in _DOCS_HIDDEN:
            return await call_next(request)
        if os.getenv("DOCS_ENABLED", "0") == "1":
            return await call_next(request)
        admin_key = os.getenv("ADMIN_API_KEY", "").strip()
        if admin_key:
            given = request.headers.get("x-admin-key", "")
            if given and _hmac.compare_digest(given, admin_key):
                return await call_next(request)
        # 404 rather than 403: do not confirm that these paths exist.
        return _JSON(status_code=404, content={"detail": "Not Found"})


app.add_middleware(AdminGate)
app.add_middleware(DocsGate)
# ========================================================================

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIG ---
API_KEY = os.getenv("API_KEY", "PASTE_YOUR_HERO_SMS_API_KEY_HERE")
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"
DATABASE_URL = os.getenv("DATABASE_URL", "")
PROFIT_MARGIN = 0.20
REFERRAL_BONUS = 0.50
STARTING_BALANCE = 0.00
MAX_REFERRALS = 8
FREE_REFERRAL_LIMIT = 3

# --- Auth / token config (v2) ---
# AUTH_MODE=compat : legacy /api/<x>/{user_id} routes still answer anonymous
#                    callers (logged as warnings) so the current APK keeps
#                    working. A supplied token is always enforced.
# AUTH_MODE=strict : those routes require a valid token (IDOR closed).
AUTH_MODE = os.getenv("AUTH_MODE", "compat").strip().lower()
AUTH_SECRET = os.getenv("AUTH_SECRET", "").strip()
TOKEN_TTL_HOURS = int(os.getenv("TOKEN_TTL_HOURS", "168"))
RESET_CODE_TTL_MINUTES = int(os.getenv("RESET_CODE_TTL_MINUTES", "15"))
RESET_MAX_ATTEMPTS = int(os.getenv("RESET_MAX_ATTEMPTS", "5"))
AUTH_GENERIC_RESPONSES = os.getenv("AUTH_GENERIC_RESPONSES", "1") == "1"
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "1") == "1"
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", "260000"))
MAX_PASSWORD_LENGTH = 200

_EFFECTIVE_AUTH_SECRET = AUTH_SECRET or secrets.token_urlsafe(48)
if not AUTH_SECRET:
    _log.warning(
        "AUTH_SECRET is not set - generated a random key at startup. "
        "Every token becomes invalid on the next restart. Set AUTH_SECRET on Render."
    )
if AUTH_MODE not in ("compat", "strict"):
    _log.warning("Unknown AUTH_MODE=%r - falling back to compat", AUTH_MODE)
    AUTH_MODE = "compat"
_log.warning("AUTH_MODE=%s (compat keeps legacy routes open; strict requires tokens)", AUTH_MODE)

# NOWPayments Config
NP_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
NP_IPN_SECRET = os.getenv("NOWPAYMENTS_IPN_SECRET", "")

# Apirone Config (NEW)
APIRONE_API_KEY = os.getenv("APIRONE_API_KEY", "PASTE_YOUR_APIRONE_KEY_HERE")
# Apirone ACCOUNT id (apr-... or btc-...). NOT the currency "btc".
APIRONE_ACCOUNT = os.getenv("APIRONE_ACCOUNT", "").strip()
APIRONE_WEBHOOK_URL = os.getenv(
    "APIRONE_WEBHOOK_URL",
    "https://grizzly-sms-backend.onrender.com/api/payment/apirone-webhook",
)
# Credit the wallet only after the invoice reaches "completed" (block confirmed).
# Set to 0 to also credit on the earlier "paid"/"overpaid" status.
APIRONE_REQUIRE_CONFIRMATION = os.getenv("APIRONE_REQUIRE_CONFIRMATION", "1") == "1"

# Resend Email Config
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
resend.api_key = RESEND_API_KEY

# ==================== DATABASE SETUP ====================
def get_db_connection():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            referral_count INTEGER DEFAULT 0,
            referral_earnings REAL DEFAULT 0.0,
            has_topped_up INTEGER DEFAULT 0,
            is_verified INTEGER DEFAULT 0,
            verification_code TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN has_topped_up INTEGER DEFAULT 0;")
    except psycopg2.errors.DuplicateColumn:
        conn.rollback()

    # v2 auth columns: reset-code expiry, attempt lockout, token revocation.
    for _stmt in (
        "ALTER TABLE users ADD COLUMN verification_code_expires TIMESTAMP",
        "ALTER TABLE users ADD COLUMN verification_attempts INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN token_invalid_before TIMESTAMP",
    ):
        try:
            cursor.execute(_stmt)
            conn.commit()
        except psycopg2.errors.DuplicateColumn:
            conn.rollback()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            activation_id TEXT,
            phone_number TEXT,
            service TEXT,
            country INTEGER,
            status TEXT DEFAULT 'PENDING',
            sms_code TEXT,
            cost REAL DEFAULT 0.50,
            created_at TIMESTAMP DEFAULT NOW()
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS payments (
            id SERIAL PRIMARY KEY,
            payment_id TEXT UNIQUE,
            user_id INTEGER NOT NULL,
            amount REAL,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256, 260k iterations, per-user random salt."""
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ITERATIONS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERATIONS, salt, dk.hex())


def verify_password(password: str, stored: str) -> bool:
    """Accepts pbkdf2_sha256$... and legacy unsalted sha256 hex."""
    if not stored:
        return False
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _algo, iterations, salt, expected = stored.split("$", 3)
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
            return hmac.compare_digest(dk.hex(), expected)
        except Exception:
            return False
    legacy = hashlib.sha256(password.encode()).hexdigest()
    return hmac.compare_digest(legacy, stored)


def needs_rehash(stored: str) -> bool:
    if not stored or not stored.startswith("pbkdf2_sha256$"):
        return True
    try:
        return int(stored.split("$")[1]) < PBKDF2_ITERATIONS
    except Exception:
        return True

def generate_referral_code() -> str:
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choices(chars, k=6))
    return f"FBG-{suffix}"

def make_unique_code(cursor) -> str:
    for _ in range(20):
        code = generate_referral_code()
        cursor.execute("SELECT id FROM users WHERE referral_code = %s", (code,))
        if not cursor.fetchone():
            return code
    raise Exception("Could not generate unique referral code")


def generate_6_digit_code():
    return ''.join(secrets.choice(string.digits) for _ in range(6))

# ==================== MODELS ====================
class RegisterRequest(BaseModel):
    email: str
    password: str
    referral_code: str = ""

class LoginRequest(BaseModel):
    email: str
    password: str

class BuyRequest(BaseModel):
    user_id: Optional[int] = None
    service: str
    country: int

class TopUpRequest(BaseModel):
    user_id: int
    amount: float

class EmailRequest(BaseModel):
    email: str

class VerifyRequest(BaseModel):
    email: str
    code: str

class ResetRequest(BaseModel):
    email: str
    code: str
    new_password: str

# ==================== AUTH & RATE-LIMIT HELPERS ====================
def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(text_value: str) -> bytes:
    return base64.urlsafe_b64decode(text_value + "=" * (-len(text_value) % 4))


def create_access_token(user_id: int) -> str:
    """Compact HS256 JWT. Standard library only (no PyJWT dependency)."""
    now = time.time()
    header = {"alg": "HS256", "typ": "JWT"}
    # iat keeps sub-second precision so a token minted moments after a password
    # reset is never mistaken for one issued before it.
    payload = {"sub": str(user_id), "iat": round(now, 6), "exp": int(now) + TOKEN_TTL_HOURS * 3600}
    head = _b64e(json.dumps(header, separators=(",", ":")).encode())
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = ("%s.%s" % (head, body)).encode()
    sig = hmac.new(_EFFECTIVE_AUTH_SECRET.encode(), signing_input, hashlib.sha256).digest()
    return "%s.%s.%s" % (head, body, _b64e(sig))


def verify_access_token(token: str) -> Optional[dict]:
    """HS256 only. No alg:none, no algorithm negotiation, no leeway beyond exp."""
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    head, body, sig = parts
    signing_input = ("%s.%s" % (head, body)).encode()
    expected = hmac.new(_EFFECTIVE_AUTH_SECRET.encode(), signing_input, hashlib.sha256).digest()
    try:
        if not hmac.compare_digest(expected, _b64d(sig)):
            return None
        header = json.loads(_b64d(head))
        payload = json.loads(_b64d(body))
    except Exception:
        return None
    if not isinstance(header, dict) or header.get("alg") != "HS256":
        return None
    if not isinstance(payload, dict):
        return None
    try:
        payload["sub"] = int(payload["sub"])
        payload["exp"] = int(payload["exp"])
    except (KeyError, TypeError, ValueError):
        return None
    if payload["exp"] < int(time.time()):
        return None
    return payload


def bearer_token(request: Request) -> Optional[str]:
    raw = request.headers.get("authorization", "")
    if raw.lower().startswith("bearer "):
        return raw[7:].strip() or None
    return None


def _token_revoked(user_id: int, issued_at: int) -> bool:
    """True if the token predates the last password reset."""
    if not issued_at:
        return False
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT token_invalid_before FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        conn.close()
    except Exception:
        return False  # fail open on DB hiccups: never lock a user out
    if not row or row[0] is None or isinstance(row[0], str):
        return False
    issued = datetime.fromtimestamp(float(issued_at), timezone.utc).replace(tzinfo=None)
    return issued < row[0]


def auth_from_request(request: Request):
    """User id from the bearer token, or None when no token was sent.

    A malformed/expired token is a 401, never silently anonymous.
    """
    token = bearer_token(request)
    if not token:
        return None
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if _token_revoked(payload["sub"], float(payload.get("iat") or 0)):
        raise HTTPException(
            status_code=401,
            detail="Session expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload["sub"]


def require_user(request: Request) -> int:
    user_id = auth_from_request(request)
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user_id


def resolve_self(request: Request, user_id: int) -> int:
    """Authorise access to user_id's data.

    Token present  -> must match user_id (403 otherwise).
    No token       -> 401 in strict mode, allowed + logged in compat mode.
    """
    token_user = auth_from_request(request)
    if token_user is not None:
        if token_user != user_id:
            raise HTTPException(status_code=403, detail="You can only access your own account.")
        return token_user
    if AUTH_MODE == "strict":
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _log.warning(
        "AUTH_MODE=compat: anonymous access to user %s (ip=%s)", user_id, _client_ip(request)
    )
    return user_id


# --- in-memory sliding-window rate limiter (one Render instance) ---
_RATE_LOCK = threading.Lock()
_RATE_HITS = {}
_RATE_RULES = {
    "login": (10, 60),
    "register": (5, 300),
    "forgot": (5, 300),
    "request_code": (5, 300),
    "verify": (10, 300),
    "reset": (10, 300),
}


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(request: Request, bucket: str) -> None:
    """Raise 429 when this IP exceeds the bucket's limit."""
    if not RATE_LIMIT_ENABLED:
        return
    limit, window = _RATE_RULES.get(bucket, (30, 60))
    key = (bucket, _client_ip(request))
    now = time.time()
    with _RATE_LOCK:
        hits = [t for t in _RATE_HITS.get(key, []) if now - t < window]
        if len(hits) >= limit:
            retry_after = max(1, int(window - (now - hits[0])) + 1)
            raise HTTPException(
                status_code=429,
                detail="Too many requests. Please slow down and try again shortly.",
                headers={"Retry-After": str(retry_after)},
            )
        hits.append(now)
        _RATE_HITS[key] = hits
        if len(_RATE_HITS) > 5000:
            for stale in [k for k, v in _RATE_HITS.items() if not v or now - v[-1] > 3600]:
                _RATE_HITS.pop(stale, None)


def _code_expired(expires) -> bool:
    if expires is None or isinstance(expires, str):
        return False
    return _utcnow() > expires


def _generic_messages() -> bool:
    return AUTH_GENERIC_RESPONSES


# ==================== EMAIL & AUTH ENDPOINTS ====================
@app.post("/api/auth/request-code")
def request_code(request: EmailRequest, http_request: Request):
    rate_limit(http_request, "request_code")
    email = request.email.strip().lower()
    code = generate_6_digit_code()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    exists = cursor.fetchone()

    if not exists:
        conn.close()
        if _generic_messages():
            return {"message": "If that email is registered, a verification code has been sent."}
        raise HTTPException(status_code=404, detail="Email not found.")

    cursor.execute(
        "UPDATE users SET verification_code = %s, verification_code_expires = %s, verification_attempts = 0 WHERE email = %s",
        (code, _utcnow() + timedelta(minutes=RESET_CODE_TTL_MINUTES), email),
    )
    conn.commit()
    conn.close()

    try:
        resend.Emails.send({
            "from": "noreply@fbgsmsactivate.com",
            "to": email,
            "subject": "Your FBG SMS Verification Code",
            "html": f"<p>Your verification code is: <strong>{code}</strong></p><p>If you didn't request this, ignore this email.</p>"
        })
    except Exception as e:
        _log.error("request-code: resend failed for %s: %s", email, e)
        raise HTTPException(status_code=502, detail="Could not send the email right now. Please try again in a moment.")

    return {"message": "Verification code sent to your email."}

@app.post("/api/auth/verify-code")
def verify_code(request: VerifyRequest, http_request: Request):
    rate_limit(http_request, "verify")
    email = request.email.strip().lower()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, verification_code, verification_code_expires, verification_attempts FROM users WHERE email = %s",
        (email,),
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")

    user_id, stored_code, expires, attempts = user[0], user[1], user[2], (user[3] or 0)

    if not stored_code:
        conn.close()
        raise HTTPException(status_code=400, detail="No active verification code. Please request a new one.")
    if _code_expired(expires):
        cursor.execute(
            "UPDATE users SET verification_code = NULL, verification_code_expires = NULL, verification_attempts = 0 WHERE id = %s",
            (user_id,),
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="This code has expired. Please request a new one.")
    if attempts >= RESET_MAX_ATTEMPTS:
        conn.close()
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new code.")
    if not hmac.compare_digest(str(stored_code), str(request.code).strip()):
        cursor.execute("UPDATE users SET verification_attempts = %s WHERE id = %s", (attempts + 1, user_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    cursor.execute(
        "UPDATE users SET is_verified = 1, verification_code = NULL, verification_code_expires = NULL, verification_attempts = 0 WHERE id = %s",
        (user_id,),
    )
    conn.commit()
    conn.close()
    return {"message": "Account verified successfully!", "user_id": user_id}

@app.post("/api/auth/forgot-password")
def forgot_password(request: EmailRequest, http_request: Request):
    rate_limit(http_request, "forgot")
    email = request.email.strip().lower()
    code = generate_6_digit_code()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    exists = cursor.fetchone()

    if not exists:
        conn.close()
        # Generic answer: do not confirm which emails are registered.
        if _generic_messages():
            return {"message": "If that email is registered, a reset code has been sent."}
        raise HTTPException(status_code=404, detail="Email not found.")

    cursor.execute(
        "UPDATE users SET verification_code = %s, verification_code_expires = %s, verification_attempts = 0 WHERE email = %s",
        (code, _utcnow() + timedelta(minutes=RESET_CODE_TTL_MINUTES), email),
    )
    conn.commit()
    conn.close()

    try:
        resend.Emails.send({
            "from": "noreply@fbgsmsactivate.com",
            "to": email,
            "subject": "FBG SMS Password Reset",
            "html": f"<p>Your password reset code is: <strong>{code}</strong></p><p>This code expires in {RESET_CODE_TTL_MINUTES} minutes.</p>"
        })
    except Exception as e:
        # Same generic answer as an unknown address: a provider outage must not
        # become a way to tell registered emails from unregistered ones.
        _log.error("forgot-password: resend failed for %s: %s", email, e)

    return {"message": "If that email is registered, a reset code has been sent."}

@app.post("/api/auth/reset-password")
def reset_password(request: ResetRequest, http_request: Request):
    rate_limit(http_request, "reset")
    email = request.email.strip().lower()

    if not request.new_password or len(request.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if len(request.new_password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail="Password is too long.")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, verification_code, verification_code_expires, verification_attempts FROM users WHERE email = %s",
        (email,),
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        if _generic_messages():
            raise HTTPException(status_code=400, detail="Invalid or expired reset code.")
        raise HTTPException(status_code=404, detail="User not found.")

    user_id, stored_code, expires, attempts = user[0], user[1], user[2], (user[3] or 0)

    if not stored_code:
        conn.close()
        raise HTTPException(status_code=400, detail="No reset code requested. Please request a new one.")
    if _code_expired(expires):
        cursor.execute(
            "UPDATE users SET verification_code = NULL, verification_code_expires = NULL, verification_attempts = 0 WHERE id = %s",
            (user_id,),
        )
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="This reset code has expired. Please request a new one.")
    if attempts >= RESET_MAX_ATTEMPTS:
        conn.close()
        raise HTTPException(status_code=429, detail="Too many incorrect attempts. Please request a new code.")
    if not hmac.compare_digest(str(stored_code), str(request.code).strip()):
        cursor.execute("UPDATE users SET verification_attempts = %s WHERE id = %s", (attempts + 1, user_id))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid reset code.")

    cursor.execute(
        "UPDATE users SET password_hash = %s, verification_code = NULL, verification_code_expires = NULL, "
        "verification_attempts = 0, token_invalid_before = %s WHERE id = %s",
        (hash_password(request.new_password), _utcnow(), user_id),
    )
    conn.commit()
    conn.close()
    return {"message": "Password reset successful! Please log in."}

# ==================== USER ENDPOINTS ====================
@app.post("/api/register")
def register(request: RegisterRequest, http_request: Request):
    rate_limit(http_request, "register")
    email = request.email.strip().lower()
    password = request.password
    if not email or "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail="Password is too long.")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="This email is already registered. Try logging in.")

    referrer_id = None
    entered_code = (request.referral_code or "").strip().upper()
    if entered_code:
        cursor.execute("SELECT id, referral_count, has_topped_up FROM users WHERE referral_code = %s", (entered_code,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid referral code.")

        referrer_id = row[0]
        referrer_count = row[1]
        referrer_topped_up = row[2]

        if referrer_count >= MAX_REFERRALS:
            conn.close()
            raise HTTPException(status_code=400, detail="This referral code has reached its maximum limit of 8 referrals.")
        if referrer_count >= FREE_REFERRAL_LIMIT and not referrer_topped_up:
            conn.close()
            raise HTTPException(status_code=400, detail="This user needs to top up their account before they can refer more people.")

    new_code = make_unique_code(cursor)
    start_balance = REFERRAL_BONUS if referrer_id else STARTING_BALANCE

    cursor.execute(
        """INSERT INTO users (email, password_hash, balance, referral_code, referred_by, is_verified)
           VALUES (%s, %s, %s, %s, %s, 0) RETURNING id""",
        (email, hash_password(password), start_balance, new_code, referrer_id)
    )
    new_user_id = cursor.fetchone()[0]

    if referrer_id:
        cursor.execute(
            """UPDATE users SET balance = balance + %s, referral_count = referral_count + 1, referral_earnings = referral_earnings + %s WHERE id = %s""",
            (REFERRAL_BONUS, REFERRAL_BONUS, referrer_id)
        )

    conn.commit()
    conn.close()
    return {
        "user_id": new_user_id,
        "email": email,
        "balance": start_balance,
        "referral_code": new_code,
        "is_verified": False,
        "access_token": create_access_token(new_user_id),
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_HOURS * 3600,
    }

@app.post("/api/login")
def login(request: LoginRequest, http_request: Request):
    rate_limit(http_request, "login")
    email = request.email.strip().lower()
    if not request.password or len(request.password) > MAX_PASSWORD_LENGTH:
        raise HTTPException(status_code=400, detail="Invalid email or password.")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, balance, referral_code, is_verified, password_hash FROM users WHERE email = %s",
        (email,),
    )
    user = cursor.fetchone()

    if not user:
        # Same work as a real check, so response timing does not reveal accounts.
        verify_password(request.password, "0" * 64)
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    user_id, balance, referral_code, is_verified, stored_hash = user[0], user[1], user[2], user[3], user[4]

    if not verify_password(request.password, stored_hash or ""):
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if needs_rehash(stored_hash or ""):
        try:
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hash_password(request.password), user_id))
        except Exception:
            conn.rollback()
        conn.commit()

    conn.close()
    return {
        "user_id": user_id,
        "email": email,
        "balance": balance,
        "referral_code": referral_code,
        "is_verified": bool(is_verified),
        "access_token": create_access_token(user_id),
        "token_type": "bearer",
        "expires_in": TOKEN_TTL_HOURS * 3600,
    }

def _profile_payload(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, balance, referral_code, referral_count, referral_earnings FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        return None
    return {"user_id": user[0], "email": user[1], "balance": user[2], "referral_code": user[3] or "", "referral_count": user[4] or 0, "referral_earnings": user[5] or 0.0}


def _referral_payload(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT referral_code, referral_count, referral_earnings FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {"referral_code": row[0] or "", "referral_count": row[1] or 0, "referral_earnings": row[2] or 0.0, "bonus_per_referral": REFERRAL_BONUS}


@app.get("/api/user/{user_id}")
def get_user(user_id: int, http_request: Request):
    resolve_self(http_request, user_id)
    payload = _profile_payload(user_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="User not found")
    return payload

@app.get("/api/referral/{user_id}")
def get_referral_info(user_id: int, http_request: Request):
    resolve_self(http_request, user_id)
    payload = _referral_payload(user_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="User not found")
    return payload

# --- token-only replacements: use these from the next app build ---
@app.get("/api/me")
def get_me(http_request: Request):
    payload = _profile_payload(require_user(http_request))
    if payload is None:
        raise HTTPException(status_code=404, detail="User not found")
    return payload

@app.get("/api/me/referral")
def get_me_referral(http_request: Request):
    payload = _referral_payload(require_user(http_request))
    if payload is None:
        raise HTTPException(status_code=404, detail="User not found")
    return payload

# ==================== PAYMENT ENDPOINTS ====================
@app.post("/api/payment/create-invoice")
async def create_invoice(request: TopUpRequest, http_request: Request):
    resolve_self(http_request, request.user_id)
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive.")
    if request.amount < 1.0:
        raise HTTPException(status_code=400, detail="Minimum top up is $1.00")

    try:
        order_id = f"user_{request.user_id}_{int(random.random() * 1000000)}"
        
        headers = {"x-api-key": NP_API_KEY, "Content-Type": "application/json"}
        payload = {
            "price_amount": request.amount,
            "price_currency": "usd",
            "order_id": order_id,
            "order_description": f"FBG SMS Wallet Top-Up for User {request.user_id}",
            "ipn_callback_url": "https://grizzly-sms-backend.onrender.com/api/payment/webhook",
            "success_url": "https://fbgsmsactivate.com/",
            "cancel_url": "https://fbgsmsactivate.com/"
        }
        
        response = requests.post("https://api.nowpayments.io/v1/invoice", json=payload, headers=headers, timeout=20)
        response.raise_for_status()
        invoice_data = response.json()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO payments (payment_id, user_id, amount, status) VALUES (%s, %s, %s, %s)",
            (str(invoice_data['id']), request.user_id, request.amount, 'waiting')
        )
        conn.commit()
        conn.close()

        return {"invoice_url": invoice_data['invoice_url']}
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Payment provider timed out. Please try again.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Payment provider error: {str(e)}")

# ---------- Apirone (crypto) helpers ----------
# Only currencies that are enabled on the Apirone account. tbtc (testnet) is
# deliberately excluded. `decimals` matches the units-factor reported by
# https://apirone.com/api/v2/accounts (OPTIONS).
COINS = [
    {"code": "btc", "cb": "BTC", "name": "Bitcoin", "symbol": "BTC", "price_id": "bitcoin", "decimals": 8},
    {"code": "eth", "cb": "ETH", "name": "Ethereum", "symbol": "ETH", "price_id": "ethereum", "decimals": 18},
    {"code": "usdt@trx", "name": "Tether (TRC20)", "symbol": "USDT", "price_id": None, "decimals": 6},
    {"code": "usdc@trx", "name": "USD Coin (TRC20)", "symbol": "USDC", "price_id": None, "decimals": 6},
    {"code": "usdt@eth", "name": "Tether (ERC20)", "symbol": "USDT", "price_id": None, "decimals": 6},
    {"code": "usdc@eth", "name": "USD Coin (ERC20)", "symbol": "USDC", "price_id": None, "decimals": 6},
    {"code": "usdt@bnb", "name": "Tether (BEP20)", "symbol": "USDT", "price_id": None, "decimals": 18},
    {"code": "usdc@bnb", "name": "USD Coin (BEP20)", "symbol": "USDC", "price_id": None, "decimals": 18},
    {"code": "usdt@ton", "name": "Tether (TON)", "symbol": "USDT", "price_id": None, "decimals": 6},
    {"code": "ltc", "cb": "LTC", "name": "Litecoin", "symbol": "LTC", "price_id": "litecoin", "decimals": 8},
    {"code": "bch", "cb": "BCH", "name": "Bitcoin Cash", "symbol": "BCH", "price_id": "bitcoin-cash", "decimals": 8},
    {"code": "doge", "cb": "DOGE", "name": "Dogecoin", "symbol": "DOGE", "price_id": "dogecoin", "decimals": 8},
    {"code": "trx", "cb": "TRX", "name": "TRON", "symbol": "TRX", "price_id": "tron", "decimals": 6},
    {"code": "bnb", "cb": "BNB", "name": "BNB", "symbol": "BNB", "price_id": "binancecoin", "decimals": 18},
]
COIN_BY_CODE = {c["code"]: c for c in COINS}
DUST_MIN_UNITS = 1000  # for UTXO chains
_price_cache = {}  # code -> (price_usd, timestamp)


def _price_from_coinbase(symbol: str) -> float:
    try:
        r = requests.get(
            f"https://api.coinbase.com/v2/prices/{symbol}-USD/spot", timeout=10
        )
        if r.status_code == 200:
            return float(r.json()["data"]["amount"])
    except Exception:
        pass
    return 0.0


def _price_from_coingecko(price_id: str) -> float:
    try:
        r = requests.get(
            "https://api.coingecko.com/api/v3/simple/price",
            params={"ids": price_id, "vs_currencies": "usd"},
            timeout=12,
        )
        if r.status_code == 200:
            payload = r.json()
            if price_id in payload:
                return float(payload[price_id]["usd"])
    except Exception:
        pass
    return 0.0


def get_asset_price_usd(code: str) -> float:
    """USD price for a coin, cached 5 minutes.

    Two independent sources so a rate-limited free API never blocks payments.
    Stablecoins are pinned to 1.00.
    """
    coin = COIN_BY_CODE.get(code)
    if coin is None:
        raise HTTPException(status_code=400, detail=f"Unsupported currency: {code}")
    if coin["price_id"] is None:
        return 1.0

    now = time.time()
    cached = _price_cache.get(code)
    if cached and (now - cached[1]) < 300:
        return cached[0]

    price = _price_from_coinbase(coin.get("cb", ""))
    if price <= 0:
        price = _price_from_coingecko(coin["price_id"])

    if price <= 0:
        raise HTTPException(
            status_code=503,
            detail=f"Could not fetch the {code.upper()}/USD rate. Try again shortly.",
        )

    _price_cache[code] = (price, now)
    return price


def apirone_account_ready() -> bool:
    return bool(APIRONE_ACCOUNT) and APIRONE_ACCOUNT.startswith(("apr-", "btc-"))


def to_base_units(amount_usd: float, price_usd: float, decimals: int) -> int:
    """Convert a USD amount into the coin's smallest unit (satoshi/wei/sun...)."""
    units = (
        Decimal(str(amount_usd))
        / Decimal(str(price_usd))
        * (Decimal(10) ** decimals)
    ).quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return int(units)


@app.get("/api/payment/coins")
def list_coins():
    return {
        "coins": [
            {
                "code": c["code"],
                "name": c["name"],
                "symbol": c["symbol"],
                "min_usd": 1.0,
            }
            for c in COINS
        ]
    }


class CryptoTopUpRequest(BaseModel):
    user_id: int
    amount: float
    currency: str = "btc"


@app.post("/api/payment/create-btc-invoice")
async def create_btc_invoice(request: CryptoTopUpRequest, http_request: Request):
    """Create a crypto invoice for any enabled coin (default Bitcoin)."""
    resolve_self(http_request, request.user_id)
    currency = (request.currency or "btc").strip().lower()

    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive.")
    if request.amount < 1.0:
        raise HTTPException(status_code=400, detail="Minimum is $1.00")
    if currency not in COIN_BY_CODE:
        raise HTTPException(status_code=400, detail=f"Unsupported currency: {currency}")
    if not apirone_account_ready():
        raise HTTPException(
            status_code=503,
            detail="Crypto payments are not configured yet (APIRONE_ACCOUNT missing on the server).",
        )

    coin = COIN_BY_CODE[currency]
    price_usd = get_asset_price_usd(currency)
    units = to_base_units(request.amount, price_usd, coin["decimals"])

    if coin["code"] in ("btc", "ltc", "bch", "doge") and units < DUST_MIN_UNITS:
        units = DUST_MIN_UNITS
    if units <= 0:
        raise HTTPException(status_code=400, detail="Amount too small.")

    url = f"https://apirone.com/api/v2/accounts/{APIRONE_ACCOUNT}/invoices"
    payload = {
        "amount": units,
        "currency": currency,
        "lifetime": 3600,
        "callback_url": APIRONE_WEBHOOK_URL,
        "user-data": {
            "title": f"FBG SMS top-up ${request.amount:.2f}",
            "merchant": "FBG SMS",
            "user_id": str(request.user_id),
        },
    }

    try:
        response = requests.post(url, json=payload, timeout=30)
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Payment provider timed out. Please try again.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Apirone unreachable: {e}")

    if response.status_code not in (200, 201):
        raise HTTPException(
            status_code=502,
            detail=f"Apirone error {response.status_code}: {response.text[:300]}",
        )

    invoice_data = response.json()
    invoice_id = invoice_data.get("invoice")
    invoice_url = invoice_data.get("invoice-url") or invoice_data.get("invoice_url")
    address = invoice_data.get("address")

    if not invoice_id or not invoice_url:
        raise HTTPException(status_code=502, detail="Apirone returned an incomplete invoice.")

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO payments (payment_id, user_id, amount, status) VALUES (%s, %s, %s, %s)",
            (invoice_id, request.user_id, request.amount, "waiting"),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"WARN: could not record apirone payment {invoice_id}: {e}")

    return {
        "provider": "apirone",
        "currency": currency,
        "invoice_url": invoice_url,
        "invoice": invoice_id,
        "address": address,
        "amount_crypto": units / (10 ** coin["decimals"]),
        "amount_units": units,
        "asset_price_usd": price_usd,
    }


@app.post("/api/payment/apirone-webhook")
async def apirone_webhook(request: Request):
    """Apirone invoice callback: {"account": "...", "invoice": "...", "status": "..."}.

    Apirone does not sign these callbacks, so the status is re-checked against
    the Apirone API before any balance is credited.
    """
    try:
        payload = await request.json()
    except Exception:
        return PlainTextResponse("bad request", status_code=400)

    invoice_id = payload.get("invoice")
    if not invoice_id:
        return PlainTextResponse("ok")

    try:
        r = requests.get(f"https://apirone.com/api/v2/invoices/{invoice_id}", timeout=20)
        if r.status_code != 200:
            return PlainTextResponse("ok")
        info = r.json()
    except Exception:
        return PlainTextResponse("retry", status_code=500)

    status = info.get("status")

    ok_statuses = {"completed"} if APIRONE_REQUIRE_CONFIRMATION else {"paid", "overpaid", "completed"}
    if status not in ok_statuses:
        return PlainTextResponse("ok")

    user_id = None
    amount_usd = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT user_id, amount, status FROM payments WHERE payment_id = %s",
            (invoice_id,),
        )
        row = cursor.fetchone()
        if row:
            user_id, amount_usd, db_status = row
            if db_status == "finished":
                conn.close()
                return PlainTextResponse("ok")

        if user_id is None:
            raw = info.get("user-data", {}).get("user_id")
            try:
                user_id = int(raw)
            except (TypeError, ValueError):
                user_id = None

        if user_id is None:
            conn.close()
            return PlainTextResponse("ok")

        if amount_usd is None:
            currency = (info.get("currency") or "btc").lower()
            coin = COIN_BY_CODE.get(currency)
            if coin is None:
                conn.close()
                return PlainTextResponse("ok")
            price_usd = get_asset_price_usd(currency)
            paid_units = Decimal(str(info.get("amount", 0) or 0))
            amount_usd = float(
                (paid_units / (Decimal(10) ** coin["decimals"])) * Decimal(str(price_usd))
            )
            amount_usd = round(amount_usd, 2)

        cursor.execute("UPDATE payments SET status = 'finished' WHERE payment_id = %s", (invoice_id,))
        cursor.execute(
            "UPDATE users SET balance = balance + %s, has_topped_up = 1 WHERE id = %s",
            (amount_usd, user_id),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"ERROR crediting apirone invoice {invoice_id}: {e}")
        return PlainTextResponse("retry", status_code=500)

    print(f"Apirone invoice {invoice_id} {status}: credited ${amount_usd} to user {user_id}")
    return PlainTextResponse("ok")


@app.post("/api/payment/webhook")
async def payment_webhook(request: Request):
    payload = await request.json()
    signature = request.headers.get("x-nowpayments-sig")
    
    message = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    expected_sig = hmac.new(NP_IPN_SECRET.encode(), message.encode(), hashlib.sha512).hexdigest()
    
    if not signature or not hmac.compare_digest(expected_sig, signature):
        raise HTTPException(status_code=403, detail="Invalid signature")

    payment_status = payload.get("payment_status")
    order_id = payload.get("order_id")
    payment_id = str(payload.get("payment_id"))
    price_amount = payload.get("price_amount")

    if payment_status in ["finished", "confirmed"]:
        try:
            user_id = int(order_id.split("_")[1])
        except (IndexError, ValueError):
            return {"status": "error", "message": "Invalid order_id format"}

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM payments WHERE payment_id = %s", (payment_id,))
        row = cursor.fetchone()
        
        if row and row[0] != 'finished':
            cursor.execute("UPDATE payments SET status = 'finished' WHERE payment_id = %s", (payment_id,))
            cursor.execute("UPDATE users SET balance = balance + %s, has_topped_up = 1 WHERE id = %s", (price_amount, user_id))
            conn.commit()
        conn.close()

    return {"status": "success"}

# ==================== TEMPORARY ADMIN ENDPOINT ====================
@app.post("/api/admin/add-funds")
def admin_add_funds(user_id: int, amount: float):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET balance = balance + %s, has_topped_up = 1 WHERE id = %s", (amount, user_id))
    conn.commit()
    cursor.execute("SELECT balance FROM users WHERE id = %s", (user_id,))
    new_bal = cursor.fetchone()
    conn.close()
    if not new_bal:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": f"Added ${amount}", "new_balance": new_bal[0]}

# ==================== REFERENCE DATA & NUMBER ENDPOINTS ====================
@app.get("/api/countries")
def get_countries():
    params = {"api_key": API_KEY, "action": "getCountries"}
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/services")
def get_services():
    params = {"api_key": API_KEY, "action": "getServicesList", "lang": "en"}
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/prices")
def get_prices(service: str = None, country: int = None):
    params = {"api_key": API_KEY, "action": "getPrices"}
    if service: params["service"] = service
    if country: params["country"] = country
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/buy-number")
def buy_number(request: BuyRequest, http_request: Request):
    token_user = auth_from_request(http_request)
    if token_user is not None:
        if request.user_id not in (None, 0, token_user):
            raise HTTPException(status_code=403, detail="You can only buy numbers for your own account.")
        user_id = token_user
    else:
        if AUTH_MODE == "strict":
            raise HTTPException(
                status_code=401,
                detail="Authentication required.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if not request.user_id:
            raise HTTPException(status_code=400, detail="user_id is required.")
        user_id = request.user_id
        _log.warning("AUTH_MODE=compat: anonymous buy-number for user %s", user_id)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    # --- Facebook route gate (OBSERVE ONLY): log, never block ---
    if str(getattr(request, "service", "")).lower() == "fb" and getattr(request, "country", None) == 187:
        _log.warning(
            "fb_gate OBSERVE: facebook order requested country=187 user=%s",
            user_id,
        )

    price_params = {"api_key": API_KEY, "action": "getPrices", "service": request.service, "country": request.country}
    try:
        price_response = requests.get(BASE_URL, params=price_params, timeout=15)
        price_data = price_response.json()
        cost = price_data[str(request.country)][request.service]["cost"]
        final_price = round(cost + PROFIT_MARGIN, 2)
    except (KeyError, TypeError):
        conn.close()
        raise HTTPException(status_code=400, detail="This service is currently unavailable. Please try another country or service.")
    except requests.exceptions.Timeout:
        conn.close()
        raise HTTPException(status_code=504, detail="HeroSMS server timed out. Please try again.")

    if user[0] < final_price:
        conn.close()
        raise HTTPException(status_code=400, detail="INSUFFICIENT_BALANCE")

    params = {"api_key": API_KEY, "action": "getNumber", "service": request.service, "country": request.country}
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        if "ACCESS_NUMBER" not in response.text:
            conn.close()
            raise HTTPException(status_code=400, detail="HeroSMS is out of stock for this selection. Try another country.")
    except requests.exceptions.Timeout:
        conn.close()
        raise HTTPException(status_code=504, detail="HeroSMS server timed out. Please try again.")

    parts = response.text.split(":")
    activation_id, phone_number = parts[1], parts[2]

    cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (final_price, user_id))
    cursor.execute("""INSERT INTO transactions (user_id, activation_id, phone_number, service, country, status, cost) VALUES (%s, %s, %s, %s, %s, 'PENDING', %s)""", (user_id, activation_id, phone_number, request.service, request.country, final_price))
    conn.commit()
    conn.close()
    return {"activation_id": activation_id, "phone_number": phone_number, "price": final_price}

def _activation_owner(http_request: Request, activation_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM transactions WHERE activation_id = %s", (activation_id,))
    row = cursor.fetchone()
    conn.close()
    owner = row[0] if row else None

    token_user = auth_from_request(http_request)
    if token_user is not None:
        if owner is not None and owner != token_user:
            raise HTTPException(status_code=403, detail="This activation belongs to another account.")
        return owner
    if AUTH_MODE == "strict":
        raise HTTPException(
            status_code=401,
            detail="Authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    _log.warning("AUTH_MODE=compat: anonymous access to activation %s", activation_id)
    return owner


def _iso_utc(dt):
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


@app.get("/api/check-sms/{activation_id}")
def check_sms(activation_id: str, http_request: Request):
    _activation_owner(http_request, activation_id)
    params = {"api_key": API_KEY, "action": "getStatus", "id": activation_id}
    response = requests.get(BASE_URL, params=params, timeout=15)
    text = response.text
    if "STATUS_OK" in text:
        code = text.split(":")[1]
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM transactions WHERE activation_id = %s", (activation_id,))
        row = cursor.fetchone()
        if row and row[0] != 'COMPLETED':
            cursor.execute("UPDATE transactions SET status = 'COMPLETED', sms_code = %s WHERE activation_id = %s", (code, activation_id))
            conn.commit()
            conn.close()
            requests.get(BASE_URL, params={"api_key": API_KEY, "action": "setStatus", "status": 6, "id": activation_id})
        else:
            conn.close()
    return {"status": text}

@app.post("/api/cancel/{activation_id}")
@app.post("/api/cancel/{activation_id}")
def cancel_activation(activation_id: str, http_request: Request):
    _activation_owner(http_request, activation_id)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, cost, status, sms_code, created_at FROM transactions WHERE activation_id = %s",
        (activation_id,),
    )
    row = cursor.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Activation not found.")
    owner_id, cost, status, sms_code, created_at = row

    if status == "CANCELLED":
        conn.close()
        return {"message": "Activation already cancelled"}
    if status == "COMPLETED" or sms_code:
        conn.close()
        raise HTTPException(
            status_code=409,
            detail="This activation already received an SMS and cannot be refunded.",
        )
    if created_at is not None and (_utcnow() - created_at).total_seconds() < 120:
        conn.close()
        raise HTTPException(
            status_code=429,
            detail="This number was just purchased. Please wait before cancelling.",
        )

    cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (cost, owner_id))
    cursor.execute("UPDATE transactions SET status = 'CANCELLED' WHERE activation_id = %s", (activation_id,))
    conn.commit()
    conn.close()
    try:
        requests.get(
            BASE_URL,
            params={"api_key": API_KEY, "action": "setStatus", "status": 8, "id": activation_id},
            timeout=15,
        )
    except Exception:
        pass
    return {"message": "Activation cancelled"}

def _active_payload(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT activation_id, phone_number, service, country, created_at
           FROM transactions
           WHERE user_id = %s AND status = 'PENDING'
           ORDER BY created_at DESC""",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return {"has_active": False, "activations": []}

    activations = []
    for row in rows:
        activations.append({
            "activation_id": row[0],
            "phone_number": row[1],
            "service": row[2],
            "country": row[3],
            "created_at": _iso_utc(row[4]),
        })

    return {"has_active": True, "activations": activations}


def _history_payload(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, phone_number, service, country, status, sms_code, cost, created_at FROM transactions WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return {"history": [{"id": r[0], "phone_number": r[1], "service": r[2], "country": r[3], "status": r[4], "sms_code": r[5], "cost": r[6], "created_at": _iso_utc(r[7])} for r in rows]}


@app.get("/api/active/{user_id}")
def get_active(user_id: int, http_request: Request):
    resolve_self(http_request, user_id)
    return _active_payload(user_id)

@app.get("/api/history/{user_id}")
def get_history(user_id: int, http_request: Request):
    resolve_self(http_request, user_id)
    return _history_payload(user_id)

@app.get("/api/me/active")
def get_me_active(http_request: Request):
    return _active_payload(require_user(http_request))

@app.get("/api/me/history")
def get_me_history(http_request: Request):
    return _history_payload(require_user(http_request))
