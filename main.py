import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import sqlite3
import hashlib
import random
import string

app = FastAPI()

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- CONFIG ---
API_KEY = os.getenv("API_KEY", "A5206AcbA110e26be7c1dAed5A029bb5")
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"
DB_FILE = "grizzly.db"
PROFIT_MARGIN = 0.20

REFERRAL_BONUS = 0.50     # Amount each user gets when a referral works
STARTING_BALANCE = 0.00   # New users start with 0 unless they use a referral code

# ==================== DATABASE SETUP ====================
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            referral_code TEXT UNIQUE,
            referred_by INTEGER,
            referral_count INTEGER DEFAULT 0,
            referral_earnings REAL DEFAULT 0.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activation_id TEXT,
            phone_number TEXT,
            service TEXT,
            country INTEGER,
            status TEXT DEFAULT 'PENDING',
            sms_code TEXT,
            cost REAL DEFAULT 0.50,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    conn.commit()
    conn.close()

init_db()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def generate_referral_code() -> str:
    """Generate a code like FBG-X7K9M2"""
    chars = string.ascii_uppercase + string.digits
    suffix = ''.join(random.choices(chars, k=6))
    return f"FBG-{suffix}"

def make_unique_code(cursor) -> str:
    """Keep generating until we find one not in the DB."""
    for _ in range(20):
        code = generate_referral_code()
        cursor.execute("SELECT id FROM users WHERE referral_code = ?", (code,))
        if not cursor.fetchone():
            return code
    raise Exception("Could not generate unique referral code")

# ==================== MODELS ====================
class RegisterRequest(BaseModel):
    email: str
    password: str
    referral_code: str = ""  # optional

class LoginRequest(BaseModel):
    email: str
    password: str

class BuyRequest(BaseModel):
    user_id: int
    service: str
    country: int

class TopUpRequest(BaseModel):
    user_id: int
    amount: float

# ==================== AUTH ENDPOINTS ====================
@app.post("/api/register")
def register(request: RegisterRequest):
    email = request.email.strip().lower()
    password = request.password
    if not email or "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="This email is already registered. Try logging in.")

    # Check referral code (if provided)
    referrer_id = None
    entered_code = (request.referral_code or "").strip().upper()
    if entered_code:
        cursor.execute("SELECT id FROM users WHERE referral_code = ?", (entered_code,))
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise HTTPException(status_code=400, detail="Invalid referral code. Please check and try again.")
        referrer_id = row[0]

    # Generate unique referral code for the new user
    new_code = make_unique_code(cursor)

    # Starting balance depends on whether they used a referral code
    start_balance = REFERRAL_BONUS if referrer_id else STARTING_BALANCE

    # Insert new user
    cursor.execute(
        """INSERT INTO users (email, password_hash, balance, referral_code, referred_by)
           VALUES (?, ?, ?, ?, ?)""",
        (email, hash_password(password), start_balance, new_code, referrer_id)
    )
    new_user_id = cursor.lastrowid

    # If they used a referral code, credit the referrer too
    if referrer_id:
        cursor.execute(
            """UPDATE users 
               SET balance = balance + ?, 
                   referral_count = referral_count + 1,
                   referral_earnings = referral_earnings + ?
               WHERE id = ?""",
            (REFERRAL_BONUS, REFERRAL_BONUS, referrer_id)
        )

    conn.commit()
    conn.close()

    return {
        "user_id": new_user_id,
        "email": email,
        "balance": start_balance,
        "referral_code": new_code,
        "used_referral": bool(referrer_id),
    }

@app.post("/api/login")
def login(request: LoginRequest):
    email = request.email.strip().lower()
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, balance, referral_code FROM users WHERE email = ? AND password_hash = ?",
        (email, hash_password(request.password))
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return {"user_id": user[0], "email": email, "balance": user[1], "referral_code": user[2]}

@app.get("/api/user/{user_id}")
def get_user(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, email, balance, referral_code, referral_count, referral_earnings FROM users WHERE id = ?",
        (user_id,)
    )
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user_id": user[0],
        "email": user[1],
        "balance": user[2],
        "referral_code": user[3] or "",
        "referral_count": user[4] or 0,
        "referral_earnings": user[5] or 0.0,
    }

# ==================== REFERRAL INFO ====================
@app.get("/api/referral/{user_id}")
def get_referral_info(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT referral_code, referral_count, referral_earnings FROM users WHERE id = ?",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "referral_code": row[0] or "",
        "referral_count": row[1] or 0,
        "referral_earnings": row[2] or 0.0,
        "bonus_per_referral": REFERRAL_BONUS,
    }

@app.post("/api/topup")
def top_up(request: TopUpRequest):
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive.")
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (request.amount, request.user_id))
    conn.commit()
    cursor.execute("SELECT balance FROM users WHERE id = ?", (request.user_id,))
    new_balance = cursor.fetchone()[0]
    conn.close()
    return {"message": "Top up successful", "new_balance": new_balance}

# ==================== REFERENCE DATA ENDPOINTS ====================
@app.get("/api/countries")
def get_countries():
    params = {"api_key": API_KEY, "action": "getCountries"}
    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch countries: {str(e)}")

@app.get("/api/services")
def get_services():
    params = {"api_key": API_KEY, "action": "getServicesList", "lang": "en"}
    try:
        response = requests.get(BASE_URL, params=params, timeout=15)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch services: {str(e)}")

@app.get("/api/prices")
def get_prices(service: str = None, country: int = None):
    params = {"api_key": API_KEY, "action": "getPrices"}
    if service:
        params["service"] = service
    if country:
        params["country"] = country
    try:
        response = requests.get(BASE_URL, params=params, timeout=10)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch prices: {str(e)}")

# ==================== NUMBER ENDPOINTS ====================
@app.post("/api/buy-number")
def buy_number(request: BuyRequest):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE id = ?", (request.user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

    price_params = {"api_key": API_KEY, "action": "getPrices", "service": request.service, "country": request.country}
    price_response = requests.get(BASE_URL, params=price_params)
    price_data = price_response.json()
    try:
        cost = price_data[str(request.country)][request.service]["cost"]
        final_price = round(cost + PROFIT_MARGIN, 2)
    except (KeyError, TypeError):
        conn.close()
        raise HTTPException(status_code=400, detail="This service is currently unavailable for the selected country.")

    if user[0] < final_price:
        conn.close()
        raise HTTPException(status_code=400, detail="INSUFFICIENT_BALANCE")

    params = {"api_key": API_KEY, "action": "getNumber", "service": request.service, "country": request.country}
    response = requests.get(BASE_URL, params=params)
    if "ACCESS_NUMBER" not in response.text:
        conn.close()
        raise HTTPException(status_code=400, detail=response.text)

    parts = response.text.split(":")
    activation_id = parts[1]
    phone_number = parts[2]

    cursor.execute("UPDATE users SET balance = balance - ? WHERE id = ?", (final_price, request.user_id))
    cursor.execute(
        """INSERT INTO transactions (user_id, activation_id, phone_number, service, country, status, cost)
           VALUES (?, ?, ?, ?, ?, 'PENDING', ?)""",
        (request.user_id, activation_id, phone_number, request.service, request.country, final_price)
    )
    conn.commit()
    conn.close()
    return {"activation_id": activation_id, "phone_number": phone_number, "price": final_price}

@app.get("/api/check-sms/{activation_id}")
def check_sms(activation_id: str):
    params = {"api_key": API_KEY, "action": "getStatus", "id": activation_id}
    response = requests.get(BASE_URL, params=params)
    text = response.text
    if "STATUS_OK" in text:
        code = text.split(":")[1]
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("SELECT status FROM transactions WHERE activation_id = ?", (activation_id,))
        row = cursor.fetchone()
        if row and row[0] != 'COMPLETED':
            cursor.execute("UPDATE transactions SET status = 'COMPLETED', sms_code = ? WHERE activation_id = ?", (code, activation_id))
            conn.commit()
            conn.close()
            requests.get(BASE_URL, params={"api_key": API_KEY, "action": "setStatus", "status": 6, "id": activation_id})
        else:
            conn.close()
    return {"status": text}

@app.post("/api/cancel/{activation_id}")
def cancel_activation(activation_id: str):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, cost, status FROM transactions WHERE activation_id = ?", (activation_id,))
    transaction = cursor.fetchone()
    if transaction and transaction[2] != 'CANCELLED':
        cursor.execute("UPDATE users SET balance = balance + ? WHERE id = ?", (transaction[1], transaction[0]))
        cursor.execute("UPDATE transactions SET status = 'CANCELLED' WHERE activation_id = ?", (activation_id,))
        conn.commit()
    conn.close()
    requests.get(BASE_URL, params={"api_key": API_KEY, "action": "setStatus", "status": 8, "id": activation_id})
    return {"message": "Activation cancelled"}

# ==================== ACTIVE NUMBER RECOVERY ====================
@app.get("/api/active/{user_id}")
def get_active(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT activation_id, phone_number, service, country, created_at 
           FROM transactions 
           WHERE user_id = ? AND status = 'PENDING' 
           ORDER BY created_at DESC LIMIT 1""",
        (user_id,)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {"has_active": False}
    return {
        "has_active": True,
        "activation_id": row[0],
        "phone_number": row[1],
        "service": row[2],
        "country": row[3],
        "created_at": row[4],
    }

# ==================== HISTORY ====================
@app.get("/api/history/{user_id}")
def get_history(user_id: int):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute(
        """SELECT id, phone_number, service, country, status, sms_code, cost, created_at 
           FROM transactions WHERE user_id = ? ORDER BY created_at DESC""",
        (user_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    history = []
    for row in rows:
        history.append({
            "id": row[0], "phone_number": row[1], "service": row[2], "country": row[3],
            "status": row[4], "sms_code": row[5], "cost": row[6], "created_at": row[7]
        })
    return {"history": history}