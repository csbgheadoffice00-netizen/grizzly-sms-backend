import os
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import requests
import psycopg2
import hashlib
import random
import string
import hmac
import json
import resend
import time

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
API_KEY = os.getenv("API_KEY", "PASTE_YOUR_HERO_SMS_API_KEY_HERE")
BASE_URL = "https://hero-sms.com/stubs/handler_api.php"
DATABASE_URL = os.getenv("DATABASE_URL", "")
PROFIT_MARGIN = 0.20
REFERRAL_BONUS = 0.50
STARTING_BALANCE = 0.00
MAX_REFERRALS = 8
FREE_REFERRAL_LIMIT = 3

# NOWPayments Config
NP_API_KEY = os.getenv("NOWPAYMENTS_API_KEY", "")
NP_IPN_SECRET = os.getenv("NOWPAYMENTS_IPN_SECRET", "")

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
    # Add has_topped_up column if it doesn't exist (for existing databases)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN has_topped_up INTEGER DEFAULT 0;")
    except psycopg2.errors.DuplicateColumn:
        conn.rollback() # <--- THIS IS THE MAGIC FIX
    
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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    return hashlib.sha256(password.encode()).hexdigest()

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
    return ''.join(random.choices(string.digits, k=6))

# ==================== MODELS ====================
class RegisterRequest(BaseModel):
    email: str
    password: str
    referral_code: str = ""

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

class EmailRequest(BaseModel):
    email: str

class VerifyRequest(BaseModel):
    email: str
    code: str

class ResetRequest(BaseModel):
    email: str
    code: str
    new_password: str

# ==================== EMAIL & AUTH ENDPOINTS ====================
@app.post("/api/auth/request-code")
def request_code(request: EmailRequest):
    email = request.email.strip().lower()
    code = generate_6_digit_code()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Email not found.")

    cursor.execute("UPDATE users SET verification_code = %s WHERE email = %s", (code, email))
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
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {"message": "Verification code sent to your email."}

@app.post("/api/auth/verify-code")
def verify_code(request: VerifyRequest):
    email = request.email.strip().lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, verification_code FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    if user[1] != request.code:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    cursor.execute("UPDATE users SET is_verified = 1, verification_code = NULL WHERE email = %s", (email,))
    conn.commit()
    conn.close()
    return {"message": "Account verified successfully!", "user_id": user[0]}

@app.post("/api/auth/forgot-password")
def forgot_password(request: EmailRequest):
    email = request.email.strip().lower()
    code = generate_6_digit_code()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    if not cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Email not found.")

    cursor.execute("UPDATE users SET verification_code = %s WHERE email = %s", (code, email))
    conn.commit()
    conn.close()

    try:
        resend.Emails.send({
            "from": "noreply@fbgsmsactivate.com",
            "to": email,
            "subject": "FBG SMS Password Reset",
            "html": f"<p>Your password reset code is: <strong>{code}</strong></p>"
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")

    return {"message": "Password reset code sent to your email."}

@app.post("/api/auth/reset-password")
def reset_password(request: ResetRequest):
    email = request.email.strip().lower()
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, verification_code FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found.")
    if user[1] != request.code:
        conn.close()
        raise HTTPException(status_code=400, detail="Invalid reset code.")
    if len(request.new_password) < 6:
        conn.close()
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

    new_hash = hash_password(request.new_password)
    cursor.execute("UPDATE users SET password_hash = %s, verification_code = NULL WHERE email = %s", (new_hash, email))
    conn.commit()
    conn.close()
    return {"message": "Password reset successful! Please log in."}

# ==================== USER ENDPOINTS ====================
@app.post("/api/register")
def register(request: RegisterRequest):
    email = request.email.strip().lower()
    password = request.password
    if not email or "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Please enter a valid email address.")
    if not password or len(password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters.")

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

        # Check rules
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
    return {"user_id": new_user_id, "email": email, "balance": start_balance, "referral_code": new_code, "is_verified": False}

@app.post("/api/login")
def login(request: LoginRequest):
    email = request.email.strip().lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, balance, referral_code, is_verified FROM users WHERE email = %s AND password_hash = %s", (email, hash_password(request.password)))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    return {"user_id": user[0], "email": email, "balance": user[1], "referral_code": user[2], "is_verified": bool(user[3])}

@app.get("/api/user/{user_id}")
def get_user(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, balance, referral_code, referral_count, referral_earnings FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user_id": user[0], "email": user[1], "balance": user[2], "referral_code": user[3] or "", "referral_count": user[4] or 0, "referral_earnings": user[5] or 0.0}

@app.get("/api/referral/{user_id}")
def get_referral_info(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT referral_code, referral_count, referral_earnings FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return {"referral_code": row[0] or "", "referral_count": row[1] or 0, "referral_earnings": row[2] or 0.0, "bonus_per_referral": REFERRAL_BONUS}

# ==================== PAYMENT ENDPOINTS ====================
@app.post("/api/payment/create-invoice")
async def create_invoice(request: TopUpRequest):
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
        
        # ADDED TIMEOUT HERE
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
def buy_number(request: BuyRequest):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT balance FROM users WHERE id = %s", (request.user_id,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="User not found")

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

    cursor.execute("UPDATE users SET balance = balance - %s WHERE id = %s", (final_price, request.user_id))
    cursor.execute("""INSERT INTO transactions (user_id, activation_id, phone_number, service, country, status, cost) VALUES (%s, %s, %s, %s, %s, 'PENDING', %s)""", (request.user_id, activation_id, phone_number, request.service, request.country, final_price))
    conn.commit()
    conn.close()
    return {"activation_id": activation_id, "phone_number": phone_number, "price": final_price}

@app.get("/api/check-sms/{activation_id}")
def check_sms(activation_id: str):
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
def cancel_activation(activation_id: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT user_id, cost, status FROM transactions WHERE activation_id = %s", (activation_id,))
    transaction = cursor.fetchone()
    if transaction and transaction[2] != 'CANCELLED':
        cursor.execute("UPDATE users SET balance = balance + %s WHERE id = %s", (transaction[1], transaction[0]))
        cursor.execute("UPDATE transactions SET status = 'CANCELLED' WHERE activation_id = %s", (activation_id,))
        conn.commit()
    conn.close()
    requests.get(BASE_URL, params={"api_key": API_KEY, "action": "setStatus", "status": 8, "id": activation_id}, timeout=15)
    return {"message": "Activation cancelled"}

@app.get("/api/active/{user_id}")
def get_active(user_id: int):
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
            "created_at": row[4],
        })

    return {"has_active": True, "activations": activations}

@app.get("/api/history/{user_id}")
def get_history(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, phone_number, service, country, status, sms_code, cost, created_at FROM transactions WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return {"history": [{"id": r[0], "phone_number": r[1], "service": r[2], "country": r[3], "status": r[4], "sms_code": r[5], "cost": r[6], "created_at": r[7]} for r in rows]}