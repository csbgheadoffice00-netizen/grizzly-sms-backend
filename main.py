#!/usr/bin/env python3
"""Exercise the v2 backend locally.

Runs main.py against an in-process sqlite database through a tiny psycopg2
shim, so no Postgres is needed. Not a production substitute: it verifies the
auth logic, not Postgres semantics.
"""
import hashlib
import importlib.util
import os
import sqlite3
import sys
import types
from datetime import datetime

DBFILE = "/tmp/v2test.db"
if os.path.exists(DBFILE):
    os.remove(DBFILE)

# ------------------------------------------------------------ psycopg2 shim
sqlite3.register_adapter(datetime, lambda d: d.strftime("%Y-%m-%d %H:%M:%S.%f"))
sqlite3.register_converter("TIMESTAMP", lambda b: datetime.strptime(b.decode(), "%Y-%m-%d %H:%M:%S.%f"))


class DuplicateColumn(Exception):
    pass


class _Cursor:
    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql, params=None):
        sql = sql.replace("%s", "?").replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
        try:
            if params is None:
                self._cur.execute(sql)
            else:
                self._cur.execute(sql, params)
        except sqlite3.OperationalError as exc:
            if "duplicate column" in str(exc).lower():
                raise DuplicateColumn(str(exc))
            raise
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()


class _Conn:
    def __init__(self):
        self._conn = sqlite3.connect(
            DBFILE, check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES, timeout=10
        )

    def cursor(self):
        return _Cursor(self._conn.cursor())

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()


fake_pg = types.ModuleType("psycopg2")
fake_pg.connect = lambda dsn: _Conn()
fake_pg.errors = types.SimpleNamespace(DuplicateColumn=DuplicateColumn)
sys.modules["psycopg2"] = fake_pg

os.environ.setdefault("DATABASE_URL", "shim://local")
os.environ.setdefault("ADMIN_API_KEY", "test-admin-key")
os.environ.setdefault("AUTH_SECRET", "test-secret-please-change")
os.environ.setdefault("AUTH_MODE", "compat")
os.environ.setdefault("RESEND_API_KEY", "re_test")
os.environ.setdefault("NOWPAYMENTS_API_KEY", "np_test")
os.environ.setdefault("NOWPAYMENTS_IPN_SECRET", "ipn_test")

MODE = os.environ["AUTH_MODE"]

# ------------------------------------------------------------------ import
MAIN = os.environ.get("MAIN_PATH", "/home/user/deliver-v2/main.py")
spec = importlib.util.spec_from_file_location("grizzly_v2", MAIN)
main = importlib.util.module_from_spec(spec)
sys.modules["grizzly_v2"] = main
spec.loader.exec_module(main)

from fastapi.testclient import TestClient  # noqa: E402

client = TestClient(main.app)

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(("  PASS  " if cond else "  FAIL  ") + name + (("  | " + str(detail)) if detail and not cond else ""))


def raw_db():
    conn = sqlite3.connect(DBFILE, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    return conn


def register(email, password="Passw0rd!", ip="10.0.0.1"):
    return client.post("/api/register", json={"email": email, "password": password},
                       headers={"X-Forwarded-For": ip})


def login(email, password="Passw0rd!", ip="10.0.0.2"):
    return client.post("/api/login", json={"email": email, "password": password},
                       headers={"X-Forwarded-For": ip})


def auth(token):
    return {"Authorization": "Bearer " + token}


print("\nMODE=%s" % MODE)

if MODE == "compat":
    # ---------------------------------------------------------- basic
    r = register("alice@example.com")
    check("register 200", r.status_code == 200, r.text)
    alice = r.json()
    check("register returns access_token", bool(alice.get("access_token")))
    check("register returns user_id", isinstance(alice.get("user_id"), int))

    r = register("bob@example.com")
    bob = r.json()
    check("second register 200", r.status_code == 200, r.text)

    check("password stored as pbkdf2",
          raw_db().execute("SELECT password_hash FROM users WHERE id=?", (alice["user_id"],)).fetchone()[0]
          .startswith("pbkdf2_sha256$"))

    r = login("alice@example.com")
    check("login 200", r.status_code == 200, r.text)
    check("login returns access_token", bool(r.json().get("access_token")))
    check("login still returns user_id/balance/referral_code",
          all(k in r.json() for k in ("user_id", "balance", "referral_code", "is_verified")))
    alice_tok = r.json()["access_token"]
    bob_tok = bob["access_token"]

    r = login("alice@example.com", "wrong-password")
    check("login wrong password 401", r.status_code == 401, r.text)

    # ---------------------------------------------------------- /api/me
    r = client.get("/api/me", headers=auth(alice_tok))
    check("GET /api/me with token 200", r.status_code == 200, r.text)
    check("/api/me returns own id", r.json().get("user_id") == alice["user_id"], r.text)
    check("/api/me no password_hash leak", "password" not in r.text)

    r = client.get("/api/me")
    check("GET /api/me anonymous 401", r.status_code == 401, r.text)

    r = client.get("/api/me", headers={"Authorization": "Bearer not.a.token"})
    check("GET /api/me garbage token 401", r.status_code == 401, r.text)

    for path in ("/api/me/referral", "/api/me/active", "/api/me/history"):
        r = client.get(path, headers=auth(alice_tok))
        check("GET %s 200" % path, r.status_code == 200, r.text)
        r2 = client.get(path)
        check("GET %s anonymous 401" % path, r2.status_code == 401, r2.text)

    # ---------------------------------------------------------- legacy routes
    r = client.get("/api/user/%d" % alice["user_id"], headers=auth(alice_tok))
    check("legacy /api/user/self with token 200", r.status_code == 200, r.text)

    r = client.get("/api/user/%d" % alice["user_id"], headers=auth(bob_tok))
    check("legacy /api/user/other with bob token 403", r.status_code == 403, r.text)

    r = client.get("/api/user/%d" % alice["user_id"])
    check("compat: legacy anonymous read allowed (documented gap)", r.status_code == 200, r.text)

    r = client.get("/api/user/%d" % alice["user_id"], headers={"Authorization": "Bearer expired.garbage.here"})
    check("legacy route with bad token 401 (no anonymous fallback)", r.status_code == 401, r.text)

    r = client.get("/api/history/%d" % alice["user_id"], headers=auth(bob_tok))
    check("legacy /api/history/other with bob token 403", r.status_code == 403, r.text)
    r = client.get("/api/active/%d" % alice["user_id"], headers=auth(bob_tok))
    check("legacy /api/active/other with bob token 403", r.status_code == 403, r.text)
    r = client.get("/api/referral/%d" % alice["user_id"], headers=auth(bob_tok))
    check("legacy /api/referral/other with bob token 403", r.status_code == 403, r.text)

    # ---------------------------------------------------------- token tampering
    head, body, sig = alice_tok.split(".")
    forged_body = main._b64e(b'{"sub":"%d","iat":1,"exp":9999999999}' % bob["user_id"])
    r = client.get("/api/me", headers={"Authorization": "Bearer %s.%s.%s" % (head, forged_body, sig)})
    check("forged token payload 401", r.status_code == 401, r.text)

    # ---------------------------------------------------------- reset flow
    r = client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"},
                    headers={"X-Forwarded-For": "10.0.0.20"})
    check("forgot-password unknown email generic 200", r.status_code == 200, r.text)
    check("forgot-password does not reveal existence",
          "not found" not in r.text.lower(), r.text)

    r = client.post("/api/auth/forgot-password", json={"email": "alice@example.com"},
                    headers={"X-Forwarded-For": "10.0.0.21"})
    check("forgot-password known email 200", r.status_code == 200, r.text)

    row = raw_db().execute(
        "SELECT verification_code, verification_code_expires, verification_attempts FROM users WHERE id=?",
        (alice["user_id"],)).fetchone()
    alice_code = row[0]
    check("code stored with expiry", row[1] is not None, row[1])
    check("reset code is 6 digits", alice_code is not None and len(alice_code) == 6, alice_code)

    # expiry
    raw = raw_db()
    raw.execute("UPDATE users SET verification_code_expires=? WHERE id=?",
                ("2020-01-01 00:00:00.000000", alice["user_id"]))
    raw.commit()
    raw.close()
    r = client.post("/api/auth/reset-password",
                    json={"email": "alice@example.com", "code": alice_code, "new_password": "BrandNew1!"},
                    headers={"X-Forwarded-For": "10.0.0.22"})
    check("expired reset code rejected 400", r.status_code == 400, r.text)
    check("expired-code message", "expired" in r.text.lower(), r.text)

    # attempts lockout on bob
    r = client.post("/api/auth/forgot-password", json={"email": "bob@example.com"},
                    headers={"X-Forwarded-For": "10.0.0.23"})
    check("forgot-password bob 200", r.status_code == 200, r.text)
    for i in range(5):
        r = client.post("/api/auth/reset-password",
                        json={"email": "bob@example.com", "code": "000000" if i else "111111",
                              "new_password": "BrandNew1!"},
                        headers={"X-Forwarded-For": "10.0.0.30"})
        check("wrong code attempt %d -> 400/429" % (i + 1), r.status_code in (400, 429), r.text)
    r = client.post("/api/auth/reset-password",
                    json={"email": "bob@example.com", "code": "000000", "new_password": "BrandNew1!"},
                    headers={"X-Forwarded-For": "10.0.0.30"})
    check("6th attempt locked out 429", r.status_code == 429, r.text)

    # successful reset for a fresh user + token revocation
    r = register("carol@example.com", ip="10.0.0.40")
    carol = r.json()
    carol_tok = carol["access_token"]
    client.post("/api/auth/forgot-password", json={"email": "carol@example.com"},
                headers={"X-Forwarded-For": "10.0.0.41"})
    code = raw_db().execute("SELECT verification_code FROM users WHERE id=?", (carol["user_id"],)).fetchone()[0]
    r = client.post("/api/auth/reset-password",
                    json={"email": "carol@example.com", "code": code, "new_password": "Another1!"},
                    headers={"X-Forwarded-For": "10.0.0.42"})
    check("valid reset 200", r.status_code == 200, r.text)
    r = client.post("/api/auth/reset-password",
                    json={"email": "carol@example.com", "code": code, "new_password": "Another1!"},
                    headers={"X-Forwarded-For": "10.0.0.43"})
    check("reset code is single-use", r.status_code == 400, r.text)

    r = client.get("/api/me", headers=auth(carol_tok))
    check("token issued before password reset is revoked", r.status_code == 401, r.text)
    r = login("carol@example.com", "Another1!", ip="10.0.0.44")
    check("login with new password 200", r.status_code == 200, r.text)
    fresh = r.json().get("access_token", "")
    r = client.get("/api/me", headers=auth(fresh))
    check("token issued right after reset is valid", r.status_code == 200, r.text)

    # ---------------------------------------------------------- legacy hash upgrade
    raw = raw_db()
    raw.execute("UPDATE users SET password_hash=? WHERE email=?",
                (hashlib.sha256(b"LegacyPass1").hexdigest(), "bob@example.com"))
    raw.commit()
    raw.close()
    r = login("bob@example.com", "LegacyPass1", ip="10.0.0.50")
    check("legacy sha256 password still logs in", r.status_code == 200, r.text)
    stored = raw_db().execute("SELECT password_hash FROM users WHERE email=?", ("bob@example.com",)).fetchone()[0]
    check("legacy hash upgraded to pbkdf2 on login", stored.startswith("pbkdf2_sha256$"), stored[:24])

    # ---------------------------------------------------------- rate limiting
    codes = []
    for i in range(12):
        codes.append(client.post("/api/login", json={"email": "alice@example.com", "password": "nope"},
                                 headers={"X-Forwarded-For": "10.9.9.9"}).status_code)
    check("login rate limit returns 429", 429 in codes, codes)
    check("rate limit kicks in at 11th request", codes[10] == 429, codes[:12])

    # ---------------------------------------------------------- verify-code flow
    r = client.post("/api/auth/request-code", json={"email": "carol@example.com"},
                    headers={"X-Forwarded-For": "10.0.0.60"})
    check("request-code stores code even if mail provider fails", r.status_code in (200, 502), r.text)
    vcode = raw_db().execute("SELECT verification_code FROM users WHERE email=?", ("carol@example.com",)).fetchone()[0]
    r = client.post("/api/auth/verify-code", json={"email": "carol@example.com", "code": "999999"},
                    headers={"X-Forwarded-For": "10.0.0.61"})
    check("verify-code wrong code 400", r.status_code == 400, r.text)
    if vcode != "999999":
        r = client.post("/api/auth/verify-code", json={"email": "carol@example.com", "code": vcode},
                        headers={"X-Forwarded-For": "10.0.0.62"})
        check("verify-code correct code 200", r.status_code == 200, r.text)
        check("verify-code sets is_verified",
              raw_db().execute("SELECT is_verified FROM users WHERE email=?", ("carol@example.com",)).fetchone()[0] == 1)

    r = client.post("/api/auth/request-code", json={"email": "bob@example.com"},
                    headers={"X-Forwarded-For": "10.0.0.63"})
    bcode = raw_db().execute("SELECT verification_code FROM users WHERE email=?", ("bob@example.com",)).fetchone()[0]
    raw = raw_db()
    raw.execute("UPDATE users SET verification_code_expires=? WHERE email=?",
                ("2020-01-01 00:00:00.000000", "bob@example.com"))
    raw.commit()
    raw.close()
    r = client.post("/api/auth/verify-code", json={"email": "bob@example.com", "code": bcode},
                    headers={"X-Forwarded-For": "10.0.0.64"})
    check("verify-code expired code 400", r.status_code == 400, r.text)

    # ---------------------------------------------------------- activation ownership
    raw = raw_db()
    raw.execute("INSERT INTO transactions (user_id, activation_id, phone_number, service, country, status, cost) "
                "VALUES (?,?,?,?,?,?,?)", (alice["user_id"], "ACT-1", "15550001111", "fb", 187, "PENDING", 0.5))
    raw.commit()
    raw.close()
    r = client.get("/api/check-sms/ACT-1", headers=auth(bob_tok))
    check("check-sms other user's activation 403", r.status_code == 403, r.text)
    r = client.post("/api/cancel/ACT-1", headers=auth(bob_tok))
    check("cancel other user's activation 403", r.status_code == 403, r.text)

    # ---------------------------------------------------------- gates unchanged
    r = client.post("/api/admin/add-funds?user_id=1&amount=100")
    check("admin route still 403 without key", r.status_code == 403, r.text)
    r = client.post("/api/admin/add-funds?user_id=1&amount=100", headers={"X-Admin-Key": "test-admin-key"})
    check("admin route works with key", r.status_code == 200, r.text)
    for path in ("/docs", "/redoc", "/openapi.json"):
        r = client.get(path)
        check("%s still 404" % path, r.status_code == 404, r.status_code)

else:
    # ---------------------------------------------------------- strict mode
    r = register("dave@example.com")
    dave = r.json()
    check("strict: register 200", r.status_code == 200, r.text)
    tok = dave["access_token"]

    r = client.get("/api/user/%d" % dave["user_id"])
    check("strict: legacy anonymous read 401", r.status_code == 401, r.text)
    r = client.get("/api/user/%d" % dave["user_id"], headers=auth(tok))
    check("strict: legacy read with own token 200", r.status_code == 200, r.text)

    r = client.post("/api/buy-number", json={"user_id": dave["user_id"], "service": "fb", "country": 187})
    check("strict: anonymous buy-number 401", r.status_code == 401, r.text)
    r = client.get("/api/history/%d" % dave["user_id"])
    check("strict: legacy history anonymous 401", r.status_code == 401, r.text)
    r = client.get("/api/active/%d" % dave["user_id"])
    check("strict: legacy active anonymous 401", r.status_code == 401, r.text)
    r = client.get("/api/referral/%d" % dave["user_id"])
    check("strict: legacy referral anonymous 401", r.status_code == 401, r.text)

print("\n%d passed, %d failed" % (len(PASS), len(FAIL)))
if FAIL:
    print("FAILED: " + ", ".join(FAIL))
    sys.exit(1)
