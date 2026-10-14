import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DATABASE_PATH", os.path.join(APP_DIR, "suraksha_saathi.db"))
SECRET_KEY = os.getenv("SURAKSHA_SECRET_KEY", "local-demo-secret-change-before-deployment")

app = FastAPI(title="Suraksha Saathi", description="Digital risk and payment scam protection demo")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=False)
app.mount("/static", StaticFiles(directory=os.path.join(APP_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(APP_DIR, "templates"))

def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000).hex()
    return f"{salt}${digest}"

def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 180_000).hex()
        return hmac.compare_digest(candidate, digest)
    except Exception:
        return False

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
          password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student',
          guardian_email TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS analyses (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          input_value TEXT NOT NULL, input_type TEXT NOT NULL, risk_score INTEGER NOT NULL,
          verdict TEXT NOT NULL, indicators TEXT NOT NULL, recommendation TEXT NOT NULL,
          created_at TEXT NOT NULL, FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS payments (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
          payee TEXT NOT NULL, destination TEXT NOT NULL, amount REAL NOT NULL,
          purpose TEXT NOT NULL, risk_score INTEGER NOT NULL, risk_level TEXT NOT NULL,
          status TEXT NOT NULL, guardian_email TEXT DEFAULT '', reason TEXT NOT NULL,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
          FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
          action TEXT NOT NULL, details TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)
        seeds = [
            ("Demo Student", "student@suraksha.demo", "Student@123", "student", "guardian@suraksha.demo"),
            ("Demo Guardian", "guardian@suraksha.demo", "Guardian@123", "guardian", ""),
            ("Suraksha Admin", "admin@suraksha.demo", "Admin@123", "admin", ""),
        ]
        for name, email, password, role, guardian_email in seeds:
            existing = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if not existing:
                con.execute("INSERT INTO users(name,email,password_hash,role,guardian_email,created_at) VALUES(?,?,?,?,?,?)",
                            (name, email, hash_password(password), role, guardian_email, now()))
        student = con.execute("SELECT id FROM users WHERE email='student@suraksha.demo'").fetchone()
        if student:
            count = con.execute("SELECT COUNT(*) AS n FROM analyses WHERE user_id=?", (student["id"],)).fetchone()["n"]
            if count == 0:
                samples = [
                    ("https://secure-bank.example-login.co/verify", "URL", 82, "High risk",
                     "Brand-like wording; unusual domain structure; urgent verification pattern",
                     "Do not enter credentials. Visit the organization through its official app or manually typed official domain."),
                    ("Scholarship reward: pay ₹499 processing fee now", "Message", 68, "High risk",
                     "Upfront fee request; urgency; promised reward",
                     "Verify the scheme with the official institution before paying. Never pay to unlock an unverified benefit."),
                    ("Example Campus Store", "Brand", 18, "Low risk",
                     "No strong indicators detected in the supplied text",
                     "This is not a guarantee of legitimacy. Verify ownership and independent contact details."),
                ]
                for val, typ, score, verdict, indicators, recommendation in samples:
                    con.execute("INSERT INTO analyses(user_id,input_value,input_type,risk_score,verdict,indicators,recommendation,created_at) VALUES(?,?,?,?,?,?,?,?)",
                                (student["id"], val, typ, score, verdict, indicators, recommendation, now()))
        if student:
            pc = con.execute("SELECT COUNT(*) AS n FROM payments WHERE user_id=?", (student["id"],)).fetchone()["n"]
            if pc == 0:
                con.execute("""INSERT INTO payments(user_id,payee,destination,amount,purpose,risk_score,risk_level,status,guardian_email,reason,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (student["id"], "Unknown Rewards App", "rewards-example.invalid", 1500, "Demo wallet top-up", 76, "High", "Blocked",
                 "guardian@suraksha.demo", "High-risk indicators detected; request held by safety policy.", now(), now()))
        con.execute("INSERT INTO audit_events(user_id,action,details,created_at) VALUES(NULL,?,?,?)",
                    ("system_initialized", "Suraksha Saathi demo database initialized", now()))

init_db()

def current_user(request):
    uid = request.session.get("user_id")
    if not uid:
        return None
    with db() as con:
        row = con.execute("SELECT id,name,email,role,guardian_email,created_at FROM users WHERE id=?", (uid,)).fetchone()
        return dict(row) if row else None

def audit(user_id, action, details):
    with db() as con:
        con.execute("INSERT INTO audit_events(user_id,action,details,created_at) VALUES(?,?,?,?)",
                    (user_id, action, details[:500], now()))
def render(request, name, **context):
    user = current_user(request)
    return templates.TemplateResponse(
        request=request,
        name=name,
        context={
            "request": request,
            "user": user,
            "year": datetime.now().year,
            **context
        }
    )
def require_user(request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please sign in first.")
    return user

def risk_assessment(value, kind="URL"):
    text = (value or "").strip()
    low = text.lower()
    indicators = []
    score = 8
    risky_terms = ["urgent", "verify now", "free money", "guaranteed return", "double your money",
                   "processing fee", "claim reward", "limited time", "account blocked", "otp", "seed phrase",
                   "betting", "investment", "withdrawal fee", "scholarship fee", "instant profit"]
    for term in risky_terms:
        if term in low:
            score += 11 if term in ["guaranteed return", "double your money", "seed phrase", "otp"] else 7
            indicators.append(f"Risk phrase detected: “{term}”")
    if re.search(r"(https?://)?\d{1,3}(?:\.\d{1,3}){3}", low):
        score += 20
        indicators.append("URL uses a raw IP address")
    if low.count("@") > 0 and ("http" in low or kind.lower() == "url"):
        score += 18
        indicators.append("URL may contain misleading user-info syntax")
    if kind.lower() == "url" or "http" in low or "." in low:
        try:
            candidate = text if "://" in text else "https://" + text
            parsed = urlparse(candidate)
            host = (parsed.hostname or "").lower()
            if host:
                if host.startswith("xn--") or ".xn--" in host:
                    score += 16
                    indicators.append("Internationalized/punycode domain needs extra verification")
                if host.count("-") >= 2:
                    score += 10
                    indicators.append("Domain contains multiple hyphens")
                if any(x in host for x in ["login-", "verify-", "secure-", "wallet-", "claim-"]):
                    score += 12
                    indicators.append("Security/claim wording appears in the domain")
                known_words = ["google", "bank", "pay", "scholarship", "amazon", "microsoft", "instagram"]
                if any(w in host for w in known_words) and not any(host.endswith(s) for s in [".google.com", ".amazon.com", ".microsoft.com", ".instagram.com"]):
                    score += 13
                    indicators.append("Brand-like wording in a domain; verify the exact official domain")
                if host.endswith((".zip", ".top", ".click", ".work", ".support")):
                    score += 9
                    indicators.append("Domain ending is often used in abuse; verify independently")
        except Exception:
            pass
    if len(text) > 180:
        score += 4
        indicators.append("Long input; inspect links and claims carefully")
    if not indicators:
        indicators.append("No strong heuristic indicators found in the submitted sample")
    score = min(99, max(3, score))
    verdict = "High risk" if score >= 60 else ("Review carefully" if score >= 30 else "Low risk indicators")
    recommendation = ("Do not pay or share passwords/OTPs. Verify using an independently found official contact channel."
                      if score >= 60 else
                      "Pause and verify the exact domain, organization and payment recipient before proceeding."
                      if score >= 30 else
                      "No strong indicators were detected, but this is not proof that the service is legitimate.")
    return score, verdict, " • ".join(indicators), recommendation

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if current_user(request):
        return RedirectResponse("/dashboard", status_code=303)
    return render(request, "landing.html")

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, error: str = ""):
    return render(request, "login.html", error=error)

@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE lower(email)=lower(?)", (email.strip(),)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return RedirectResponse("/login?error=Email%20or%20password%20is%20incorrect", status_code=303)
    request.session.clear()
    request.session["user_id"] = row["id"]
    audit(row["id"], "login", "Signed in")
    return RedirectResponse("/dashboard", status_code=303)

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, error: str = ""):
    return render(request, "register.html", error=error)

@app.post("/register")
def register(request: Request, name: str = Form(...), email: str = Form(...),
             password: str = Form(...), role: str = Form("student"), guardian_email: str = Form("")):
    name, email, role = name.strip(), email.strip().lower(), role.strip().lower()
    if role not in {"student", "guardian"}:
        return RedirectResponse("/register?error=Choose%20Student%20or%20Guardian", status_code=303)
    if len(password) < 8:
        return RedirectResponse("/register?error=Password%20must%20be%20at%20least%208%20characters", status_code=303)
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return RedirectResponse("/register?error=Enter%20a%20valid%20email", status_code=303)
    try:
        with db() as con:
            con.execute("INSERT INTO users(name,email,password_hash,role,guardian_email,created_at) VALUES(?,?,?,?,?,?)",
                        (name, email, hash_password(password), role, guardian_email.strip().lower(), now()))
            uid = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
        request.session["user_id"] = uid
        audit(uid, "register", f"Created {role} account")
        return RedirectResponse("/dashboard", status_code=303)
    except sqlite3.IntegrityError:
        return RedirectResponse("/register?error=That%20email%20already%20has%20an%20account", status_code=303)

@app.post("/logout")
def logout(request: Request):
    user = current_user(request)
    if user:
        audit(user["id"], "logout", "Signed out")
    request.session.clear()
    return RedirectResponse("/", status_code=303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as con:
        if user["role"] == "guardian":
            payments = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id WHERE lower(p.guardian_email)=lower(?) ORDER BY p.id DESC LIMIT 8", (user["email"],)).fetchall()
            analyses = []
            all_count = len(payments)
            high_count = sum(1 for p in payments if p["risk_level"] == "High")
            pending = sum(1 for p in payments if p["status"] == "Pending guardian approval")
            recent = [dict(p) for p in payments]
        elif user["role"] == "admin":
            payments = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 8").fetchall()
            analyses = con.execute("SELECT a.*,u.name AS owner_name FROM analyses a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 6").fetchall()
            all_count = con.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
            high_count = con.execute("SELECT COUNT(*) n FROM analyses WHERE risk_score>=60").fetchone()["n"]
            pending = con.execute("SELECT COUNT(*) n FROM payments WHERE status='Pending guardian approval'").fetchone()["n"]
            recent = [dict(p) for p in payments]
        else:
            payments = con.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 6", (user["id"],)).fetchall()
            analyses = con.execute("SELECT * FROM analyses WHERE user_id=? ORDER BY id DESC LIMIT 5", (user["id"],)).fetchall()
            all_count = con.execute("SELECT COUNT(*) n FROM analyses WHERE user_id=?", (user["id"],)).fetchone()["n"]
            high_count = con.execute("SELECT COUNT(*) n FROM analyses WHERE user_id=? AND risk_score>=60", (user["id"],)).fetchone()["n"]
            pending = con.execute("SELECT COUNT(*) n FROM payments WHERE user_id=? AND status='Pending guardian approval'", (user["id"],)).fetchone()["n"]
            recent = [dict(p) for p in payments]
    return render(request, "dashboard.html", analyses=[dict(a) for a in analyses], payments=recent,
                  all_count=all_count, high_count=high_count, pending=pending)

@app.get("/analyzer", response_class=HTMLResponse)
def analyzer_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return render(request, "analyzer.html", result=None)

@app.post("/analyzer")
def analyzer(request: Request, input_value: str = Form(...), input_type: str = Form("URL")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    input_value = input_value.strip()
    if not input_value:
        return RedirectResponse("/analyzer", status_code=303)
    score, verdict, indicators, recommendation = risk_assessment(input_value, input_type)
    with db() as con:
        con.execute("INSERT INTO analyses(user_id,input_value,input_type,risk_score,verdict,indicators,recommendation,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (user["id"], input_value[:1000], input_type[:40], score, verdict, indicators, recommendation, now()))
    audit(user["id"], "analysis_created", f"{input_type}: risk score {score}")
    result = {"input_value": input_value, "input_type": input_type, "risk_score": score,
              "verdict": verdict, "indicators": indicators.split(" • "), "recommendation": recommendation}
    return render(request, "analyzer.html", result=result)

@app.get("/payments", response_class=HTMLResponse)
def payments_page(request: Request, error: str = ""):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as con:
        if user["role"] == "guardian":
            rows = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id WHERE lower(p.guardian_email)=lower(?) ORDER BY p.id DESC", (user["email"],)).fetchall()
        elif user["role"] == "admin":
            rows = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC").fetchall()
        else:
            rows = con.execute("SELECT * FROM payments WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return render(request, "payments.html", payments=[dict(r) for r in rows], error=error)

@app.post("/payments")
def create_payment(request: Request, payee: str = Form(...), destination: str = Form(...),
                   amount: float = Form(...), purpose: str = Form(...), guardian_email: str = Form("")):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "student":
        return RedirectResponse("/payments?error=Only%20student%20accounts%20can%20create%20a%20payment%20request", status_code=303)
    if amount <= 0 or amount > 10000000:
        return RedirectResponse("/payments?error=Enter%20a%20valid%20amount", status_code=303)
    score, verdict, indicators, _ = risk_assessment(f"{payee} {destination} {purpose}", "Payment")
    guardian = guardian_email.strip().lower() or user.get("guardian_email", "")
    if score >= 60:
        status, reason, level = "Blocked", "High-risk indicators detected. Request is held by the safety policy.", "High"
    elif amount > 1000:
        status, reason, level = "Pending guardian approval", "Amount is above ₹1,000; guardian approval is required by this demo policy.", "Elevated" if score >= 30 else "Low"
    else:
        status, reason, level = "Approved by policy", "Amount is ₹1,000 or less and no high-risk indicator triggered. This is a simulated approval, not a real payment.", "Elevated" if score >= 30 else "Low"
    with db() as con:
        con.execute("""INSERT INTO payments(user_id,payee,destination,amount,purpose,risk_score,risk_level,status,guardian_email,reason,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (user["id"], payee.strip()[:150], destination.strip()[:300], amount, purpose.strip()[:300],
                     score, level, status, guardian, reason + " Indicators: " + indicators, now(), now()))
    audit(user["id"], "payment_request_created", f"Payee={payee[:80]}; amount={amount}; status={status}")
    return RedirectResponse("/payments", status_code=303)

@app.post("/payments/{payment_id}/decision")
def payment_decision(request: Request, payment_id: int, decision: str = Form(...)):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    decision = decision.lower().strip()
    if decision not in {"approve", "reject"}:
        raise HTTPException(400, "Invalid decision")
    with db() as con:
        payment = con.execute("SELECT * FROM payments WHERE id=?", (payment_id,)).fetchone()
        if not payment:
            raise HTTPException(404, "Payment request not found")
        allowed = user["role"] == "admin" or (user["role"] == "guardian" and payment["guardian_email"].lower() == user["email"].lower())
        if not allowed:
            raise HTTPException(403, "Only the linked guardian or admin can decide this request")
        if payment["status"] == "Blocked" or payment["risk_level"] == "High":
            new_status = "Blocked"
            reason = "Safety policy keeps high-risk requests blocked; guardian approval cannot override this rule."
        elif payment["status"] != "Pending guardian approval":
            new_status = payment["status"]
            reason = "This request is not awaiting guardian approval."
        elif decision == "approve":
            new_status = "Guardian approved (simulated)"
            reason = "Guardian approved in the demo. This does not initiate a real transfer."
        else:
            new_status = "Rejected by guardian"
            reason = "Guardian rejected the simulated payment request."
        con.execute("UPDATE payments SET status=?,reason=?,updated_at=? WHERE id=?",
                    (new_status, reason, now(), payment_id))
    audit(user["id"], "payment_decision", f"Payment {payment_id}: {new_status}")
    return RedirectResponse("/payments", status_code=303)

@app.get("/network", response_class=HTMLResponse)
def network_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return render(request, "network.html")

@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db() as con:
        if user["role"] == "admin":
            analyses = con.execute("SELECT a.*,u.name AS owner_name FROM analyses a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC").fetchall()
            events = con.execute("SELECT e.*,u.name AS actor_name FROM audit_events e LEFT JOIN users u ON u.id=e.user_id ORDER BY e.id DESC LIMIT 30").fetchall()
        else:
            analyses = con.execute("SELECT * FROM analyses WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
            events = con.execute("SELECT * FROM audit_events WHERE user_id=? ORDER BY id DESC LIMIT 20", (user["id"],)).fetchall()
    return render(request, "reports.html", analyses=[dict(a) for a in analyses], events=[dict(e) for e in events])

@app.get("/guardian", response_class=HTMLResponse)
def guardian_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] not in {"guardian", "admin"}:
        return RedirectResponse("/payments", status_code=303)
    with db() as con:
        if user["role"] == "admin":
            rows = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id WHERE p.status='Pending guardian approval' OR p.status='Blocked' ORDER BY p.id DESC").fetchall()
        else:
            rows = con.execute("SELECT p.*,u.name AS student_name FROM payments p JOIN users u ON u.id=p.user_id WHERE lower(p.guardian_email)=lower(?) ORDER BY p.id DESC", (user["email"],)).fetchall()
    return render(request, "guardian.html", payments=[dict(r) for r in rows])

@app.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    if not current_user(request):
        return RedirectResponse("/login", status_code=303)
    return render(request, "settings.html")

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        return RedirectResponse("/dashboard", status_code=303)
    with db() as con:
        users = con.execute("SELECT id,name,email,role,guardian_email,created_at FROM users ORDER BY id DESC").fetchall()
        events = con.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 30").fetchall()
    return render(request, "admin.html", users=[dict(u) for u in users], events=[dict(e) for e in events])

@app.get("/health")
def health():
    return {"status": "ok", "app": "Suraksha Saathi", "database": "sqlite"}
