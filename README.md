# Suraksha Saathi — Professional Demo Platform

**Tagline:** Pause. Verify. Pay Safely.

A responsive, full-stack digital-risk protection demo focused on student payment-scam prevention, with supporting scam analysis for URLs, apps, brands, companies and messages.

## Included

- Student, Guardian and Admin role-based demo accounts
- Registration and login with password hashing and signed sessions
- SQLite persistence for users, analyses, payment requests and audit events
- Scam Analyzer with explainable indicator-based risk scoring
- Payment Safety workflow:
  - Up to ₹1,000: guardian approval is not required by the policy configured in this demo
  - Above ₹1,000: guardian approval is required
  - High-risk payment requests are held/blocked by the risk rule, even if guardian approval is requested
- Guardian approval/rejection page
- Dashboard cards, risk charts, evidence/report history and scam-network visualization
- Responsive dark UI, subtle motion, mobile navigation, polished footer
- Local sample/demo data; no live UPI/bank integration and no live platform crawling

## Run on Windows

1. Install Python 3.13 or another supported Python version.
2. Extract the ZIP to a folder.
3. Open the extracted `Suraksha_Saathi_Professional` folder in VS Code.
4. Open Terminal in that folder and run:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

5. Open `http://127.0.0.1:8000` in your browser.

If `py` is not available, use `python` instead. Keep the terminal open while using the website. Press `Ctrl+C` to stop the server.

## Demo accounts

The database seeds these accounts on first run:

- Student: `student@suraksha.demo` / `Student@123`
- Guardian: `guardian@suraksha.demo` / `Guardian@123`
- Admin: `admin@suraksha.demo` / `Admin@123`

For guardian approval testing, register a student and use `guardian@suraksha.demo` as the student's guardian email, or use the seeded student account (already linked to the demo guardian).

## Important boundaries

This is a functional academic prototype, not a production banking product. It does not connect to bank accounts, UPI, payment gateways, app stores or social platforms; it cannot intercept or automatically block real transactions. Risk scores are heuristic demo assessments, not proof that a service is fraudulent. Guardian approvals change the app's simulated payment status only.

Before public deployment, add HTTPS, secure secret management, CSRF protection, rate limiting, email verification, password reset, stronger audit controls, database migrations, privacy/retention policies and professional security testing.
