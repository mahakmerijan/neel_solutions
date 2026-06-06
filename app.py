import os, random, time, sqlite3
from flask import Flask, send_from_directory, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "neel-solutions-dev-secret-2026")

# ── Mail ──────────────────────────────────────────────────────
app.config["MAIL_SERVER"]         = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
app.config["MAIL_PORT"]           = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"]        = os.environ.get("MAIL_USE_TLS",  "true").lower() == "true"
app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_USERNAME")
mail = Mail(app)

# ── Database ──────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified      INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()

OTP_EXPIRY = 600  # 10 minutes

def _otp():
    return str(random.randint(100000, 999999))

def _send_otp(email, otp, subject):
    msg = Message(subject, recipients=[email])
    msg.body = (
        f"Dear User,\n\n"
        f"Your One-Time Password (OTP) is: {otp}\n\n"
        f"This OTP is valid for 10 minutes. Do not share it with anyone.\n\n"
        f"– NEEL Solutions Team"
    )
    mail.send(msg)

# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/check-auth")
def check_auth():
    if session.get("user_email"):
        return jsonify({"logged_in": True, "email": session["user_email"]})
    return jsonify({"logged_in": False})

@app.route("/register", methods=["POST"])
def register():
    data     = request.get_json() or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Invalid email address."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    conn     = get_db()
    existing = conn.execute("SELECT verified FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if existing and existing["verified"]:
        return jsonify({"success": False, "message": "This email is already registered."}), 409
    otp = _otp()
    session["reg_email"]         = email
    session["reg_password_hash"] = generate_password_hash(password)
    session["reg_otp"]           = otp
    session["reg_otp_time"]      = time.time()
    try:
        _send_otp(email, otp, "NEEL Solutions – Registration OTP")
    except Exception:
        return jsonify({"success": False, "message": "Could not send OTP. Please check email settings."}), 500
    return jsonify({"success": True, "message": "OTP sent to your email."})

@app.route("/verify-register", methods=["POST"])
def verify_register():
    data = request.get_json() or {}
    otp  = (data.get("otp") or "").strip()
    if not session.get("reg_otp") or time.time() - session.get("reg_otp_time", 0) > OTP_EXPIRY:
        return jsonify({"success": False, "message": "OTP expired. Please register again."}), 400
    if otp != session["reg_otp"]:
        return jsonify({"success": False, "message": "Incorrect OTP. Please try again."}), 400
    email         = session["reg_email"]
    password_hash = session["reg_password_hash"]
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR REPLACE INTO users (email, password_hash, verified) VALUES (?,?,1)",
            (email, password_hash)
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"success": False, "message": "Registration failed. Please try again."}), 500
    conn.close()
    for k in ["reg_email", "reg_password_hash", "reg_otp", "reg_otp_time"]:
        session.pop(k, None)
    return jsonify({"success": True, "message": "Registration successful! You can now log in."})

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=? AND verified=1", (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
    session["user_email"] = email
    return jsonify({"success": True, "message": "Logged in successfully.", "email": email})

@app.route("/logout", methods=["POST"])
def logout():
    session.pop("user_email", None)
    return jsonify({"success": True})

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    data  = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    conn  = get_db()
    user  = conn.execute("SELECT id FROM users WHERE email=? AND verified=1", (email,)).fetchone()
    conn.close()
    otp = _otp()
    session["reset_email"]    = email
    session["reset_otp"]      = otp
    session["reset_otp_time"] = time.time()
    if user:
        try:
            _send_otp(email, otp, "NEEL Solutions – Password Reset OTP")
        except Exception:
            return jsonify({"success": False, "message": "Could not send OTP. Please try again."}), 500
    # Always return success to prevent email enumeration
    return jsonify({"success": True, "message": "If this email is registered, an OTP has been sent."})

@app.route("/verify-reset", methods=["POST"])
def verify_reset():
    data = request.get_json() or {}
    otp  = (data.get("otp") or "").strip()
    if not session.get("reset_otp") or time.time() - session.get("reset_otp_time", 0) > OTP_EXPIRY:
        return jsonify({"success": False, "message": "OTP expired. Please try again."}), 400
    if otp != session["reset_otp"]:
        return jsonify({"success": False, "message": "Incorrect OTP. Please try again."}), 400
    session["reset_verified"] = True
    return jsonify({"success": True})

@app.route("/reset-password", methods=["POST"])
def reset_password():
    if not session.get("reset_verified"):
        return jsonify({"success": False, "message": "OTP not verified."}), 403
    data     = request.get_json() or {}
    password = data.get("password") or ""
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    email = session.get("reset_email")
    conn  = get_db()
    conn.execute("UPDATE users SET password_hash=? WHERE email=?", (generate_password_hash(password), email))
    conn.commit()
    conn.close()
    for k in ["reset_email", "reset_otp", "reset_otp_time", "reset_verified"]:
        session.pop(k, None)
    return jsonify({"success": True, "message": "Password reset successfully. You can now log in."})

if __name__ == "__main__":
    app.run()
