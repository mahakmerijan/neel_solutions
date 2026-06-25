import os, random, time, sqlite3, uuid, threading, json
from urllib import request as urlrequest
from urllib.error import URLError, HTTPError
from flask import Flask, send_from_directory, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message

app = Flask(__name__, static_folder=".", static_url_path="")
app.secret_key = os.environ.get("SECRET_KEY", "neel-solutions-dev-secret-2026")

# ── Mail ──────────────────────────────────────────────────────
app.config["MAIL_SERVER"]         = os.environ.get("MAIL_SERVER",   "smtp.gmail.com")
app.config["MAIL_PORT"]           = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"]        = os.environ.get("MAIL_USE_TLS",  "true").lower() == "true"
app.config["MAIL_USERNAME"]       = os.environ.get("MAIL_USERNAME")
app.config["MAIL_PASSWORD"]       = os.environ.get("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.environ.get("MAIL_SENDER") or os.environ.get("MAIL_USERNAME")
app.config["MAIL_TIMEOUT"]        = int(os.environ.get("MAIL_TIMEOUT", 10))
MAIL_ENABLED = bool(os.environ.get("MAIL_USERNAME"))
mail = Mail(app) if MAIL_ENABLED else None

# ── EmailJS (optional) ───────────────────────────────────────
EMAILJS_SERVICE_ID           = os.environ.get("EMAILJS_SERVICE_ID", "service_9ko6lao")
EMAILJS_APPROVAL_TEMPLATE_ID = os.environ.get("EMAILJS_APPROVAL_TEMPLATE_ID", "template_gvp6exk")
EMAILJS_PUBLIC_KEY           = os.environ.get("EMAILJS_PUBLIC_KEY", "8RVJ1Y6zL-VvkLeE1")
EMAILJS_PRIVATE_KEY          = os.environ.get("EMAILJS_PRIVATE_KEY")

# ── Admin credentials ─────────────────────────────────────────
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "NeelAdmin@2026")
ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL")  # where to send new-registration notifications

# ── Database ──────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

UPLOAD_FOLDER    = os.path.join(os.path.dirname(__file__), "uploads", "haat_bazar")
ALLOWED_IMG_EXTS = {"png", "jpg", "jpeg", "gif", "webp"}

def _allowed_img(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMG_EXTS

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            name          TEXT,
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            approved      INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS haat_bazar_ads (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            title         TEXT NOT NULL,
            category      TEXT NOT NULL,
            description   TEXT,
            price         TEXT,
            location      TEXT,
            contact_name  TEXT,
            contact_phone TEXT,
            contact_email TEXT,
            image_filename TEXT,
            posted_by     TEXT,
            created_at    TEXT DEFAULT (datetime('now','localtime'))
        )
    """)
    conn.commit()
    # Migration: add columns if they don't exist in older databases
    for migration in [
        "ALTER TABLE users ADD COLUMN name TEXT",
        "ALTER TABLE users ADD COLUMN approved INTEGER DEFAULT 0",
    ]:
        try:
            conn.execute(migration)
            conn.commit()
        except Exception:
            pass
    conn.close()

init_db()

OTP_EXPIRY = 600  # 10 minutes

def _otp():
    return str(random.randint(100000, 999999))

def _send_otp(email, otp, subject):
    if not MAIL_ENABLED or mail is None:
        raise RuntimeError("Mail not configured")
    msg = Message(subject, recipients=[email])
    msg.body = (
        f"Dear User,\n\n"
        f"Your One-Time Password (OTP) is: {otp}\n\n"
        f"This OTP is valid for 10 minutes. Do not share it with anyone.\n\n"
        f"– NEEL Solutions Team"
    )
    mail.send(msg)

def _send_admin_notification(user_email, name):
    """Notify admin when a new user registers."""
    if not MAIL_ENABLED or mail is None or not ADMIN_EMAIL:
        return
    try:
        msg = Message(
            "NEEL Solutions – New Registration Pending Approval",
            recipients=[ADMIN_EMAIL]
        )
        msg.body = (
            f"A new user has registered and is awaiting your approval.\n\n"
            f"Name:  {name or '(not provided)'}\n"
            f"Email: {user_email}\n\n"
            f"Please log in to the Admin Panel to approve or reject this request.\n\n"
            f"– NEEL Solutions System"
        )
        mail.send(msg)
    except Exception as e:
        print(f"[ERROR] Failed to send admin notification: {e}")

def _send_approval_email(user_email, name):
    """Send approval confirmation to the user."""
    site_url = os.environ.get("SITE_URL", "")

    # First preference: EmailJS API (if private key is configured).
    if EMAILJS_PRIVATE_KEY:
        try:
            payload = {
                "service_id": EMAILJS_SERVICE_ID,
                "template_id": EMAILJS_APPROVAL_TEMPLATE_ID,
                "user_id": EMAILJS_PUBLIC_KEY,
                "accessToken": EMAILJS_PRIVATE_KEY,
                "template_params": {
                    "to_name": name or user_email,
                    "to_email": user_email,
                    "login_url": site_url,
                    "user_email": user_email,
                    "site_name": "NEEL Solutions"
                }
            }
            req = urlrequest.Request(
                "https://api.emailjs.com/api/v1.0/email/send",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urlrequest.urlopen(req, timeout=10) as resp:
                _ = resp.read().decode("utf-8", errors="ignore")
                if resp.status >= 400:
                    raise RuntimeError(f"EmailJS failed with status {resp.status}")
            return
        except (HTTPError, URLError, Exception) as e:
            print(f"[ERROR] EmailJS approval mail failed: {e}")

    # Fallback: SMTP via Flask-Mail.
    if MAIL_ENABLED and mail is not None:
        try:
            msg = Message(
                "Your NEEL Solutions Account Has Been Approved!",
                recipients=[user_email]
            )
            msg.body = (
                f"Dear {name or user_email},\n\n"
                f"Great news! Your NEEL Solutions account has been approved.\n\n"
                f"You can now log in to your account"
                + (f" at: {site_url}" if site_url else "") + ".\n\n"
                f"Welcome aboard!\n\n"
                f"– NEEL Solutions Team"
            )
            mail.send(msg)
            return
        except Exception as e:
            print(f"[ERROR] SMTP approval mail failed: {e}")

    print("[WARN] Approval email not sent: neither EmailJS nor SMTP is fully configured.")

def _send_email_async(fn, *args):
    """Run email send in background so API responses do not block on SMTP."""
    def runner():
        try:
            with app.app_context():
                fn(*args)
        except Exception as e:
            print(f"[ERROR] Background email job failed: {e}")
    threading.Thread(target=runner, daemon=True).start()

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
    name     = (data.get("name") or "").strip()
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    if not email or "@" not in email:
        return jsonify({"success": False, "message": "Invalid email address."}), 400
    if len(password) < 6:
        return jsonify({"success": False, "message": "Password must be at least 6 characters."}), 400
    conn     = get_db()
    existing = conn.execute("SELECT id, approved FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if existing:
        if existing["approved"] == 0:
            return jsonify({"success": False, "message": "Your registration is already pending approval. Please wait for the approval email."}), 409
        return jsonify({"success": False, "message": "This email is already registered."}), 409
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (name, email, password_hash, approved) VALUES (?,?,?,0)",
            (name, email, generate_password_hash(password))
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"success": False, "message": "Registration failed. Please try again."}), 500
    conn.close()
    _send_email_async(_send_admin_notification, email, name)
    return jsonify({"success": True, "message": "Registration submitted! Your account is pending admin approval. You'll receive an email once it's activated."})

@app.route("/login", methods=["POST"])
def login():
    data     = request.get_json() or {}
    email    = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"success": False, "message": "Invalid email or password."}), 401
    if not user["approved"]:
        return jsonify({"success": False, "message": "⏳ Your account is pending admin approval. You'll receive an email once it's activated."}), 403
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
    user  = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    otp = _otp()
    session["reset_email"]    = email
    session["reset_otp"]      = otp
    session["reset_otp_time"] = time.time()
    if user:
        if not MAIL_ENABLED:
            print(f"[DEV] Reset OTP for {email}: {otp}")
            return jsonify({"success": True, "message": f"[Dev mode] Mail not configured. Your OTP is: {otp}"})
        try:
            _send_otp(email, otp, "NEEL Solutions – Password Reset OTP")
        except Exception as e:
            print(f"[ERROR] Failed to send reset OTP: {e}")
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

# ── Haat Bazar ───────────────────────────────────────────────
@app.route("/haat-bazar/ads", methods=["GET"])
def get_haat_bazar_ads():
    category = request.args.get("category", "")
    conn = get_db()
    if category and category != "All":
        ads = conn.execute(
            "SELECT * FROM haat_bazar_ads WHERE category=? ORDER BY created_at DESC",
            (category,)
        ).fetchall()
    else:
        ads = conn.execute(
            "SELECT * FROM haat_bazar_ads ORDER BY created_at DESC"
        ).fetchall()
    conn.close()
    return jsonify([dict(a) for a in ads])

@app.route("/haat-bazar/ads", methods=["POST"])
def post_haat_bazar_ad():
    title         = (request.form.get("title")         or "").strip()
    category      = (request.form.get("category")      or "").strip()
    description   = (request.form.get("description")   or "").strip()
    price         = (request.form.get("price")         or "").strip()
    location      = (request.form.get("location")      or "").strip()
    contact_name  = (request.form.get("contact_name")  or "").strip()
    contact_phone = (request.form.get("contact_phone") or "").strip()
    contact_email = (request.form.get("contact_email") or "").strip()
    posted_by     = session.get("user_email") or "Guest"
    if not title or not category or not contact_name or not contact_phone:
        return jsonify({"success": False, "message": "Please fill all required fields."}), 400
    image_filename = None
    if "image" in request.files:
        f = request.files["image"]
        if f and f.filename and _allowed_img(f.filename):
            os.makedirs(UPLOAD_FOLDER, exist_ok=True)
            ext = secure_filename(f.filename).rsplit(".", 1)[1].lower()
            image_filename = uuid.uuid4().hex + "." + ext
            f.save(os.path.join(UPLOAD_FOLDER, image_filename))
    conn = get_db()
    conn.execute(
        """INSERT INTO haat_bazar_ads
           (title,category,description,price,location,
            contact_name,contact_phone,contact_email,image_filename,posted_by)
           VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (title, category, description, price, location,
         contact_name, contact_phone, contact_email, image_filename, posted_by)
    )
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Ad posted successfully!"})

@app.route("/haat-bazar/ads/<int:ad_id>", methods=["DELETE"])
def delete_haat_bazar_ad(ad_id):
    user_email = session.get("user_email")
    if not user_email:
        return jsonify({"success": False, "message": "Login required."}), 401
    conn = get_db()
    ad = conn.execute("SELECT * FROM haat_bazar_ads WHERE id=?", (ad_id,)).fetchone()
    if not ad:
        conn.close()
        return jsonify({"success": False, "message": "Ad not found."}), 404
    if ad["posted_by"] != user_email:
        conn.close()
        return jsonify({"success": False, "message": "You can only delete your own ads."}), 403
    if ad["image_filename"]:
        img_path = os.path.join(UPLOAD_FOLDER, ad["image_filename"])
        if os.path.exists(img_path):
            os.remove(img_path)
    conn.execute("DELETE FROM haat_bazar_ads WHERE id=?", (ad_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "Ad deleted."})

@app.route("/uploads/haat_bazar/<filename>")
def serve_haat_bazar_upload(filename):
    return send_from_directory(UPLOAD_FOLDER, secure_filename(filename))

# ── Admin API ─────────────────────────────────────────────────
def _require_admin():
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "message": "Unauthorized."}), 401
    return None

@app.route("/admin/login", methods=["POST"])
def admin_login():
    data     = request.get_json() or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
        session["admin_logged_in"] = True
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid admin credentials."}), 401

@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("admin_logged_in", None)
    return jsonify({"success": True})

@app.route("/admin/check")
def admin_check():
    return jsonify({"admin": bool(session.get("admin_logged_in"))})

@app.route("/admin/pending-users")
def admin_pending_users():
    err = _require_admin()
    if err:
        return err
    conn  = get_db()
    users = conn.execute(
        "SELECT id, name, email FROM users WHERE approved=0 ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def admin_approve_user(user_id):
    err = _require_admin()
    if err:
        return err
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=? AND approved=0", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "User not found in pending list."}), 404
    conn.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    _send_email_async(_send_approval_email, user["email"], user["name"] or user["email"])
    login_url = os.environ.get("SITE_URL") or request.url_root.rstrip("/")
    return jsonify({
        "success": True,
        "message": f"User {user['email']} approved.",
        "user_email": user["email"],
        "user_name": user["name"] or user["email"],
        "login_url": login_url
    })

@app.route("/admin/reject/<int:user_id>", methods=["POST"])
def admin_reject_user(user_id):
    err = _require_admin()
    if err:
        return err
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=? AND approved=0", (user_id,)).fetchone()
    if not user:
        conn.close()
        return jsonify({"success": False, "message": "User not found in pending list."}), 404
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": f"Registration rejected for {user['email']}."})

if __name__ == "__main__":
    app.run()
