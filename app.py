import os, random, time, sqlite3, uuid
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
MAIL_ENABLED = bool(os.environ.get("MAIL_USERNAME"))
mail = Mail(app) if MAIL_ENABLED else None

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
            email         TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified      INTEGER DEFAULT 0
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
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if existing:
        return jsonify({"success": False, "message": "This email is already registered."}), 409
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (email, password_hash, verified) VALUES (?,?,1)",
            (email, generate_password_hash(password))
        )
        conn.commit()
    except Exception:
        conn.close()
        return jsonify({"success": False, "message": "Registration failed. Please try again."}), 500
    conn.close()
    return jsonify({"success": True, "message": "Account created! You can now log in."})

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

if __name__ == "__main__":
    app.run()
