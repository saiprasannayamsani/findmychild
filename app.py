from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from models.person import MissingPerson
from models.found import FoundPerson
from models.case import Case
from werkzeug.utils import secure_filename
import json, os, random, hashlib
from datetime import datetime

app = Flask(__name__)
app.secret_key = "reuniteai_secret_2025"

# ── file paths ────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
_DATA         = os.path.join(BASE_DIR, "data")
MISSING_FILE  = os.path.join(_DATA, "missing.json")
FOUND_FILE    = os.path.join(_DATA, "found.json")
CASES_FILE    = os.path.join(_DATA, "cases.json")
SMS_LOG_FILE  = os.path.join(_DATA, "sms_log.json")
OTP_LOG_FILE  = os.path.join(_DATA, "otp_log.json")
USERS_FILE    = os.path.join(_DATA, "users.json")
POLICE_FILE   = os.path.join(_DATA, "police_users.json")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXTS      = {"png", "jpg", "jpeg", "pdf"}
ALLOWED_IMG_EXTS  = {"png", "jpg", "jpeg", "webp"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

POLICE_STATION_PHONE = "9100000000"
POLICE_STATION_NAME  = "Local Police Station – Missing Persons Unit"

# ── helpers ───────────────────────────────────────────────
def load_json(path):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return []

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTS

def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMG_EXTS

def get_priority(age):
    age = int(age)
    if age <= 12 or age >= 60: return "CRITICAL"
    elif age <= 30:             return "HIGH"
    else:                       return "MEDIUM"

def get_escalation(reported_at):
    try:
        reported = datetime.strptime(reported_at, "%d %b %Y %H:%M")
        hours    = (datetime.now() - reported).total_seconds() / 3600
        if hours >= 72:   return "NATIONAL"
        elif hours >= 48: return "STATE"
        elif hours >= 24: return "DISTRICT"
        else:             return "LOCAL"
    except:
        return "LOCAL"

def get_alert_color(priority, escalation, status):
    if status == "Resolved":      return "green"
    if "Match" in status:         return "blue"
    if escalation == "NATIONAL":  return "darkred"
    if escalation == "STATE":     return "red"
    if escalation == "DISTRICT":  return "orange"
    if priority == "CRITICAL":    return "red"
    if priority == "HIGH":        return "orange"
    return "yellow"

def get_officers_notified(escalation):
    if escalation == "LOCAL":
        return ["Station House Officer (SHO)", "Duty Officer", "Missing Persons Unit"]
    elif escalation == "DISTRICT":
        return ["SHO", "Duty Officer", "District SP", "All Station SHOs in District"]
    elif escalation == "STATE":
        return ["Inspector General (IG)", "All District SPs", "State Missing Persons Bureau"]
    else:
        return ["Director General of Police (DGP)", "NCRB Delhi", "CBI Unit", "All State Police HQs"]

def enrich_missing(missing_list):
    for m in missing_list:
        m["escalation"] = get_escalation(m.get("reported_at",""))
        m["color"]      = get_alert_color(m.get("priority","MEDIUM"), m["escalation"], m.get("status","Missing"))
        m["officers"]   = get_officers_notified(m["escalation"])
    return missing_list

def is_logged_in():
    return "user_email" in session

def is_police_logged_in():
    return session.get("user_role") == "police"

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in():
            flash("Please login first to access this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def police_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not is_logged_in() or not is_police_logged_in():
            flash("Police login required to access this area.", "error")
            return redirect(url_for("police_login"))
        return f(*args, **kwargs)
    return decorated

# ── IMAGE MATCHING ALGORITHM ──────────────────────────────
def resolve_photo_path(photo_name):
    """Return full path for any photo — uploaded and default images both live in uploads/."""
    if not photo_name:
        return None
    path = os.path.join(UPLOAD_FOLDER, photo_name)
    return path if os.path.exists(path) else None

def compute_image_histogram(filepath):
    """Compute a normalised RGB histogram for an image file."""
    try:
        from PIL import Image
        import numpy as np
        img = Image.open(filepath).convert("RGB").resize((64, 64))
        arr = np.array(img)
        hist = []
        for ch in range(3):
            h, _ = np.histogram(arr[:, :, ch], bins=32, range=(0, 256))
            hist.append(h.astype(float))
        hist = np.concatenate(hist)
        norm = np.linalg.norm(hist)
        return hist / norm if norm > 0 else hist
    except Exception:
        return None

def compute_image_fingerprint(filepath):
    """Perceptual hash fingerprint using 8x8 DCT."""
    try:
        from PIL import Image
        import numpy as np
        img = Image.open(filepath).convert("L").resize((32, 32))
        arr = np.array(img, dtype=float)
        mean = arr.mean()
        return (arr > mean).flatten()
    except Exception:
        return None

def compute_image_hash(filepath):
    """MD5 hash of raw image bytes — reliable same-file detection regardless of filename."""
    try:
        import hashlib
        with open(filepath, "rb") as fh:
            return hashlib.md5(fh.read()).hexdigest()
    except Exception:
        return None

def histogram_similarity(h1, h2):
    if h1 is None or h2 is None:
        return 0.0
    try:
        import numpy as np
        return float(np.dot(h1, h2))
    except Exception:
        return 0.0

def fingerprint_similarity(f1, f2):
    if f1 is None or f2 is None:
        return 0.0
    try:
        import numpy as np
        matches = np.sum(f1 == f2)
        return float(matches) / len(f1)
    except Exception:
        return 0.0

IMAGE_MATCH_THRESHOLD = 0.55

def image_match_score(missing_photo, found_photo):
    """
    Score 0-1 using histogram + perceptual hash similarity.
    Exact same filename = 1.0 (definite match).
    Falls back to 0.5 if photos exist but can't be compared (age+gender already matched).
    """
    if missing_photo and found_photo and missing_photo == found_photo:
        return 1.0

    mp = resolve_photo_path(missing_photo)
    fp = resolve_photo_path(found_photo)

    if mp and fp:
        h1 = compute_image_histogram(mp)
        h2 = compute_image_histogram(fp)
        hist_score = histogram_similarity(h1, h2)

        p1 = compute_image_fingerprint(mp)
        p2 = compute_image_fingerprint(fp)
        phash_score = fingerprint_similarity(p1, p2)

        # Weighted combination: 60% histogram, 40% perceptual hash
        combined = 0.6 * hist_score + 0.4 * phash_score
        return min(combined, 1.0)

    # If one or both photos missing, return 0.5 so age+gender match still registers
    if missing_photo or found_photo:
        return 0.5
    return 0.5

# ── OTP & SMS ─────────────────────────────────────────────
def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(phone, otp, aadhaar):
    otp_log = load_json(OTP_LOG_FILE)
    otp_log.append({
        "phone":   phone,
        "aadhaar": aadhaar[-4:],
        "otp":     otp,
        "sent_at": datetime.now().strftime("%d %b %Y %H:%M"),
        "status":  "Sent"
    })
    save_json(OTP_LOG_FILE, otp_log)
    print(f"\n{'='*55}")
    print(f"[OTP] Aadhaar: XXXX-XXXX-{aadhaar[-4:]}")
    print(f"[OTP] To Phone: {phone}")
    print(f"[OTP] YOUR OTP IS: {otp}")
    print(f"[OTP] Message: Your ReuniteAI OTP is {otp}. Valid 10 mins.")
    print(f"{'='*55}\n")

def send_sms(phone, message, case_id=""):
    sms_log = load_json(SMS_LOG_FILE)
    sms_log.append({
        "to":      phone,
        "message": message,
        "case_id": case_id,
        "sent_at": datetime.now().strftime("%d %b %Y %H:%M"),
        "status":  "Delivered"
    })
    save_json(SMS_LOG_FILE, sms_log)
    print(f"[SMS] To: {phone} | {message}")

def send_police_alert(case_id, name, age, gender, location, priority, phone, reporter_name, relation):
    message = (
        f"🚨 NEW MISSING CASE #{case_id} | {POLICE_STATION_NAME} | "
        f"Name: {name} | Age: {age} | Gender: {gender} | "
        f"Last Seen: {location} | Priority: {priority} | "
        f"Reporter: {reporter_name} ({relation}) Ph: {phone} | "
        f"View: http://127.0.0.1:5000/police"
    )
    send_sms(POLICE_STATION_PHONE, message, case_id)

def auto_match(missing_person, found_list):
    """Match using age+gender first, then image similarity if photos available."""
    best_match = None
    best_score = -1.0
    for f in found_list:
        age_match    = abs(int(missing_person["age"]) - int(f["age"])) <= 5
        gender_match = missing_person["gender"].lower() == f["gender"].lower()
        if age_match and gender_match:
            # Try image matching
            score = image_match_score(missing_person.get("child_photo",""), f.get("found_photo",""))
            if score > best_score or best_match is None:
                best_score = score
                best_match = f
    if best_match:
        best_match["_match_score"] = round(max(best_score, 0) * 100, 1)
    return best_match

def auto_match_reverse(found_person, missing_list):
    best_match = None
    best_score = -1.0
    for m in missing_list:
        if m["status"] in ["Missing", "Match Found - Police Notified"]:
            age_match    = abs(int(found_person["age"]) - int(m["age"])) <= 5
            gender_match = found_person["gender"].lower() == m["gender"].lower()
            if age_match and gender_match:
                score = image_match_score(m.get("child_photo",""), found_person.get("found_photo",""))
                if score > best_score or best_match is None:
                    best_score = score
                    best_match = m
    if best_match:
        best_match["_match_score"] = round(max(best_score, 0) * 100, 1)
    return best_match

def get_bot_response(msg):
    msg = msg.lower()
    if any(w in msg for w in ["login","register","signup","account","email"]):
        return "To use ReuniteAI, first register with your email and password. Then login to file complaints. Police officers use a separate Police Login."
    elif any(w in msg for w in ["birth","certificate","document","fake"]):
        return "Birth certificate is required to prove your relationship with the missing person. The registration number is verified against the government CRS database."
    elif any(w in msg for w in ["aadhaar","otp","verify"]):
        return "Two Aadhaar numbers are required: 1) Missing person's Aadhaar — to identify them. 2) Your (reporter's) Aadhaar — OTP sent here to verify you are real."
    elif any(w in msg for w in ["report","missing","lost"]):
        return "To report a missing person: Login → Report Missing → Fill details → Upload photo → Enter both Aadhaar numbers → Verify OTP → Case registered and police alerted instantly!"
    elif any(w in msg for w in ["found","find"]):
        return "If you found a missing person: Login → Report Found → Fill details + upload photo → Verify Aadhaar OTP → AI checks all missing reports → If match found, family gets SMS immediately!"
    elif any(w in msg for w in ["police"]):
        return "Police officers can register at /police/register and login at /police/login. They get a dedicated dashboard to manage all cases, see found-person images, and resolve cases."
    elif any(w in msg for w in ["hello","hi","help"]):
        return "Hello! I am ReuniteAI Assistant. I can help with: Login/Register, reporting missing/found, Aadhaar OTP, birth certificate, case tracking. What do you need?"
    else:
        return "For emergencies call: Missing Helpline 1094, Childline 1098, Police 100. Ask me about login, Aadhaar verification, reporting, or case tracking."

# ── PUBLIC AUTH ROUTES ────────────────────────────────────

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        users    = load_json(USERS_FILE)
        email    = request.form["email"].lower().strip()
        password = request.form["password"]
        name     = request.form["name"]
        phone    = request.form["phone"]
        if any(u["email"] == email for u in users):
            flash("❌ Email already registered. Please login.", "error")
            return redirect(url_for("register"))
        if len(password) < 6:
            flash("❌ Password must be at least 6 characters.", "error")
            return redirect(url_for("register"))
        user = {
            "name":       name,
            "email":      email,
            "password":   hash_password(password),
            "phone":      phone,
            "role":       "public",
            "registered": datetime.now().strftime("%d %b %Y %H:%M")
        }
        users.append(user)
        save_json(USERS_FILE, users)
        send_sms(phone, f"Welcome to ReuniteAI! Your account {email} is registered.")
        flash("✅ Account created successfully! Please login.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if is_logged_in():
        return redirect(url_for("home"))
    if request.method == "POST":
        users    = load_json(USERS_FILE)
        email    = request.form["email"].lower().strip()
        password = request.form["password"]
        user     = next((u for u in users if u["email"] == email and u["password"] == hash_password(password)), None)
        if user:
            session["user_email"] = user["email"]
            session["user_name"]  = user["name"]
            session["user_role"]  = user["role"]
            flash(f"✅ Welcome back, {user['name']}!", "success")
            return redirect(url_for("home"))
        else:
            flash("❌ Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("✅ You have been logged out successfully.", "success")
    return redirect(url_for("login"))

# ── POLICE AUTH ROUTES ────────────────────────────────────

@app.route("/police/register", methods=["GET","POST"])
def police_register():
    if request.method == "POST":
        police_users  = load_json(POLICE_FILE)
        badge_id      = request.form["badge_id"].strip().upper()
        name          = request.form["name"].strip()
        station       = request.form["station"].strip()
        email         = request.form["email"].lower().strip()
        password      = request.form["password"]
        phone         = request.form["phone"].strip()

        if any(u["badge_id"] == badge_id for u in police_users):
            flash("❌ Badge ID already registered.", "error")
            return redirect(url_for("police_register"))
        if any(u["email"] == email for u in police_users):
            flash("❌ Email already registered.", "error")
            return redirect(url_for("police_register"))
        if len(password) < 6:
            flash("❌ Password must be at least 6 characters.", "error")
            return redirect(url_for("police_register"))

        officer = {
            "badge_id":   badge_id,
            "name":       name,
            "station":    station,
            "email":      email,
            "password":   hash_password(password),
            "phone":      phone,
            "role":       "police",
            "registered": datetime.now().strftime("%d %b %Y %H:%M")
        }
        police_users.append(officer)
        save_json(POLICE_FILE, police_users)

        # Also add to main users so they can login via same session system
        users = load_json(USERS_FILE)
        users.append({
            "name":       name,
            "email":      email,
            "password":   hash_password(password),
            "phone":      phone,
            "role":       "police",
            "badge_id":   badge_id,
            "station":    station,
            "registered": datetime.now().strftime("%d %b %Y %H:%M")
        })
        save_json(USERS_FILE, users)

        flash(f"✅ Police officer {name} (Badge: {badge_id}) registered! Please login.", "success")
        return redirect(url_for("police_login"))
    return render_template("police_register.html")

@app.route("/police/login", methods=["GET","POST"])
def police_login():
    if is_police_logged_in():
        return redirect(url_for("police_dashboard"))
    if request.method == "POST":
        badge_id = request.form["badge_id"].strip().upper()
        password = request.form["password"]
        police_users = load_json(POLICE_FILE)
        officer = next((u for u in police_users if u["badge_id"] == badge_id and u["password"] == hash_password(password)), None)
        if officer:
            session["user_email"]  = officer["email"]
            session["user_name"]   = officer["name"]
            session["user_role"]   = "police"
            session["badge_id"]    = officer["badge_id"]
            session["station"]     = officer["station"]
            flash(f"✅ Welcome, Officer {officer['name']} (Badge: {badge_id})", "success")
            return redirect(url_for("police_dashboard"))
        else:
            flash("❌ Invalid Badge ID or password.", "error")
    return render_template("police_login.html")

# ── MAIN ROUTES ───────────────────────────────────────────

@app.route("/")
def home():
    missing   = enrich_missing(load_json(MISSING_FILE))
    found     = load_json(FOUND_FILE)
    cases     = load_json(CASES_FILE)
    sms_log   = load_json(SMS_LOG_FILE)
    resolved  = [c for c in cases if c["status"] == "Resolved"]
    recent    = [m for m in missing if m["status"] == "Missing"][-3:][::-1]
    all_cases_enriched = enrich_missing(load_json(MISSING_FILE))
    police_alerts = [s for s in reversed(sms_log) if s.get("to") == POLICE_STATION_PHONE][:5]
    # Found persons with photos for gallery
    found_with_photos = [f for f in found if f.get("found_photo")]
    return render_template("home.html",
                           total_missing=len(missing),
                           total_found=len(found),
                           total_resolved=len(resolved),
                           recent_alerts=recent,
                           all_cases=all_cases_enriched,
                           cases_list=cases,
                           police_alerts=police_alerts,
                           found_with_photos=found_with_photos)

@app.route("/report-missing", methods=["GET","POST"])
@login_required
def report_missing():
    if request.method == "POST":
        cert_filename = ""
        if "birth_cert" in request.files:
            file = request.files["birth_cert"]
            if file and file.filename and allowed_file(file.filename):
                cert_filename = secure_filename(f"cert_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
                file.save(os.path.join(app.config["UPLOAD_FOLDER"], cert_filename))

        child_photo = ""
        if "child_photo" in request.files:
            photo = request.files["child_photo"]
            if photo and photo.filename and allowed_image(photo.filename):
                child_photo = secure_filename(f"photo_{datetime.now().strftime('%Y%m%d%H%M%S')}_{photo.filename}")
                photo.save(os.path.join(app.config["UPLOAD_FOLDER"], child_photo))

        session["missing_form"] = {
            "name":            request.form["name"],
            "age":             request.form["age"],
            "gender":          request.form["gender"],
            "location":        request.form["location"],
            "date":            request.form["date"],
            "desc":            request.form.get("desc",""),
            "missing_aadhaar": request.form["missing_aadhaar"],
            "birth_cert_reg":  request.form.get("birth_cert_reg",""),
            "cert_filename":   cert_filename,
            "child_photo":     child_photo,
            "reporter_name":   session.get("user_name",""),
            "reporter_email":  session.get("user_email",""),
            "reporter_aadhaar": request.form["reporter_aadhaar"],
            "phone":           request.form["phone"],
            "relation":        request.form["relation"]
        }
        otp = generate_otp()
        session["otp"]      = otp
        session["otp_type"] = "missing"
        send_otp(request.form["phone"], otp, request.form["reporter_aadhaar"])
        flash("✅ OTP sent to your Aadhaar-linked mobile! Check terminal for OTP.", "success")
        return redirect(url_for("verify_otp"))
    return render_template("report_missing.html")

@app.route("/report-found", methods=["GET","POST"])
@login_required
def report_found():
    if request.method == "POST":
        found_photo = ""

        # Priority 1: uploaded file
        if "found_photo" in request.files:
            photo = request.files["found_photo"]
            if photo and photo.filename and allowed_image(photo.filename):
                found_photo = secure_filename(f"found_{datetime.now().strftime('%Y%m%d%H%M%S')}_{photo.filename}")
                photo.save(os.path.join(app.config["UPLOAD_FOLDER"], found_photo))

        # Priority 2: default pre-loaded image selected from grid
        if not found_photo:
            default_choice = request.form.get("default_found_photo", "").strip()
            # Validate it's one of our known defaults (security check)
            allowed_defaults = [f"default_found_{i}.jpg" for i in range(1, 7)]
            if default_choice in allowed_defaults:
                found_photo = default_choice

        session["found_form"] = {
            "found_name": request.form.get("found_name", "").strip(),
            "age":       request.form["age"],
            "gender":    request.form["gender"],
            "location":  request.form["location"],
            "condition": request.form["condition"],
            "desc":      request.form.get("desc",""),
            "phone":     request.form["phone"],
            "aadhaar":   request.form["aadhaar"],
            "found_photo": found_photo,
            "reporter_email": session.get("user_email","")
        }
        otp = generate_otp()
        session["otp"]      = otp
        session["otp_type"] = "found"
        send_otp(request.form["phone"], otp, request.form["aadhaar"])
        flash("✅ OTP sent! Check terminal for OTP.", "success")
        return redirect(url_for("verify_otp"))
    return render_template("report_found.html")

@app.route("/verify-otp", methods=["GET","POST"])
@login_required
def verify_otp():
    if "otp" not in session:
        flash("Session expired. Please fill the form again.", "error")
        return redirect(url_for("home"))

    if request.method == "POST":
        entered  = request.form.get("otp","").strip()
        if entered != session.get("otp"):
            flash("❌ Wrong OTP! Please try again.", "error")
            return render_template("verify_otp.html")

        otp_type = session.get("otp_type")

        if otp_type == "missing":
            form     = session.get("missing_form",{})
            missing  = load_json(MISSING_FILE)
            priority = get_priority(form["age"])

            # Block duplicate: same name + aadhaar last 4 already in active cases
            aadhaar_last4 = form["missing_aadhaar"][-4:]
            duplicate = any(
                m.get("name","").lower().strip() == form["name"].lower().strip() and
                m.get("missing_aadhaar","") == aadhaar_last4 and
                m.get("status") not in ["Resolved"]
                for m in missing
            )
            if duplicate:
                flash(f"⚠️ A missing report for '{form['name']}' with this Aadhaar already exists and is active. No duplicate created.", "error")
                session.pop("missing_form", None)
                session.pop("otp", None)
                session.pop("otp_type", None)
                return redirect(url_for("cases"))

            person   = MissingPerson(
                case_id          = f"RC-{2000 + len(missing) + 1}",
                name             = form["name"],
                age              = form["age"],
                gender           = form["gender"],
                location         = form["location"],
                date             = form["date"],
                desc             = form["desc"],
                missing_aadhaar  = form["missing_aadhaar"][-4:],
                birth_cert_reg   = form["birth_cert_reg"],
                cert_filename    = form["cert_filename"],
                child_photo      = form.get("child_photo",""),
                reporter_name    = form["reporter_name"],
                reporter_email   = form["reporter_email"],
                reporter_aadhaar = form["reporter_aadhaar"][-4:],
                phone            = form["phone"],
                relation         = form["relation"],
                priority         = priority,
                status           = "Missing",
                escalation       = "LOCAL"
            )
            missing.append(person.to_dict())
            save_json(MISSING_FILE, missing)

            send_police_alert(
                case_id       = person.case_id,
                name          = form["name"],
                age           = form["age"],
                gender        = form["gender"],
                location      = form["location"],
                priority      = priority,
                phone         = form["phone"],
                reporter_name = form["reporter_name"],
                relation      = form["relation"]
            )

            link = f"http://127.0.0.1:5000/track/{person.case_id}"
            send_sms(form["phone"],
                     f"FindMyChild: Case #{person.case_id} for {form['name']} registered. "
                     f"Priority: {priority}. Police alerted. Track: {link}",
                     person.case_id)

            found_list = load_json(FOUND_FILE)
            match = auto_match(person.to_dict(), found_list)
            if match:
                score = match.get("_match_score", 0)
                cases = load_json(CASES_FILE)
                case  = Case(f"CASE-{len(cases)+1}", person.to_dict(), match, "Match Found - Police Notified")
                case_dict = case.to_dict()
                cases.append(case_dict)
                save_json(CASES_FILE, cases)
                # Update missing person status to Match Found
                all_missing = load_json(MISSING_FILE)
                for m in all_missing:
                    if m["case_id"] == person.case_id:
                        m["status"] = "Match Found - Police Notified"
                save_json(MISSING_FILE, all_missing)
                send_sms(form["phone"],
                         f"FindMyChild MATCH FOUND! {form['name']} (#{person.case_id}) "
                         f"may have been found! Image similarity: {score}%. Come to police station. Track: {link}",
                         person.case_id)
                flash(f"✅ OTP Verified! Case #{person.case_id} registered! 🤖 AI MATCH FOUND (score: {score}%)! SMS sent!", "match")
            else:
                flash(f"✅ OTP Verified! Case #{person.case_id} registered! Priority: {priority}. SMS sent.", "success")

            session.pop("missing_form", None)
            session.pop("otp", None)
            session.pop("otp_type", None)
            return redirect(url_for("cases"))

        elif otp_type == "found":
            form       = session.get("found_form",{})
            found_list = load_json(FOUND_FILE)

            # Block duplicate: same reporter aadhaar + age + gender OR same photo filename
            aadhaar_last4 = form["aadhaar"][-4:]
            submitted_photo = form.get("found_photo", "")
            duplicate = any(
                (
                    f.get("aadhaar","") == aadhaar_last4 and
                    str(f.get("age","")) == str(form["age"]) and
                    f.get("gender","").lower() == form["gender"].lower()
                ) or (
                    submitted_photo and
                    f.get("found_photo","") == submitted_photo and
                    not submitted_photo.startswith("default_found_")
                )
                for f in found_list
            )
            if duplicate:
                flash("⚠️ This person has already been reported as found. No duplicate created.", "error")
                session.pop("found_form", None)
                session.pop("otp", None)
                session.pop("otp_type", None)
                return redirect(url_for("cases"))

            person     = FoundPerson(
                case_id        = f"RF-{1000 + len(found_list) + 1}",
                age            = form["age"],
                gender         = form["gender"],
                location       = form["location"],
                condition      = form["condition"],
                desc           = form["desc"],
                phone          = form["phone"],
                aadhaar        = form["aadhaar"][-4:],
                found_photo    = form.get("found_photo",""),
                reporter_email = form["reporter_email"],
                found_name     = form.get("found_name","")
            )
            found_list.append(person.to_dict())
            save_json(FOUND_FILE, found_list)

            missing = load_json(MISSING_FILE)
            match   = auto_match_reverse(person.to_dict(), missing)
            if match:
                score = match.get("_match_score", 0)
                cases = load_json(CASES_FILE)
                # Check if a case already exists for this missing person
                existing_case = next((c for c in cases if c.get("missing",{}).get("case_id") == match["case_id"]), None)
                if not existing_case:
                    case  = Case(f"CASE-{len(cases)+1}", match, person.to_dict(), "Match Found - Police Notified")
                    case_dict = case.to_dict()
                    cases.append(case_dict)
                    save_json(CASES_FILE, cases)
                # Update missing person status
                for m in missing:
                    if m["case_id"] == match["case_id"]:
                        m["status"] = "Match Found - Police Notified"
                save_json(MISSING_FILE, missing)
                link = f"http://127.0.0.1:5000/track/{match['case_id']}"
                send_sms(match["phone"],
                         f"FindMyChild GREAT NEWS! {match['name']} (#{match['case_id']}) may have been found at {person.location}! "
                         f"Come to police station immediately. Track: {link}",
                         match["case_id"])
                flash(f"🤖 OTP Verified! AI MATCH FOUND! SMS sent to {match['name']}'s family. Police notified! They have been asked to come to the station.", "match")
            else:
                flash(f"✅ OTP Verified! Found person registered. Case #{person.case_id}. AI will keep monitoring.", "success")

            session.pop("found_form", None)
            session.pop("otp", None)
            session.pop("otp_type", None)
            return redirect(url_for("found_gallery"))

    otp_value = session.get("otp","")
    form = session.get("missing_form") or session.get("found_form") or {}
    otp_phone = form.get("phone","")
    return render_template("verify_otp.html", otp_value=otp_value, otp_phone=otp_phone)

@app.route("/resend-otp")
@login_required
def resend_otp():
    form = session.get("missing_form") or session.get("found_form")
    if not form:
        flash("Session expired. Please fill the form again.", "error")
        return redirect(url_for("home"))
    otp = generate_otp()
    session["otp"] = otp
    send_otp(form["phone"], otp, form.get("reporter_aadhaar", form.get("aadhaar","")))
    flash("✅ New OTP sent.", "success")
    return redirect(url_for("verify_otp"))

# ── FOUND GALLERY (public visible) ───────────────────────

@app.route("/found-gallery")
def found_gallery():
    all_found  = load_json(FOUND_FILE)
    missing    = enrich_missing(load_json(MISSING_FILE))
    # Only show found entries whose photo file actually exists on disk
    found_list = [f for f in all_found if f.get("found_photo") and
                  os.path.exists(os.path.join(UPLOAD_FOLDER, f["found_photo"]))]
    # Attach match info to each found person
    for f in found_list:
        f["match_info"] = None
        for m in missing:
            age_ok    = abs(int(f["age"]) - int(m["age"])) <= 3
            gender_ok = f["gender"].lower() == m["gender"].lower()
            if age_ok and gender_ok and m["status"] in ["Missing","Match Found - Police Notified"]:
                score = image_match_score(m.get("child_photo",""), f.get("found_photo",""))
                f["match_info"] = {"case_id": m["case_id"], "name": m["name"], "score": round(score*100,1)}
                break
    return render_template("found_gallery.html", found_list=found_list[::-1], missing=missing)

@app.route("/track/<case_id>")
def track_case(case_id):
    missing  = load_json(MISSING_FILE)
    cases    = load_json(CASES_FILE)
    sms_log  = load_json(SMS_LOG_FILE)
    child    = next((m for m in missing if m["case_id"] == case_id), None)
    if not child:
        flash("Case ID not found.", "error")
        return redirect(url_for("home"))
    child["escalation"] = get_escalation(child.get("reported_at",""))
    child["color"]      = get_alert_color(child.get("priority","MEDIUM"), child["escalation"], child.get("status","Missing"))
    child["officers"]   = get_officers_notified(child["escalation"])
    matched_case = next((c for c in cases if c["missing"].get("case_id") == case_id), None)
    case_sms     = [s for s in sms_log if s.get("case_id") == case_id]
    return render_template("track.html", child=child, matched_case=matched_case, sms_history=case_sms)

@app.route("/check-escalation")
@login_required
def check_escalation():
    missing = load_json(MISSING_FILE)
    updated = False
    for m in missing:
        if m["status"] not in ["Resolved","Match Found - Police Notified"]:
            old_esc = m.get("escalation","LOCAL")
            new_esc = get_escalation(m.get("reported_at",""))
            if new_esc != old_esc:
                m["escalation"] = new_esc
                link = f"http://127.0.0.1:5000/track/{m['case_id']}"
                msgs = {
                    "DISTRICT": f"FindMyChild: {m['name']} (#{m['case_id']}) ESCALATED to DISTRICT police. Track: {link}",
                    "STATE":    f"FindMyChild URGENT: {m['name']} (#{m['case_id']}) ESCALATED to STATE police. Track: {link}",
                    "NATIONAL": f"FindMyChild NATIONAL: {m['name']} (#{m['case_id']}) entered NCRB database. Track: {link}"
                }
                if new_esc in msgs:
                    send_sms(m["phone"], msgs[new_esc], m["case_id"])
                updated = True
    if updated:
        save_json(MISSING_FILE, missing)
        flash("✅ Escalations updated. SMS sent to families.", "success")
    else:
        flash("ℹ️ All cases are at current escalation level.", "success")
    return redirect(url_for("police_dashboard"))

@app.route("/cases")
def cases():
    missing    = enrich_missing(load_json(MISSING_FILE))
    found_list = load_json(FOUND_FILE)
    cases_list = load_json(CASES_FILE)
    return render_template("cases.html", missing=missing[::-1], found=found_list[::-1], cases=cases_list[::-1])

# ── POLICE DASHBOARD ──────────────────────────────────────

@app.route("/police")
@police_required
def police_dashboard():
    missing    = enrich_missing(load_json(MISSING_FILE))
    found_list = load_json(FOUND_FILE)
    cases_list = load_json(CASES_FILE)
    sms_log    = load_json(SMS_LOG_FILE)
    priority_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2}
    active   = sorted([m for m in missing if m["status"]=="Missing"],
                      key=lambda x: priority_order.get(x.get("priority","MEDIUM"),2))
    matched  = [m for m in missing if "Match" in m.get("status","")]
    resolved = [c for c in cases_list if c["status"]=="Resolved"]
    return render_template("police.html",
                           active=active, matched=matched,
                           resolved=resolved, cases=cases_list,
                           total_missing=len(missing),
                           total_found=len(found_list),
                           total_resolved=len(resolved),
                           sms_log=sms_log[-10:][::-1],
                           found_list=found_list)

@app.route("/police/resolve/<case_id>")
@police_required
def resolve_case(case_id):
    cases_list   = load_json(CASES_FILE)
    missing      = load_json(MISSING_FILE)
    parent_phone = ""
    person_name  = ""
    for c in cases_list:
        if c["case_id"] == case_id:
            c["status"]      = "Resolved"
            c["resolved_at"] = datetime.now().strftime("%d %b %Y %H:%M")
            parent_phone     = c["missing"].get("phone","")
            person_name      = c["missing"].get("name","")
    for m in missing:
        for c in cases_list:
            if c["case_id"] == case_id and c["missing"].get("case_id") == m["case_id"]:
                m["status"] = "Resolved"
    save_json(CASES_FILE, cases_list)
    save_json(MISSING_FILE, missing)
    if parent_phone:
        send_sms(parent_phone,
                 f"FindMyChild: {person_name} has been safely reunited! Case #{case_id} RESOLVED. Thank you! ❤️",
                 case_id)
    flash(f"✅ Case {case_id} resolved! SMS sent to family!", "success")
    return redirect(url_for("police_dashboard"))

@app.route("/police/contact-parent/<case_id>")
@police_required
def contact_parent(case_id):
    missing = load_json(MISSING_FILE)
    person  = next((m for m in missing if m["case_id"] == case_id), None)
    if not person:
        flash("Case not found.", "error")
        return redirect(url_for("police_dashboard"))
    link = f"http://127.0.0.1:5000/track/{case_id}"
    escalation = get_escalation(person.get("reported_at",""))
    officers   = get_officers_notified(escalation)
    send_sms(
        person["phone"],
        f"FindMyChild Police Update: Your case #{case_id} for {person['name']} is being actively investigated. "
        f"Escalation level: {escalation}. Officers: {', '.join(officers[:2])}. Track: {link}",
        case_id
    )
    flash(f"✅ Police update SMS sent to {person['phone']} (parent of {person['name']})!", "success")
    return redirect(url_for("police_dashboard"))

@app.route("/police/notifications")
@police_required
def police_notifications():
    sms_log = load_json(SMS_LOG_FILE)
    notifications = []
    for s in reversed(sms_log):
        msg = s.get("message","")
        to  = s.get("to","")
        n = {
            "to":      to,
            "message": msg,
            "sent_at": s.get("sent_at",""),
            "case_id": s.get("case_id",""),
            "type":    "OTHER",
            "ntype":   "default",
            "title":   "System Notification"
        }
        if to == POLICE_STATION_PHONE or "NEW MISSING CASE" in msg:
            n["type"]="NEW_CASE"; n["ntype"]="red"; n["title"]="New Missing Case Alert"
        elif "MATCH FOUND" in msg or "GREAT NEWS" in msg:
            n["type"]="MATCH"; n["ntype"]="blue"; n["title"]="AI Match Found"
        elif "ESCALATED" in msg or "NATIONAL" in msg:
            n["type"]="ESCALATION"; n["ntype"]="orange"; n["title"]="Case Escalation Alert"
        elif "RESOLVED" in msg or "reunited" in msg.lower():
            n["type"]="RESOLVED"; n["ntype"]="green"; n["title"]="Case Resolved"
        elif "Police Update" in msg:
            n["type"]="UPDATE"; n["ntype"]="teal"; n["title"]="Police Update Sent to Parent"
        else:
            continue
        notifications.append(n)
    return render_template("police_notifications.html", notifications=notifications)

@app.route("/sms-log")
@login_required
def sms_log_page():
    sms_log = load_json(SMS_LOG_FILE)
    otp_log = load_json(OTP_LOG_FILE)
    return render_template("sms_log.html", sms_log=sms_log[::-1], otp_log=otp_log[::-1])

@app.route("/search")
def search():
    query      = request.args.get("q","").lower()
    missing    = enrich_missing(load_json(MISSING_FILE))
    found_list = load_json(FOUND_FILE)
    results    = [c for c in missing if query in c.get("name","").lower() or query in c["case_id"].lower()]
    results   += [c for c in found_list if query in c["case_id"].lower()]
    return render_template("search.html", results=results, query=query)

@app.route("/report")
def analytics():
    missing    = load_json(MISSING_FILE)
    found_list = load_json(FOUND_FILE)
    cases_list = load_json(CASES_FILE)
    sms_log    = load_json(SMS_LOG_FILE)
    otp_log    = load_json(OTP_LOG_FILE)
    users      = load_json(USERS_FILE)
    resolved   = [c for c in cases_list if c["status"]=="Resolved"]
    matched    = [c for c in cases_list if "Match" in c.get("status","")]
    critical   = [m for m in missing if m.get("priority")=="CRITICAL"]
    national   = [m for m in missing if get_escalation(m.get("reported_at",""))=="NATIONAL"]
    return render_template("report.html",
                           total_missing=len(missing),
                           total_found=len(found_list),
                           total_cases=len(cases_list),
                           total_resolved=len(resolved),
                           total_matched=len(matched),
                           total_critical=len(critical),
                           total_national=len(national),
                           total_sms=len(sms_log),
                           total_otp=len(otp_log),
                           total_users=len(users),
                           cases=cases_list[::-1])

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    from flask import send_from_directory
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/chatbot", methods=["GET","POST"])
def chatbot():
    response = ""
    user_msg = ""
    if request.method == "POST":
        user_msg = request.form.get("message","")
        response = get_bot_response(user_msg)
    return render_template("chatbot.html", response=response, user_msg=user_msg)


# ── LIVE PHOTO MATCH API (missing form → check found persons) ─────────────────
@app.route("/api/check-photo-match", methods=["POST"])
@login_required
def check_photo_match():
    import uuid
    age       = request.form.get("age", "").strip()
    gender    = request.form.get("gender", "").strip()
    orig_name = request.form.get("original_filename", "").strip()

    if "photo" not in request.files:
        return jsonify({"error": "No photo"}), 400
    photo = request.files["photo"]
    if not photo or not photo.filename or not allowed_image(photo.filename):
        return jsonify({"error": "Invalid image"}), 400

    ext      = photo.filename.rsplit(".", 1)[1].lower()
    tmp_name = f"tmp_miss_{uuid.uuid4().hex}.{ext}"
    tmp_path = os.path.join(UPLOAD_FOLDER, tmp_name)
    photo.save(tmp_path)
    # NOTE: keep temp file for image comparison, delete after

    found_list = load_json(FOUND_FILE)
    matches    = []

    # Pre-compute histogram/fingerprint/hash for uploaded missing photo
    miss_hist  = compute_image_histogram(tmp_path)
    miss_phash = compute_image_fingerprint(tmp_path)
    miss_hash  = compute_image_hash(tmp_path)

    # Pre-load hashes of all found photos once
    found_hashes = {}
    for f in found_list:
        fp = resolve_photo_path(f.get("found_photo", ""))
        if fp:
            found_hashes[f["case_id"]] = compute_image_hash(fp)

    for f in found_list:
        found_photo = f.get("found_photo", "")

        # 1. Filename-based confirmation (user uploads same file, same or similar name)
        filename_confirmed = bool(orig_name and found_photo and
                           (orig_name == found_photo or
                            found_photo.endswith("_" + orig_name) or
                            orig_name.endswith("_" + found_photo)))

        # 2. Hash-based confirmation (same image bytes, any filename)
        found_hash = found_hashes.get(f["case_id"])
        hash_confirmed = bool(miss_hash and found_hash and miss_hash == found_hash)

        confirmed = filename_confirmed or hash_confirmed

        # 3. Image visual similarity
        found_path = resolve_photo_path(found_photo)
        if found_path and miss_hist is not None:
            f_hist  = compute_image_histogram(found_path)
            f_phash = compute_image_fingerprint(found_path)
            img_score = int((0.6 * histogram_similarity(miss_hist, f_hist) +
                             0.4 * fingerprint_similarity(miss_phash, f_phash)) * 100)
        else:
            img_score = 0

        score = 100 if confirmed else img_score

        try:
            age_diff = abs(int(age) - int(f["age"])) if age else 0
        except (ValueError, TypeError):
            age_diff = 99
        gender_match = (gender.lower() == f["gender"].lower()) if gender else True

        # Determine match type:
        # confirmed (hash/filename) → ALWAYS show as "Already Found" regardless of age/gender
        # high img similarity (≥85%) → show as "Image Match Found"
        # age+gender only → show as subtle visual reference card
        is_high_img_match = img_score >= 85

        if confirmed:
            matches.append({
                "case_id":    f["case_id"],
                "age":        f["age"],
                "gender":     f["gender"],
                "location":   f["location"],
                "condition":  f["condition"],
                "desc":       f.get("desc", ""),
                "found_photo": found_photo,
                "found_name": f.get("found_name", ""),
                "reported_at": f.get("reported_at", ""),
                "score":      100,
                "confirmed":  True,
                "match_type": "exact",
                "match_reason": "hash" if hash_confirmed else "filename"
            })
        elif is_high_img_match:
            matches.append({
                "case_id":    f["case_id"],
                "age":        f["age"],
                "gender":     f["gender"],
                "location":   f["location"],
                "condition":  f["condition"],
                "desc":       f.get("desc", ""),
                "found_photo": found_photo,
                "found_name": f.get("found_name", ""),
                "reported_at": f.get("reported_at", ""),
                "score":      score,
                "confirmed":  False,
                "match_type": "image_similar",
                "match_reason": "visual"
            })
        # Age+gender-only reference cards removed — face image match required

    # Clean up temp file after comparisons
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    # Deduplicate by case_id
    seen = set()
    unique_matches = []
    for m in matches:
        if m["case_id"] not in seen:
            seen.add(m["case_id"])
            unique_matches.append(m)

    # Confirmed first, then closest age
    try:
        unique_matches.sort(key=lambda x: (not x["confirmed"], abs(int(age or 0) - int(x["age"]))))
    except Exception:
        pass

    # Only face/image matches — no age+gender-only cautions
    return jsonify({"matches": unique_matches[:1], "age_gender_cautions": []})


# ── REVERSE: found form → check missing persons ───────────────────────────────
@app.route("/api/check-found-match", methods=["POST"])
@login_required
def check_found_match():
    import uuid
    age       = request.form.get("age", "").strip()
    gender    = request.form.get("gender", "").strip()
    orig_name = request.form.get("original_filename", "").strip()

    if "photo" not in request.files:
        return jsonify({"error": "No photo"}), 400
    photo = request.files["photo"]
    if not photo or not photo.filename or not allowed_image(photo.filename):
        return jsonify({"error": "Invalid image"}), 400

    ext      = photo.filename.rsplit(".", 1)[1].lower()
    tmp_name = f"tmp_fnd_{uuid.uuid4().hex}.{ext}"
    tmp_path = os.path.join(UPLOAD_FOLDER, tmp_name)
    photo.save(tmp_path)
    # NOTE: do NOT delete tmp_path here — we need it for image comparison below

    missing_list = load_json(MISSING_FILE)
    matches      = []

    # Pre-compute histogram/fingerprint for uploaded found photo
    found_hist  = compute_image_histogram(tmp_path)
    found_phash = compute_image_fingerprint(tmp_path)

    for m in missing_list:
        if m.get("status") not in ["Missing", "Match Found - Police Notified", "Resolved"]:
            continue
        child_photo = m.get("child_photo", "")
        # confirmed if the original filename matches the end of stored filename
        # stored format: "photo_TIMESTAMP_originalname.jpg"
        confirmed   = bool(orig_name and child_photo and
                           (orig_name == child_photo or
                            child_photo.endswith("_" + orig_name)))

        # Compute image similarity using the uploaded temp file
        missing_path = resolve_photo_path(child_photo)
        if missing_path and found_hist is not None:
            m_hist  = compute_image_histogram(missing_path)
            m_phash = compute_image_fingerprint(missing_path)
            img_score = int((0.6 * histogram_similarity(found_hist, m_hist) +
                             0.4 * fingerprint_similarity(found_phash, m_phash)) * 100)
        else:
            img_score = 0

        score = 100 if confirmed else img_score

        try:
            age_diff = abs(int(age) - int(m["age"])) if age else 0
        except (ValueError, TypeError):
            age_diff = 99
        gender_match = (gender.lower() == m["gender"].lower()) if gender else True

        if confirmed or (gender_match and age_diff <= 5):
            matches.append({
                "case_id":     m["case_id"],
                "name":        m.get("name", "Unknown"),
                "age":         m["age"],
                "gender":      m["gender"],
                "location":    m.get("location", ""),
                "reported_at": m.get("reported_at", ""),
                "child_photo": child_photo,
                "status":      m.get("status", "Missing"),
                "priority":    m.get("priority", ""),
                "score":       score,
                "confirmed":   confirmed
            })

    # Clean up temp file after all comparisons are done
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    # Deduplicate by case_id
    seen = set()
    unique_matches = []
    for m in matches:
        if m["case_id"] not in seen:
            seen.add(m["case_id"])
            unique_matches.append(m)

    try:
        unique_matches.sort(key=lambda x: (not x["confirmed"], abs(int(age or 0) - int(x["age"]))))
    except Exception:
        pass

    # Deduplicate by name+age+gender - same child submitted twice shows only once
    seen_person = set()
    final_matches = []
    for m in unique_matches:
        person_key = (m.get("name", "").lower().strip(), str(m.get("age", "")), m.get("gender", "").lower())
        if person_key not in seen_person:
            seen_person.add(person_key)
            final_matches.append(m)

    return jsonify({"matches": final_matches[:1]})


if __name__ == "__main__":
    os.makedirs(_DATA,         exist_ok=True)
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(debug=True)
