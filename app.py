import os
import hashlib
import io
import re
import pytesseract
from PIL import Image
from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from datetime import datetime
import pytz

app = Flask(__name__)
app.secret_key = "vault_secret"

# ---------------- CONFIG ----------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

UPLOAD_FOLDER = os.path.join(os.getcwd(), "VaultCloud")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- LOGIN ----------------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ---------------- MODELS ----------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password = db.Column(db.String(120))

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('Asia/Kolkata')))
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(100))
    status = db.Column(db.String(20))
    details = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ENCRYPTION ----------------
KEY_FILE = "vault.key"
if os.path.exists(KEY_FILE):
    KEY = open(KEY_FILE, "rb").read()
else:
    KEY = Fernet.generate_key()
    open(KEY_FILE, "wb").write(KEY)

cipher = Fernet(KEY)

# ---------------- SCAN FUNCTION ----------------
def scan_content(text):
    leaks = []
    
    # 1. Refined Credit Card (Matches digits ONLY if preceded by CC keywords)
    card_pattern = r'(?i)(?:card|cc|visa|master|debit|payment)[\s\w]*[:#-]?\s*(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})'
    potential_cards = re.findall(card_pattern, text)
    for card in potential_cards:
        if is_luhn_valid(card):
            leaks.append("Verified Credit Card")
            break

    # 2. Indian Bank Account Numbers
    if re.search(r'(?i)(?:account|a/c|acc|acct)[\s.]{0,3}#?[:\s-]*(\d{9,18})', text):
        leaks.append("Bank Account Number")

    # 3. IFSC Codes
    if re.search(r'[A-Z]{4}0[A-Z0-9]{6}', text):
        leaks.append("Bank IFSC Code")

    # 4. Cheque Number
    if re.search(r'(?i)cheque[\s\w]*[:#-]?\s*(\d{6})', text):
        leaks.append("Cheque Number")

    # 5. Passbook/Customer ID
    if re.search(r'(?i)(?:cust|customer|passbook|cif)[\s\w]*[:#-]?\s*([a-zA-Z0-9]{8,12})', text):
        leaks.append("Passbook/CIF Detail")

    # 6. PAN Card
    if re.search(r'[A-Z]{5}[0-9]{4}[A-Z]{1}', text):
        leaks.append("PAN Card")

    # 7. System Secrets
    if re.search(r'(?i)(password|secret|apikey|token)[\s:=]+[\'"]?([a-zA-Z0-9_-]{16,})[\'"]?', text):
        leaks.append("System Secret/Token")

    # 8. Aadhaar Number
    if re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text):
        leaks.append("Aadhaar Number")

    return leaks   # 🔥 THIS WAS MISSING

# ---------------- ROUTES ----------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash("Username exists")
            return redirect('/register')

        user = User(
            username=request.form['username'],
            password=generate_password_hash(request.form['password'])
        )
        db.session.add(user)
        db.session.commit()
        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect('/')
        flash("Invalid login")

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')


@app.route('/')
@login_required
def index():
    files = FileRecord.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', files=files)


# ---------------- UPLOAD ----------------
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files['file']

    if not file:
        flash("No file selected")
        return redirect('/')

    temp_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(temp_path)

    text = ""

    try:
        if file.filename.lower().endswith(('png', 'jpg', 'jpeg')):
            text = pytesseract.image_to_string(Image.open(temp_path))
        else:
            text = open(temp_path, errors='ignore').read()

    except:
        pass

    # DEBUG (optional)
    print("TEXT:", text[:200])

    leaks = scan_content(text)

    if leaks:
        os.remove(temp_path)

        db.session.add(AuditLog(
            user_id=current_user.id,
            action="Upload",
            status="Blocked",
            details=", ".join(leaks)
        ))
        db.session.commit()

        flash(f"🚨 Blocked: {', '.join(leaks)}")
        return redirect('/')

    # Encrypt
    raw = open(temp_path, 'rb').read()
    encrypted = cipher.encrypt(raw)

    safe_name = hashlib.sha256(f"{current_user.id}_{file.filename}".encode()).hexdigest()
    open(os.path.join(UPLOAD_FOLDER, safe_name), 'wb').write(encrypted)

    os.remove(temp_path)

    db.session.add(FileRecord(filename=file.filename, user_id=current_user.id))
    db.session.add(AuditLog(
        user_id=current_user.id,
        action="Upload",
        status="Success",
        details=file.filename
    ))
    db.session.commit()

    flash("Uploaded successfully")
    return redirect('/')


# ---------------- DOWNLOAD ----------------
@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    record = FileRecord.query.get_or_404(file_id)

    safe_name = hashlib.sha256(f"{current_user.id}_{record.filename}".encode()).hexdigest()
    path = os.path.join(UPLOAD_FOLDER, safe_name)

    data = cipher.decrypt(open(path, 'rb').read())

    return send_file(io.BytesIO(data), download_name=record.filename, as_attachment=True)


# ---------------- RUN ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)