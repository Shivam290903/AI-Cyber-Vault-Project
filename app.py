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
from commonregex import CommonRegex
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = "major_project_vault_2026_secure"

# --- CONFIGURATION ---
# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# OCR Path (Update this if your Tesseract location is different)
pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

# Storage setup
# UPLOAD_FOLDER = "C:\\Users\\imshi\\OneDrive\\VaultCloud" 
# os.makedirs(UPLOAD_FOLDER, exist_ok=True)
UPLOAD_FOLDER = os.path.join(os.getcwd(), "VaultCloud")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    files = db.relationship('FileRecord', backref='owner', lazy=True)

class FileRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- ADD THIS TO YOUR MODELS SECTION ---
from datetime import datetime
import pytz

def get_ist_time():
    """Helper function to get current time in IST."""
    ist = pytz.timezone('Asia/Kolkata')
    return datetime.now(ist)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Change 'default' to use our IST function
    timestamp = db.Column(db.DateTime, default=get_ist_time)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100))
    status = db.Column(db.String(20))
    details = db.Column(db.String(200))
    
    user = db.relationship('User', backref='logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ENCRYPTION ENGINE ---
KEY_FILE = "vault.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as kf: KEY = kf.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as kf: kf.write(KEY)
cipher = Fernet(KEY)

# --- ROUTES ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user_exists = User.query.filter_by(username=request.form.get('username')).first()
        if user_exists:
            flash("Username already taken!")
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(request.form.get('password'))
        new_user = User(username=request.form.get('username'), password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration Successful! Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('index'))
        flash("Invalid Credentials")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    # 1. Get all records for this user from the DB
    db_records = FileRecord.query.filter_by(user_id=current_user.id).all()
    
    valid_files = []
    
    for record in db_records:
        # Generate the hashed name to check the physical folder
        safe_name = hashlib.sha256(f"{current_user.id}_{record.filename}".encode()).hexdigest()
        file_path = os.path.join(UPLOAD_FOLDER, safe_name)
        
        # 2. ONLY show if the file exists on the disk
        if os.path.exists(file_path):
            valid_files.append(record)
        else:
            # 3. AUTO-CLEAN: If file was manually deleted, remove from DB and Log it
            db.session.delete(record)
            
            # Create a "Deleted" log entry
            new_log = AuditLog(
                user_id=current_user.id, 
                action="System Sync", 
                status="Deleted", 
                details=f"File {record.filename} was removed from storage."
            )
            db.session.add(new_log)
            db.session.commit()
            
    return render_template('index.html', files=valid_files)

from PIL import Image
import os

# --- ADD THIS HELPER FUNCTION ---
def optimize_image_for_ocr(image_path):
    """Resizes large images to speed up Tesseract scanning."""
    with Image.open(image_path) as img:
        # If image is larger than 1500px, scale it down
        if img.width > 1500 or img.height > 1500:
            img.thumbnail((1500, 1500))
            img.save(image_path, "JPEG", quality=85)

@app.route('/audit-logs')
@login_required
def view_logs():
    if current_user.username != 'admin':
        flash("Unauthorized: Admin access required.")
        return redirect(url_for('index'))
        
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('logs.html', logs=all_logs)

def is_luhn_valid(card_number):
    #Verifies if a number string is a valid Credit Card using Luhn's Algorithm.
    # Remove spaces or dashes
    card_number = card_number.replace(" ", "").replace("-", "")
    if not card_number.isdigit(): return False
    
    digits = [int(d) for d in card_number]
    # Double every second digit from the right
    for i in range(len(digits) - 2, -1, -2):
        digits[i] *= 2
        if digits[i] > 9:
            digits[i] -= 9
    return sum(digits) % 10 == 0

# --- UPDATE YOUR SCAN LOGIC ---
def scan_content(text):
    leaks = []
    
    # 1. Refined Credit Card (Matches digits ONLY if preceded by CC keywords)
    card_pattern = r'(?i)(?:card|cc|visa|master|debit|payment)[\s\w]*[:#-]?\s*(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})'
    potential_cards = re.findall(card_pattern, text)
    for card in potential_cards:
        if is_luhn_valid(card):
            leaks.append("Verified Credit Card")
            break

    # 2. Indian Bank Account Numbers (Usually 9-18 digits)
    # Refinement: Look for 'Account No' or 'A/C' nearby to avoid random number hits
    if re.search(r'(?i)(?:account|a/c|acc|acct)[\s.]{0,3}#?[:\s-]*(\d{9,18})', text):
        leaks.append("Bank Account Number")

    # 3. IFSC Codes (Format: 4 Alpha, 0, 6 Alphanumeric)
    if re.search(r'[A-Z]{4}0[A-Z0-9]{6}', text):
        leaks.append("Bank IFSC Code")

    # 4. Cheque Number (6 digits usually in quotes or at bottom)
    # Refinement: Look for the word 'Cheque' nearby
    if re.search(r'(?i)cheque[\s\w]*[:#-]?\s*(\d{6})', text):
        leaks.append("Cheque Number")

    # 5. Passbook/Customer ID (Usually alpha-numeric 8-12 chars)
    if re.search(r'(?i)(?:cust|customer|passbook|cif)[\s\w]*[:#-]?\s*([a-zA-Z0-9]{8,12})', text):
        leaks.append("Passbook/CIF Detail")

    # 6. Government ID (PAN Card)
    if re.search(r'[A-Z]{5}[0-9]{4}[A-Z]{1}', text):
        leaks.append("PAN Card")

    # 7. System Secrets (API Keys/Passwords)
    if re.search(r'(?i)(password|secret|apikey|token)[\s:=]+[\'"]?([a-zA-Z0-9_-]{16,})[\'"]?', text):
        leaks.append("System Secret/Token")
    #8. Aadhar Number
    if re.search(r'\b\d{4}\s\d{4}\s\d{4}\b', text):
        leaks.append("Aadhaar Number")

    

    return leaks

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    file = request.files.get('file')
    if not file or file.filename == '':
        flash("No file selected.")
        return redirect(url_for('index'))
    
    temp_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(temp_path)

    extracted_text = ""
    file_ext = file.filename.lower().split('.')[-1]
    
    try:
        # 1. Extraction with Speed Optimization
        if file_ext in ['png', 'jpg', 'jpeg', 'bmp']:
            optimize_image_for_ocr(temp_path) # Speeds up OCR
            extracted_text = pytesseract.image_to_string(Image.open(temp_path))
        else:
            with open(temp_path, 'r', errors='ignore') as f:
                extracted_text = f.read(10000)
        
        # 2. SMART SCANNING (Using your refined logic)
        found_leaks = scan_content(extracted_text)

        if found_leaks:
            leak_details = ", ".join(found_leaks)
            # Log the Block
            new_log = AuditLog(
                user_id=current_user.id, 
                action="Upload", 
                status="Blocked", 
                details=f"AI detected: {leak_details} in {file.filename}"
            )
            db.session.add(new_log)
            db.session.commit()

            os.remove(temp_path)
            flash(f"🚨 AI BLOCK: {leak_details} detected.")
            return redirect(url_for('index'))
            
    except Exception as e:
        print(f"Scan Error: {e}")

    # 3. ENCRYPTION PHASE
    with open(temp_path, 'rb') as f: 
        raw_data = f.read()
    
    encrypted_data = cipher.encrypt(raw_data)
    safe_name = hashlib.sha256(f"{current_user.id}_{file.filename}".encode()).hexdigest()
    final_path = os.path.join(UPLOAD_FOLDER, safe_name)
    
    with open(final_path, 'wb') as f: 
        f.write(encrypted_data)
    
    os.remove(temp_path)

    # 4. SUCCESS LOGGING
    new_file = FileRecord(filename=file.filename, user_id=current_user.id)
    new_log = AuditLog(
        user_id=current_user.id, 
        action="Upload", 
        status="Success", 
        details=f"File encrypted: {file.filename}"
    )
    
    db.session.add(new_file)
    db.session.add(new_log)
    db.session.commit()

    flash(f"🔒 AI Verified & Encrypted: {file.filename}")
    return redirect(url_for('index'))

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    record = FileRecord.query.get_or_404(file_id)
    
    # Ownership Check
    if record.user_id != current_user.id:
        flash("Access Denied.")
        return redirect(url_for('index'))

    safe_name = hashlib.sha256(f"{current_user.id}_{record.filename}".encode()).hexdigest()
    file_path = os.path.join(UPLOAD_FOLDER, safe_name)
    
    # NEW: Safety check to prevent crash
    if not os.path.exists(file_path):
        db.session.delete(record)
        db.session.commit()
        flash("Error: The physical file has been moved or deleted from storage.")
        return redirect(url_for('index'))

    with open(file_path, 'rb') as f: 
        enc_data = f.read()
        
    return send_file(io.BytesIO(cipher.decrypt(enc_data)), download_name=record.filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



