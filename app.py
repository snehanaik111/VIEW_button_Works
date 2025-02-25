import os
import hashlib
import time
import random
from flask import Flask, render_template, request, url_for, send_file, jsonify, redirect
from reportlab.pdfgen import canvas
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_session import Session
import logging
from google.oauth2 import id_token  # ✅ Import this
from google.auth.transport import requests as google_requests
from flask import session
from datetime import datetime
from datetime import datetime, timedelta
from dotenv import load_dotenv
from sqlalchemy import func, cast, Date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
load_dotenv()


# ✅ Configure Logging
logging.basicConfig(
    filename="app.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"  # Stores session data
app.config["SESSION_COOKIE_SECURE"] = True  # Force HTTPS only
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JavaScript access
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protect against CSRF attacks

Session(app)  # Initialize Flask-Session


# Load PayU credentials from environment variables
MERCHANT_KEY = os.getenv("PAYU_MERCHANT_KEY")
MERCHANT_SALT = os.getenv("PAYU_MERCHANT_SALT")

# Validate that the credentials are set
if not MERCHANT_KEY or not MERCHANT_SALT:
    raise ValueError("PayU credentials are missing. Set PAYU_MERCHANT_KEY and PAYU_MERCHANT_SALT environment variables.")

PAYU_URL = os.getenv("PAYU_URL", "https://secure.payu.in/_payment")  # Fetch from environment


# ✅ Database Configuration (Using ODBC)
DB_SERVER = os.getenv("DB_SERVER")
DB_NAME = os.getenv("DB_NAME")
DB_USERNAME = os.getenv("DB_USERNAME")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DRIVER = os.getenv("DB_DRIVER", "ODBC Driver 18 for SQL Server")

DATABASE_URL = f"mssql+pyodbc://{DB_USERNAME}:{DB_PASSWORD}@{DB_SERVER}/{DB_NAME}?driver={DB_DRIVER.replace(' ', '+')}"

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secret_key'

db = SQLAlchemy(app)
from flask_migrate import Migrate

migrate = Migrate(app, db)  # ✅ Initialize Flask-Migrate


# ✅ Hash Generation Function for PayU
def generate_payu_hash(txnid, amount, productinfo, firstname, email):
    hash_sequence = f"{MERCHANT_KEY}|{txnid}|{amount}|{productinfo}|{firstname}|{email}|||||||||||{MERCHANT_SALT}"
    return hashlib.sha512(hash_sequence.encode('utf-8')).hexdigest().lower()

# ✅ Define User Model (With Picture)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(50), unique=True, nullable=False)  # ✅ Unique Google ID
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    picture = db.Column(db.String(300), nullable=True)
    is_active = db.Column(db.Boolean, default=True)  # ✅ New column added

    def __init__(self, google_id, email, name, picture=None):
        self.google_id = google_id
        self.name = name
        self.email = email
        self.picture = picture

   

    
# ✅ Define Payment Model
class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)  # User's email
    name = db.Column(db.String(100), nullable=False)  # User's name
    plan_name = db.Column(db.String(50), nullable=False)  # Subscription Plan
    amount = db.Column(db.Float, nullable=False)  # Amount Paid
    txnid = db.Column(db.String(50), unique=True, nullable=False)  # Transaction ID
    payment_status = db.Column(db.String(20), nullable=False, default="Pending")  # Success, Failed, Pending
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp

    def __init__(self, email, name, plan_name, amount, txnid, payment_status="Pending"):
        self.email = email
        self.name = name
        self.plan_name = plan_name
        self.amount = amount
        self.txnid = txnid
        self.payment_status = payment_status




class ServiceLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    service_name = db.Column(db.String(255), nullable=False)  # Example: 'Worksheet', 'Flashcard'
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("logs", lazy=True))

    def __repr__(self):
        return f"<ServiceLog {self.service_name} - {self.timestamp}>"
    





class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("questions", lazy=True))


class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    answer_text = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", backref=db.backref("answers", lazy=True))
    question = db.relationship("Question", backref=db.backref("answers", lazy=True))
    



class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    resource_type = db.Column(db.String(50), nullable=False)
    resource_name = db.Column(db.String(255), nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(50), default="AI Generated")
    pdf_base64 = db.Column(db.Text, nullable=True)  # ✅ Ensure this column exists

    user = db.relationship("User", backref=db.backref("activity_logs", lazy=True))



# ✅ Ensure Tables are Created
with app.app_context():
    db.create_all()
    print("✅ Database tables created successfully!")


app.secret_key = os.getenv("FLASK_SECRET_KEY")  # Load Flask secret key from .env
# Google OAuth Config
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")

app.config["GOOGLE_DISCOVERY_URL"] = "https://accounts.google.com/.well-known/openid-configuration"



oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params={"scope": "openid email profile"},
    access_token_url="https://oauth2.googleapis.com/token",
    access_token_params=None,
    client_kwargs={"scope": "openid email profile"},
    server_metadata_url=app.config["GOOGLE_DISCOVERY_URL"],
)

# ✅ Admin Credentials (Change These)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")



@app.route("/")
def home():
    return render_template("index.html")

import secrets


@app.route("/login")
def login():
    """Handles login and sets next_url based on action"""

    allowed_domains = {
        "levelupai.azurewebsites.net": "https://levelupai.azurewebsites.net/auth/callback",
        "leveluponline.shop": "https://leveluponline.shop/auth/callback",
        "127.0.0.1": "http://127.0.0.1:8000/auth/callback",  # For local testing
    "localhost": "http://localhost:8000/auth/callback",  # Localhost testing
    }

    current_domain = request.host.split(":")[0]  # Extract domain without port
    redirect_url = allowed_domains.get(current_domain)

    if not redirect_url:
        return "Unauthorized domain", 400  # Reject if domain is not in the list

    # ✅ Store the next page user should visit
    next_url = request.args.get("next", url_for("chatbot"))  # Default is chatbot
    session["next_url"] = next_url  
    session["oauth_state"] = secrets.token_urlsafe(16)  # ✅ Store CSRF state token

    print(f"Redirecting to Google OAuth: {redirect_url}")  # Debugging
    return google.authorize_redirect(
        redirect_url, state=session["oauth_state"]  # ✅ Include CSRF state
    )

@app.route("/auth/callback")
def auth_callback():
    logging.info("🔄 Google OAuth callback hit!")

    try:
        # ✅ Validate OAuth state to prevent CSRF attacks
        received_state = request.args.get("state")
        expected_state = session.pop("oauth_state", None)
        if received_state != expected_state:
            logging.error("❌ CSRF Warning! State mismatch detected.")
            return "CSRF Warning! Invalid OAuth state.", 400

        # ✅ Retrieve OAuth Token
        token = google.authorize_access_token()
        if not token:
            logging.error("❌ No token received from Google!")
            return "Authentication failed", 400

        # ✅ Get user info from Google
        resp = google.get("https://www.googleapis.com/oauth2/v3/userinfo")
        if resp.status_code != 200:
            logging.error(f"❌ Google API Error: {resp.status_code} - {resp.text}")
            return "Error retrieving user info", 400

        user_info = resp.json()
        google_id = user_info.get("sub")
        email = user_info.get("email")
        name = user_info.get("name", "User")
        picture = user_info.get("picture")

        logging.info(f"✅ Google Login Successful - Google ID: {google_id}, Email: {email}, Name: {name}")

        # ✅ Store user details in session
        session.permanent = True
        session["google_id"] = google_id
        session["email"] = email
        session["name"] = name
        session["picture"] = picture

        logging.info(f"📌 Session Data After Login: {dict(session)}")

        # ✅ Store user details in database
        with app.app_context():
            db.create_all()

            user = User.query.filter((User.google_id == google_id) | (User.email == email)).first()
            if user:
                logging.info(f"🔄 User {email} exists. Updating info.")
                user.name = name
                user.picture = picture
            else:
                logging.info(f"🆕 Creating new user in DB: {email}")
                user = User(google_id=google_id, email=email, name=name, picture=picture)
                db.session.add(user)

            # ✅ Track Login Activity
            new_log = ServiceLog(user_id=user.id, service_name="User Login")
            db.session.add(new_log)

            db.session.commit()
            logging.info(f"✅ User {email} saved/updated in database with login activity.")

        # ✅ Redirect user to next page
        next_page = session.pop("next_url", url_for("chatbot"))
        logging.info(f"🔀 Redirecting user to: {next_page}")

        return redirect(next_page)

    except Exception as e:
        logging.error(f"❌ Error in OAuth callback: {str(e)}")
        return "Internal Server Error", 500








        


@app.route('/save_email', methods=['POST'])
def save_email():
    token = request.json.get('token')
    try:
        # Verify the token using Google ID Token verification
        info = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)

        google_id = info.get('sub')  # ✅ Extract Google ID
        email = info.get('email')
        name = info.get('name', 'Unknown User')  # ✅ Set a default name
        picture = info.get('picture')  # ✅ Store profile picture (optional)

        if email and google_id:
            with app.app_context():
                user = User.query.filter_by(email=email).first()

                if user:
                    # ✅ If user exists, update details
                    logging.info(f"🔄 User {email} already exists. Updating info.")
                    user.name = name
                    user.google_id = google_id  # ✅ Ensure correct Google ID is stored
                    user.picture = picture
                else:
                    # ✅ Create a new user with the correct Google ID
                    logging.info(f"🆕 Creating new user in DB: {email}")
                    new_user = User(google_id=google_id, email=email, name=name, picture=picture)
                    db.session.add(new_user)

                db.session.commit()
                logging.info(f"✅ User {email} saved/updated in database.")

            return jsonify({"success": True})

    except ValueError as e:
        logging.error(f"❌ Invalid token: {str(e)}")
        return jsonify({"success": False, "error": "Invalid token"}), 401

    except Exception as e:
        logging.error(f"❌ Error in save_email: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500




@app.route("/chatbot")
def chatbot():
    email = session.get("email")
    logging.info(f"📌 DEBUG: Session Data - {dict(session)}")

    if not email:
        logging.warning("🚫 No user session found! Redirecting to login.")
        return redirect(url_for("login"))  # ✅ Fixed incorrect redirect

    user = User.query.filter_by(email=email).first()
    if not user:
        logging.error(f"🚫 User {email} not found in database! Logging out user.")
        session.clear()  # ✅ Clear session to prevent looping redirects
        return redirect(url_for("login"))  # Redirect to login instead of 404

    # ✅ Only check for payment IF user came from "Subscribe"
    next_url = session.pop("next_url", None)
    if next_url == "pay":
        payment = Payment.query.filter_by(email=email, payment_status="Success").first()
        if not payment:
            logging.warning(f"🚫 Access Denied: {email} has NOT paid! Redirecting to home.")
            return redirect(url_for("home"))  # Redirect unpaid users

    # ✅ Normal login users get direct access
    return render_template("chatbot.html", name=user.name, email=user.email, picture=user.picture)




from flask import redirect, url_for  # ✅ Import redirect function

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    logging.info(f"Admin Login Attempt: {request.method}")

    if request.method == "POST":
        # ✅ Handle both Form Data and JSON requests
        if request.is_json:
            data = request.json
            username = data.get("username")
            password = data.get("password")
        else:
            username = request.form.get("username")
            password = request.form.get("password")

        logging.info(f"Entered Username: {username}")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True  # ✅ Store session
            
            # ✅ Redirect to admin_dashboard on successful login
            return redirect(url_for("admin_dashboard"))  

        return jsonify({"error": "Invalid credentials"}), 401  # ✅ JSON Response

    return render_template("admin_login.html")  # ✅ Render login page for browsers


@app.route("/admin_dashboard", methods=["GET"])
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    # Fetch total counts
    total_users = User.query.count()
    total_worksheets = ActivityLog.query.filter(ActivityLog.resource_type == "Worksheet").count()
    total_flashcards = ActivityLog.query.filter(ActivityLog.resource_type == "Flashcard").count()

    # Fetch all users and their activity logs
    users = User.query.all()
    user_data = []

    for user in users:
        logs = ActivityLog.query.filter_by(user_id=user.id).order_by(ActivityLog.date.desc()).all()

        user_data.append({
            "profile_picture": user.picture or "/static/images/default.png",
            "name": user.name,
            "email": user.email,
            "worksheets_used": sum(1 for log in logs if log.resource_type == "Worksheet"),
            "flashcards_used": sum(1 for log in logs if log.resource_type == "Flashcard"),
            "logs": [{"service_name": log.action, "timestamp": log.date.strftime('%Y-%m-%d %H:%M:%S')} for log in logs],
            "subscription": "Paid" if Payment.query.filter_by(email=user.email, payment_status="Success").first() else "Free",
        })

    return render_template(
        "admin_dashboard.html",
        total_users=total_users,
        total_worksheets=total_worksheets,
        total_flashcards=total_flashcards,
        users=user_data
    )




@app.route("/log_activity", methods=["POST"])
def log_activity():
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    action = data.get("action")
    resource_type = data.get("resource_type")
    resource_name = data.get("resource_name")
    source = data.get("source", "AI Generated")
    pdf_base64 = data.get("pdf")  # Base64 PDF

    if not action or not resource_type:
        return jsonify({"error": "Invalid activity data"}), 400

    new_log = ActivityLog(
        user_id=user.id,
        action=action,
        resource_type=resource_type,
        resource_name=resource_name,
        source=source,
        pdf_base64=pdf_base64  # Store PDF as Base64
    )
    db.session.add(new_log)
    db.session.commit()

    return jsonify({"message": "Activity logged successfully"})













@app.route("/admin_logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route('/table')
def table():
    return render_template('table.html')





@app.route("/pay", methods=["GET", "POST"])
def pay():
    if "email" not in session:
        return redirect(url_for("login"))  # Ensure user is logged in

    email = session.get("email")
    name = session.get("name", "User")

    if request.method == "POST":  # Payment initiated via form submission
        txnid = str(int(time.time()))  # Unique transaction ID
        amount = request.form.get("amount", "0.00")
        productinfo = request.form.get("productinfo", "Subscription Plan")

    else:  # If request is GET (from a button click)
        plan = request.args.get("plan")
        amount = request.args.get("amount")
        txnid = "TXN" + str(int(time.time() * 1000)) + str(random.randint(1000, 9999))  # Unique txnid
        productinfo = plan if plan else "Subscription Plan"

    # ✅ Generate PayU Hash
    hash_value = generate_payu_hash(txnid, amount, productinfo, name, email)

    # ✅ Store transaction in DB (status: "Pending")
    payment = Payment(email=email, name=name, amount=amount, plan_name=productinfo, txnid=txnid, payment_status="Pending")
    db.session.add(payment)
    db.session.commit()

    # ✅ Prepare PayU Data
    payu_data = {
        "key": MERCHANT_KEY,
        "txnid": txnid,
        "amount": amount,
        "productinfo": productinfo,
        "firstname": name,
        "email": email,
        "phone": "9999999999",  # Required field
        "surl": url_for('success', _external=True) + f"?txnid={txnid}&productinfo={productinfo}&amount={amount}",  # Ensure values are passed
        "furl": url_for("failure", _external=True),
        "hash": hash_value
    }

    return render_template("payment.html", payu_url=PAYU_URL, payu_data=payu_data)



@app.route('/success', methods=['GET', 'POST'])
def success():
    if request.method == 'POST' and 'txnid' in request.form:
        print(request.form)  # Debug: Print PayU's response in logs
        txnid = request.form.get('txnid', 'Unknown')
        plan = request.form.get('productinfo', 'N/A')
        amount = request.form.get('amount', '0.00')
    else:  # Use GET as a fallback
        print(request.args)  # Debug: Print if PayU sends GET
        txnid = request.args.get('txnid', 'Unknown')
        plan = request.args.get('productinfo', 'N/A')
        amount = request.args.get('amount', '0.00')

    print(f"Received Payment Data -> Transaction ID: {txnid}, Plan: {plan}, Amount: {amount}")

    # ✅ Update payment status in database
    payment = Payment.query.filter_by(txnid=txnid).first()
    if payment:
        payment.payment_status = "Success"
        db.session.commit()
        logging.info(f"✅ Payment Success for {payment.email} - TXN: {txnid}")

    # ✅ Generate Receipt PDF
    pdf_path = f"receipt_{txnid}.pdf"
    generate_pdf(txnid, plan, amount, pdf_path)

    return render_template('payment_success.html', txnid=txnid, plan=plan, amount=amount, pdf_path=pdf_path)



@app.route('/generate_receipt/<txnid>')
def generate_receipt(txnid):
    plan = request.args.get('plan')
    amount = request.args.get('amount')
    pdf_path = f"receipt_{txnid}.pdf"
    generate_pdf(txnid, plan, amount, pdf_path)
    return send_file(pdf_path, as_attachment=True)

def generate_pdf(txnid, plan, amount, pdf_path):
    c = canvas.Canvas(pdf_path)
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(200, 800, "Payment Receipt")
    
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, f"Transaction ID: {txnid}")
    c.drawString(100, 730, f"Plan: {plan}")
    c.drawString(100, 710, f"Amount Paid: ${amount}")
    
    c.drawString(100, 680, "Thank you for your purchase!")
    c.save()

# ✅ Failure Route (Update Payment Status)
@app.route('/failure')
def failure():
    txnid = request.args.get("txnid")
    payment = Payment.query.filter_by(txnid=txnid).first()
    
    if payment:
        payment.payment_status = "Failed"
        db.session.commit()
        logging.warning(f"🚨 Payment Failed for {payment.email} - TXN: {txnid}")
    
    return render_template('payment_failure.html')
    


@app.route("/questions", methods=["GET"])
def get_questions():
    """Fetch all questions with user details, including profile pictures."""
    questions = Question.query.order_by(Question.created_at.desc()).all()
    question_list = [
        {
            "id": q.id,
            "user": q.user.name,
            "user_picture": q.user.picture or "/static/images/default-user.png",
            "text": q.question_text,
            "created_at": q.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "answers": [
                {
                    "user": a.user.name,
                    "user_picture": a.user.picture or "/static/images/default-user.png",
                    "text": a.answer_text,
                    "created_at": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                }
                for a in q.answers
            ],
        }
        for q in questions
    ]
    return jsonify(question_list)

@app.route("/ask_question", methods=["POST"])
def ask_question():
    """Allow users to post questions with their profile image."""
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    question_text = data.get("question")

    if not question_text:
        return jsonify({"error": "Question cannot be empty"}), 400

    new_question = Question(user_id=user.id, question_text=question_text)
    db.session.add(new_question)
    db.session.commit()

    return jsonify({
        "message": "Question posted successfully",
        "user_picture": user.picture or "/static/images/default-user.png"
    })


@app.route("/answer_question", methods=["POST"])
def answer_question():
    """Allow users to reply with their profile picture."""
    if "email" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json()
    question_id = data.get("question_id")
    answer_text = data.get("answer")

    if not question_id or not answer_text:
        return jsonify({"error": "Invalid input"}), 400

    question = Question.query.get(question_id)
    if not question:
        return jsonify({"error": "Question not found"}), 404

    new_answer = Answer(user_id=user.id, question_id=question_id, answer_text=answer_text)
    db.session.add(new_answer)
    db.session.commit()

    return jsonify({
        "message": "Answer posted successfully",
        "user_picture": user.picture or "/static/images/default-user.png"
    })



@app.route("/get_user_profile")
def get_user_profile():
    if "email" not in session:
        logging.warning("Unauthorized access to profile data")
        return jsonify({"error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        logging.error(f"User not found: {session.get('email')}")
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "name": user.name,
        "email": user.email,
        "picture": user.picture or "/static/images/default-user.png"
    })



@app.route('/update_profile', methods=['POST'])
def update_profile():
    if "email" not in session:
        logging.warning("Unauthorized access to profile update")
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        logging.error(f"User not found: {session.get('email')}")
        return jsonify({"success": False, "error": "User not found"}), 404

    try:
        password = request.json.get("password")
        if password:
            user.password = hashlib.sha256(password.encode()).hexdigest()

        db.session.commit()
        logging.info(f"User {user.email} updated profile successfully")
        return jsonify({"success": True})
    except Exception as e:
        logging.error(f"Error updating profile: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500
    



def get_deleted_user():
    """Ensure a default 'Deleted User' exists and return its ID."""
    deleted_user = User.query.filter_by(email="deleted_user@system.com").first()
    if not deleted_user:
        deleted_user = User(
            google_id="deleted_system_id",
            name="Deleted User",
            email="deleted_user@system.com",
            picture="/static/images/default-user.png"
        )
        db.session.add(deleted_user)
        db.session.commit()
    return deleted_user



@app.route('/delete_account', methods=['POST'])
def delete_account():
    if "email" not in session:
        logging.warning("Unauthorized attempt to delete account")
        return jsonify({"success": False, "error": "Unauthorized"}), 401

    user = User.query.filter_by(email=session["email"]).first()
    if not user:
        logging.error(f"Attempted to delete non-existent user: {session.get('email')}")
        return jsonify({"success": False, "error": "User not found"}), 404

    try:
        deleted_user = get_deleted_user()  # Get or create the default 'Deleted User'

        logging.info(f"Replacing user {user.id} with deleted user {deleted_user.id}")

        # ✅ Replace user_id in all related tables instead of setting NULL
        db.session.query(Question).filter(Question.user_id == user.id).update({"user_id": deleted_user.id})
        db.session.query(Answer).filter(Answer.user_id == user.id).update({"user_id": deleted_user.id})
        db.session.query(ServiceLog).filter(ServiceLog.user_id == user.id).update({"user_id": deleted_user.id})

        db.session.delete(user)  # Now safe to delete the user
        db.session.commit()

        session.clear()  # Log the user out after deletion
        logging.info(f"User {user.email} deleted their account")

        return jsonify({"success": True})  # ✅ Ensure returning JSON
    except Exception as e:
        db.session.rollback()  # Rollback any partial changes
        logging.error(f"Error deleting account: {str(e)}")
        print(f"Error deleting account: {str(e)}")  # Debug print
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/get_top_users")
def get_top_users():
    try:
        top_users = (
            db.session.query(User.name, User.email, db.func.count(ServiceLog.id).label("activity_count"))
            .join(ServiceLog, User.id == ServiceLog.user_id)
            .group_by(User.id, User.name, User.email)
            .order_by(db.desc("activity_count"))
            .limit(5)
            .all()
        )
        return jsonify([
            {"name": user.name, "email": user.email, "activity_count": user.activity_count} 
            for user in top_users
        ])
    except Exception as e:
        app.logger.error(f"Error fetching top users: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500


@app.route("/get_activity_logs")
def get_activity_logs():
    logs = ActivityLog.query.order_by(ActivityLog.date.desc()).limit(10).all()
    log_data = []

    for log in logs:
        log_data.append({
            "user": log.user.name if log.user else "Unknown",
            "action": log.action,
            "resource_type": log.resource_type,
            "resource_name": log.resource_name or "N/A",
            "date": log.date.strftime('%Y-%m-%d %H:%M:%S'),
            "source": log.source or "AI Generated",
            "pdf": log.pdf_base64 or ""  # ✅ Handle missing PDFs
        })

    return jsonify(log_data)






@app.route("/get_activity_data")
def get_activity_data():
    try:
        filter_type = request.args.get("filter", "daily")

        if filter_type == "daily":
            start_date = datetime.utcnow() - timedelta(days=7)
        elif filter_type == "weekly":
            start_date = datetime.utcnow() - timedelta(weeks=4)
        else:  # Monthly
            start_date = datetime.utcnow() - timedelta(days=30)

        app.logger.info(f"Fetching activity data from: {start_date}")  # Debug log

        # Use CAST instead of date() for SQL Server compatibility
        activity_data = (
            db.session.query(cast(ServiceLog.timestamp, Date).label("date"), func.count(ServiceLog.id))
            .filter(ServiceLog.timestamp >= start_date)
            .group_by(cast(ServiceLog.timestamp, Date))
            .order_by(cast(ServiceLog.timestamp, Date))
            .all()
        )

        if not activity_data:
            app.logger.warning("No activity data found!")
            return jsonify({"labels": [], "values": []})  # Return empty if no data

        labels = [str(data.date) for data in activity_data]
        values = [data[1] for data in activity_data]

        return jsonify({"labels": labels, "values": values})
    
    except Exception as e:
        app.logger.error(f"Error fetching activity data: {str(e)}")
        return jsonify({"error": "Internal Server Error", "details": str(e)}), 500




@app.route("/save_admin_settings", methods=["POST"])
def save_admin_settings():
    data = request.json
    session["theme"] = data.get("theme", "light")
    session["admin_notifications"] = data.get("admin_notifications", False)
    session["content_moderation"] = data.get("content_moderation", False)
    
    return jsonify({"message": "Settings saved successfully"})





import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, request, jsonify

@app.route("/send_bulk_email", methods=["POST"])
def send_bulk_email():
    try:
        data = request.json
        emails = data.get("emails", [])
        message = data.get("message", "")

        if not emails or not message:
            return jsonify({"message": "Invalid request. Please select recipients and enter a message."}), 400

        sender_email = "snehafrankocean@gmail.com"
        sender_password = "sjgo tbpe ovow typt"  # Use App Password if 2FA is enabled

        # Setup the email server
        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
        server.login(sender_email, sender_password)

        # Compose and send the email
        for recipient_email in emails:
            msg = MIMEMultipart()
            msg["From"] = sender_email
            msg["To"] = recipient_email
            msg["Subject"] = "Bulk Email"
            msg.attach(MIMEText(message, "plain"))

            server.sendmail(sender_email, recipient_email, msg.as_string())
        
        server.quit()
        return jsonify({"message": "Emails sent successfully!"})

    except Exception as e:
        print(f"Error: {e}")  # Print the error for debugging
        return jsonify({"message": f"Failed to send emails. Error: {str(e)}"}), 500



#DOES NOT WORK
@app.route('/update_user_status', methods=['POST'])
def update_user_status():
    data = request.get_json()
    user_id = data.get("user_id")
    new_status = data.get("status")

    user = User.query.get(user_id)
    if user:
        user.is_active = new_status
        db.session.commit()
        return jsonify({"message": "Status updated successfully"}), 200
    else:
        return jsonify({"error": "User not found"}), 404






from flask import Flask, request, jsonify, url_for
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
import os

# Ensure PDF directory exists
PDF_DIR = "static/pdfs"
if not os.path.exists(PDF_DIR):
    os.makedirs(PDF_DIR)

@app.route('/generate_flashcard_pdf', methods=['POST'])
def generate_flashcard_pdf():
    try:
        data = request.json  
        topic = data.get('topic', 'Unknown_Topic').replace(" ", "_")
        age_group = data.get('age_group', 'Unknown_Age').replace(" ", "_")
        flashcards = data.get('flashcards', [])

        if not flashcards:
            return jsonify({'error': 'No flashcards provided'}), 400

        # Generate filename
        pdf_filename = f"{topic}_{age_group}.pdf"
        pdf_path = os.path.join(PDF_DIR, pdf_filename)

        # Create PDF
        doc = canvas.Canvas(pdf_path, pagesize=letter)
        doc.setFont("Helvetica-Bold", 14)

        y_position = 750  # Start position

        # Add Topic and Age Group at the top
        doc.drawString(50, y_position, f"Flashcards for Topic: {topic.replace('_', ' ')}")
        y_position -= 20
        doc.drawString(50, y_position, f"Age Group: {age_group.replace('_', ' ')}")
        y_position -= 40  # Extra spacing

        doc.setFont("Helvetica", 12)  # Reset font

        for index, flashcard in enumerate(flashcards):
            question = flashcard.get('question', 'Question')
            answer = flashcard.get('answer', 'Answer')

            # Add Question
            doc.drawString(50, y_position, f"Q{index+1}: {question}")
            y_position -= 40  # Larger space between question and answer

            # Add Placeholder for fold
            doc.drawString(50, y_position, "___________________________")
            y_position -= 40  

            # Add Answer
            doc.drawString(50, y_position, f"A: {answer}")
            y_position -= 60  # Extra space before next question

            # Start a new page if needed
            if y_position < 100:
                doc.showPage()
                doc.setFont("Helvetica", 12)
                y_position = 750  

        doc.save()

        return jsonify({'pdf_url': f"/static/pdfs/{pdf_filename}"})

    except Exception as e:
        return jsonify({'error': str(e)}), 500










@app.route("/logout")
def logout():
    logging.info(f"Logging out user: {session.get('email')}")
    session.clear()
    return redirect(url_for("home"))




# Run the Flask app
if __name__ == '__main__':
    logging.info("🚀 Starting Flask app...")
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 8000)))


