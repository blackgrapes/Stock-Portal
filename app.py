from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pymysql
import os

# Initialize Flask App
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Session Configuration
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_TYPE'] = "filesystem"

# MySQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:772002@localhost:3306/mydatabase'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database
db = SQLAlchemy(app)

# Initialize Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)  # Increased size to store hashed passwords

# Create tables within the app context
with app.app_context():
    db.create_all()

# Load user session from database
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/index.html")
def index():
    return render_template("index.html")

@app.route("/login.html", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip().lower()  # Standardize username
        password = request.form["password"]

        # Fetch user from database
        user = User.query.filter_by(username=username).first()

        # Check if user exists in database
        if not user:
            flash("User does not exist! Please register first.", "danger")
            return redirect(url_for("login"))

        # Check if the provided password matches the stored hashed password
        if not check_password_hash(user.password, password):
            flash("Invalid Credentials! Please check your password.", "danger")
            return redirect(url_for("login"))

        # Login successful → Authenticate user
        login_user(user)
        flash("Login successful!", "success")
        return redirect(url_for("strategies"))  # Redirect to strategies page

    return render_template("login.html")


@app.route("/register.html", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form["fullname"].strip()
        email = request.form["email"].strip().lower()  # Store email in lowercase
        username = request.form["username"].strip().lower()  # Store username in lowercase
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Ensure username & email are unique
        if User.query.filter_by(username=username).first():
            flash("Username already exists! Please choose a different one.", "danger")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered! Use a different one or log in.", "danger")
            return redirect(url_for("register"))

        # Check password confirmation
        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("register"))

        # Hash password before storing
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(fullname=fullname, email=email, username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        flash("Account Created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/strategies.html")
@login_required
def strategies():
    return render_template("strategies.html")

@app.route("/aboutus.html")
def aboutus():
    return render_template("aboutus.html")

@app.route("/support.html")
def support():
    return render_template("support.html")

@app.route("/logout.html")
@login_required
def logout():
    logout_user()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))

# Media File Handling
MEDIA_FOLDER = os.path.join(os.getcwd(), 'media')
app.config['MEDIA_FOLDER'] = MEDIA_FOLDER

if not os.path.exists(MEDIA_FOLDER):
    os.makedirs(MEDIA_FOLDER)

@app.route('/media/<path:filename>')
def media(filename):
    return send_from_directory(app.config['MEDIA_FOLDER'], filename)

if __name__ == "__main__":
    # Ensure templates directory exists
    if not os.path.exists("templates"):
        os.makedirs("templates")

    with app.app_context():
        db.create_all()  # Ensures database tables are created

    app.run(debug=True)
