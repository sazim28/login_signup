# -*- coding: utf-8 -*-
from flask import Flask, render_template, redirect, url_for, request, session, flash, g, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import uuid
import os
import re

app = Flask(__name__)

# Secret key for sessions
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-change-me')

# Database URL (Postgres on Render, SQLite locally)
db_url = os.environ.get('DATABASE_URL', 'sqlite:///users.db')

# Normalize for Postgres
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

# Force psycopg3 instead of psycopg2
if db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    name     = db.Column(db.String(150), nullable=False)
    email    = db.Column(db.String(150), unique=True, nullable=False, index=True)
    username = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password = db.Column(db.String(200), nullable=False)

class Conversation(db.Model):
    id         = db.Column(db.String(36), primary_key=True)  # UUID string
    user_id    = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    title      = db.Column(db.String(200), default="New chat")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id              = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.String(36), db.ForeignKey('conversation.id', ondelete="CASCADE"),
                                index=True, nullable=False)
    role            = db.Column(db.String(20), nullable=False)  # 'user' or 'assistant'
    content         = db.Column(db.Text, nullable=False)
    created_at      = db.Column(db.DateTime, default=datetime.utcnow)

# Create tables once
with app.app_context():
    db.create_all()

# ---------------- Helpers ----------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        return view(*args, **kwargs)
    return wrapped

@app.before_request
def load_logged_in_user():
    g.user = None
    uid = session.get('user_id')
    if uid:
        g.user = User.query.get(uid)

# ---------------- Routes ----------------
@app.route('/')
def home():
    return redirect(url_for('dashboard') if g.user else url_for('login'))

# --- Auth ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        username = request.form['username'].strip().lower()
        password = request.form['password']

        # Simple validations
        if len(name) < 2:
            flash('Name must be at least 2 characters.', 'error')
            return redirect(url_for('signup'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email address.', 'error')
            return redirect(url_for('signup'))

        if len(password) < 8 or not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9\W]", password):
            flash('Password must be at least 8 characters and include letters + numbers/special characters.', 'error')
            return redirect(url_for('signup'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists.', 'error')
            return redirect(url_for('signup'))

        hashed = generate_password_hash(password)
        user = User(name=name, email=email, username=username, password=hashed)
        db.session.add(user)
        db.session.commit()

        flash('Signup successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash('Invalid username or password.', 'error')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        flash('Logged in successfully.', 'success')
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout', methods=['POST', 'GET'])
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

# --- Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=g.user.username)

# --- Chats ---
@app.route('/chats')
@login_required
def chats():
    convos = Conversation.query.filter_by(user_id=g.user.id)\
        .order_by(Conversation.updated_at.desc()).all()
    return render_template('chats.html', conversations=convos)

@app.route('/chat/new', methods=['POST', 'GET'])
@login_required
def new_chat():
    convo = Conversation(id=str(uuid.uuid4()), user_id=g.user.id, title="New chat")
    db.session.add(convo)
    db.session.commit()
    return redirect(url_for('chat', conversation_id=convo.id))

@app.route('/chat/<conversation_id>', methods=['GET', 'POST'])
@login_required
def chat(conversation_id):
    convo = Conversation.query.filter_by(id=conversation_id, user_id=g.user.id).first()
    if not convo:
        abort(404)

    if request.method == 'POST':
        user_text = request.form.get('message', '').strip()
        if user_text:
            db.session.add(Message(conversation_id=convo.id, role='user', content=user_text))
            reply = f"(echo) You said: {user_text}"  # stubbed assistant reply
            db.session.add(Message(conversation_id=convo.id, role='assistant', content=reply))

            if convo.title == "New chat":
                convo.title = (user_text[:40] + '...') if len(user_text) > 40 else (user_text or "New chat")
            convo.updated_at = datetime.utcnow()
            db.session.commit()
        return redirect(url_for('chat', conversation_id=convo.id))

    messages = Message.query.filter_by(conversation_id=convo.id)\
        .order_by(Message.created_at.asc()).all()
    return render_template('chat.html', conversation=convo, messages=messages)

# ------------- Run -------------
if __name__ == '__main__':
    app.run(debug=True)
