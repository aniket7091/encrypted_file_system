"""
Authentication routes for SecureShare
Handles user registration, login, and logout
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from functools import wraps
import bcrypt
from app.models import db, User

auth_bp = Blueprint('auth', __name__)


def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route('/')
def index():
    """Redirect to login or dashboard"""
    if 'user_id' in session:
        return redirect(url_for('files.dashboard'))
    return redirect(url_for('auth.login'))


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('auth_register.html')
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth_register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('auth_register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('auth_register.html')
        
        # Hash password using bcrypt
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            password_hash=password_hash.decode('utf-8')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth_register.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validation
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('auth_login.html')
        
        # Find user
        user = User.query.filter_by(username=username).first()
        
        if not user:
            flash('Invalid username or password.', 'error')
            return render_template('auth_login.html')
        
        # Verify password
        if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            # Create session
            session['user_id'] = user.id
            session['username'] = user.username
            
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('files.dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            return render_template('auth_login.html')
    
    return render_template('auth_login.html')


@auth_bp.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('auth.login'))
