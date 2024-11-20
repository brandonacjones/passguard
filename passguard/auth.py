from base64 import urlsafe_b64encode

from flask import Blueprint, render_template, request, session, url_for, redirect, flash, g, current_app
from passguard.db import get_db
from cryptography.fernet import Fernet
from passguard.config import MASTER_KEY
from hashlib import sha256

# Generate a unique encryption key for a user and return a Fernet instance with that key
def generate_user_key(username):
    hash_obj = sha256()
    hash_obj.update((MASTER_KEY + username).encode())
    user_key = urlsafe_b64encode(hash_obj.digest())
    return Fernet(user_key)

# Get a fernet instance with the username and use it to encrypt the password.
def encrypt_password(plaintext_password, username):
    user_fernet = generate_user_key(username)
    return user_fernet.encrypt(plaintext_password.encode())

# Get a fernet instance with the username and use it to decrypt the password.
def decrypt_password(encrypted_password, username):
    user_fernet = generate_user_key(username)
    decrypted_password = user_fernet.decrypt(encrypted_password)
    return decrypted_password.decode()

# Decrypt the encrypted password and compare it to the plaintext password, return True if they match.
def check_password(encrypted_password, plaintext_password, username):
    decrypted = decrypt_password(encrypted_password, username)
    return decrypted == plaintext_password

bp = Blueprint('auth', __name__, url_prefix='/')

@bp.route('/login', methods=['GET', 'POST'])
def login():

    # If the user is logging in
    if request.method == 'POST':
        user_username = request.form['user_username']
        user_password = request.form['user_password']
        error = None

        if not user_username:
            error = 'Username is required.'
        elif not user_password:
            error = 'Password is required.'

        # Fetch user from database
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE user_username = ?', (user_username,)).fetchone()

        # If a user matching the username is not found
        if user is None:
            error = 'Username or Password is incorrect.'

        # Compare the password entered to the password in the database.
        elif not check_password(user['user_password'], user_password, user_username):
            error = 'Username or Password is incorrect.'

        # If everything looks good, save session with logged-in user_id
        if error is None:
            session.clear()
            session['session_user_id'] = user['user_id']
            session['session_user_username'] = user['user_username']
            return redirect(url_for('pages.dashboard'))

        flash(error)

    return render_template('auth/login.html')

@bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        db = get_db()
        user_username = request.form['user_username']
        user_password = request.form['user_password']
        error = None

        if not user_username:
            error = 'Username is required.'
        elif not user_password:
            error = 'Password is required.'

        # If all credentials are present, add user to database.
        if error is None:
            try:
                db.execute(
                    'INSERT INTO users (user_username, user_password) VALUES (?, ?)',
                    (user_username, encrypt_password(user_password, user_username))
                )
                db.commit()

            except db.IntegrityError:
                error = f"User {user_username} already exists."

            else:
                return redirect(url_for('auth.login'))
        flash(error)
    return render_template('auth/register.html')

# upon a request, check if a user is already logged in to a session.
@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('session_user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM users WHERE user_id = ?',
            (user_id,)
        ).fetchone()

# Logout
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('pages.index'))