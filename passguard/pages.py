from os import abort

from flask import Blueprint, render_template, request, g, redirect, url_for, flash, jsonify, session
from passguard.auth import encrypt_password, decrypt_password, check_password
from passguard.db import get_db

bp = Blueprint('pages', __name__, url_prefix='/')

@bp.route('/')
def index():
    return render_template('pages/index.html')

@bp.route('/add-credential', methods=['GET', 'POST'])
def add():

    if request.method == 'POST':
        user_id = session['session_user_id']
        service_name = request.form.get('service_name')
        service_pass = request.form.get('service_password')
        service_url = request.form.get('service_url')
        service_username = request.form.get('service_username')
        error = None
        db = get_db()

        if not service_name:
            error = 'Service name is required.'
        elif not service_pass:
            error = 'Service password is required.'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO services (user_id, service_name, service_password, service_url, service_username)'
                    ' VALUES (?, ?, ?, ?, ?)',
                    (user_id, service_name, encrypt_password(service_pass, session['session_user_username']), service_url, service_username)
                )
                db.commit()
            except db.Error:
                error = 'An error occurred.'

            else:
                return redirect(url_for('pages.dashboard'))
        flash(error)
    return render_template('pages/add_cred.html')

@bp.route('/dashboard')
def dashboard():
    db = get_db()
    user_id = session['session_user_id']
    services = db.execute(
        'SELECT service_id, service_name, service_password, service_url, service_username'
        ' FROM services WHERE user_id = ?',
        (user_id, )
    ).fetchall()

    return render_template('pages/dashboard.html', services=services)

@bp.route('/decrypt/<int:service_id>')
def decrypt_on_demand(service_id):
    if not g.user:
        abort(401)

    db = get_db()
    service_password = db.execute(
        'SELECT service_password FROM services where service_id = ?',
        (service_id, )
    ).fetchone()

    if service_password:
        encoded_password = service_password['service_password']
        decrypted_credential = decrypt_password(encoded_password, session['session_user_username'])
        return jsonify({'password': decrypted_credential})

    else:
        abort(404)
