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

@bp.route('/update', methods=['GET', 'POST'])
def update():
    if request.method == 'POST':
        error = None;
        new_username = request.form.get('service_username')
        new_name = request.form.get('service_name')
        new_password = request.form.get('service_password')
        new_url = request.form.get('service_url')

        if not new_username or not new_name or not new_password or not new_url:
            error = "Missing field in update form. Ensure all fields are filled in."

        encrypted_new_password = encrypt_password(new_password, session['session_user_username'])

        db = get_db()
        if error is None:
            try:
                db.execute(
                    'UPDATE services SET service_name = ?, service_username = ?, service_password = ?, service_url = ?'
                    ' WHERE service_id = ? AND user_id = ?',
                    (new_name, new_username, encrypted_new_password, new_url, session['service_id'], session['session_user_id'])
                )
                db.commit()
                return redirect(url_for('pages.dashboard'))
            except:
                print("An Error Occurred during the database update operation.")
            else:
                redirect(url_for('pages.dashboard'))
        redirect(url_for('pages.dashboard'))

    return render_template('pages/update.html')

@bp.route('/process-service-id', methods=['POST'])
def process_service_id():
    service_id = request.form.get('service_id')
    db = get_db()
    service_details = None
    try:
        service_details = db.execute('SELECT service_username, service_password, service_name, service_url'
                   ' FROM services WHERE service_id = ?',
                   (service_id, )
                   ).fetchone()
    except db.Error:
        error = 'Something went wrong.'

    # decrypt password for display
    decrypted_service_password = decrypt_password(service_details['service_password'], session['session_user_username'])

    session['service_name'] = service_details['service_name']
    session['service_username'] = service_details['service_username']
    session['service_password_plain'] = decrypted_service_password
    session['service_url'] = service_details['service_url']
    session['service_id'] = service_id

    return jsonify({"message": "ServiceID processed successfully."})
    
