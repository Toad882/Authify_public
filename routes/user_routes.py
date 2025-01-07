from flask import Blueprint, request, jsonify, session, redirect, url_for, flash, render_template
from models import mongo, check_db_connection
from werkzeug.security import generate_password_hash
import logging
import uuid
import pyotp
import qrcode
import io
from base64 import b64encode
user_bp = Blueprint('user', __name__)

@user_bp.route('/verify-totp', methods=['GET', 'POST'])
def verify_totp():
    if 'registration_data' not in session or 'totp_secret' not in session:
        flash('Session expired. Please start the registration process again.', 'error')
        logging.error("Session data not found.")
        return redirect(url_for('user.register'))

    totp_secret = session['totp_secret']
    form = request.form
    if request.method == 'POST':
        totp_code = form.get('totp_code')

        if not totp_code:
            flash('TOTP code is required.', 'error')
            return redirect(url_for('user.verify_totp'))

        # Verify the TOTP token
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            # Generate a unique user ID
            user_id = str(uuid.uuid4())

            # Save user details and TOTP secret to the database
            check_db_connection()
            mongo.db.users.insert_one({
                'user_id': user_id,
                'username': session['registration_data']['username'],
                'email': session['registration_data']['email'],
                'password': session['registration_data']['password'],
                'totp_secret': totp_secret,
                'role': session['registration_data']['role'],
                'credentialId': None,
                'publicKeyJwk': None
            })

            # Clear the session data
            session.pop('registration_data', None)
            session.pop('totp_secret', None)

            session['user_id'] = user_id
            flash('Registration successful!', 'success')
            return redirect(url_for('user.dashboard'))
        else:
            flash('Invalid TOTP code. Please try again.', 'error')

    # Get the QR code from the session
    qr_code_base64 = session.get('qr_code', '')

    return render_template('totp_verification.html', qr_code=qr_code_base64)
@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('user.dashboard'))

    form = request.form
    if request.method == 'POST':
        username = form.get('username')
        email = form.get('email')
        password = form.get('password')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('user.register'))

        check_db_connection()
        existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
            flash('User or email already exists!', 'error')
            return redirect(url_for('user.register'))

        # Store user details in session for later use
        session['registration_data'] = {
            'username': username,
            'email': email,
            'password': generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
            'role': 'user'
        }

        logging.info("session data: ", session['registration_data'])

        # Generate a TOTP secret
        totp_secret = pyotp.random_base32()
        session['totp_secret'] = totp_secret

        # Create a QR code for the TOTP secret
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(pyotp.totp.TOTP(totp_secret).provisioning_uri(name=email, issuer_name='YourAppName'))
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_io = io.BytesIO()
        img.save(img_io, 'PNG')
        qr_code_base64 = b64encode(img_io.getvalue()).decode('utf-8')
        session['qr_code'] = qr_code_base64
        return redirect(url_for('user.verify_totp'))

    return render_template('register.html')
@user_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        #flash('You need to log in first.', 'error')
        return redirect(url_for('auth.login'))

    check_db_connection()
    user = mongo.db.users.find_one({'user_id': session['user_id']})
    username = user.get('username') if user else None
    email = user.get('email') if user else None
    role = user.get('role') if user else None

    if user.get('role') == 'admin':
        client_list = list(mongo.db.clients.find({'user_id': session['user_id']}, {'_id': 0}))
        return render_template('dashboard.html', username=username, email=email, clients=client_list, role=role)

    return render_template('dashboard.html', username=username, email=email, role=role)

@user_bp.route('/userinfo', methods=['GET'])
def userinfo():
    logging.info("method userinfo called")
    logging.info(f"Request headers: {request.headers}")
    if 'Authorization' not in request.headers or not request.headers['Authorization'].startswith('Bearer '):
        return jsonify({'error': 'missing_token'}), 401

    access_token = request.headers['Authorization'].split(' ')[1]
    logging.info(f"Access Token: {access_token}")

    # Query the token from the database
    check_db_connection()
    token_record = mongo.db.tokens.find_one({'access_token': access_token})
    if not token_record:
        return jsonify({'error': 'invalid_token'}), 401

    user_id = token_record['user_id']
    user = mongo.db.users.find_one({'user_id': user_id})

    if not user:
        return jsonify({'error': 'user_not_found'}), 404

    # Return user information
    user_info = {
        'sub': user['user_id'],
        'name': user.get('username'),
        'email': user.get('email')
    }

    return jsonify(user_info), 200

@user_bp.route('/forgotPasswd')
def forgotPasswd():
    return render_template('forgotPasswd.html')