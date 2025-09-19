from flask import Blueprint, request, jsonify, session, redirect, url_for, flash, render_template
from models import mongo, check_db_connection
from werkzeug.security import generate_password_hash
from config import Config
import logging
import uuid
import pyotp
import qrcode
import io
from base64 import b64encode
from secrets import token_urlsafe
import jwt
from datetime import datetime
import re

user_bp = Blueprint('user', __name__)


def validate_input_type(value, expected_type, pattern=None):
    if not isinstance(value, expected_type):
        return False
    if pattern and not re.match(pattern, str(value)):
        return False
    return True


def validate_jwt_token(access_token):
    try:
        decoded = jwt.decode(
            access_token,
            Config.SECRET_KEY,
            algorithms=['HS256'],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": False
            }
        )

        if 'exp' not in decoded:
            logging.warning("JWT missing expiration claim")
            return None

        if 'sub' not in decoded:
            logging.warning("JWT missing 'sub' (user_id) claim")
            return None

        if 'aud' not in decoded:
            logging.warning("JWT missing 'aud' (client_id) claim")
            return None

        if decoded['exp'] < datetime.utcnow().timestamp():
            logging.warning("JWT token expired")
            return None

        return decoded

    except jwt.ExpiredSignatureError:
        logging.warning("JWT token expired")
        return None
    except jwt.InvalidSignatureError:
        logging.warning("JWT invalid signature")
        return None
    except jwt.InvalidTokenError as e:
        logging.warning(f"JWT validation failed: {str(e)}")
        return None


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

        if not validate_input_type(totp_code, str, r'[0-9]{6}'):
            flash('Invalid TOTP code format.', 'error')
            return redirect(url_for('user.verify_totp'))

        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            user_id = str(uuid.uuid4())

            old_session_data = dict(session)
            session.clear()
            session.permanent = True

            check_db_connection()

            username = old_session_data['registration_data']['username']
            email = old_session_data['registration_data']['email']

            if not validate_input_type(username, str, r'[a-zA-Z0-9_-]{3,50}'):
                flash('Invalid username format.', 'error')
                return redirect(url_for('user.register'))

            if not validate_input_type(email, str, r'.+@.+\..+'):
                flash('Invalid email format.', 'error')
                return redirect(url_for('user.register'))

            mongo.db.users.insert_one({
                'user_id': user_id,
                'username': username,
                'email': email,
                'password': generate_password_hash(old_session_data['registration_data']['password'],
                                                   method='pbkdf2:sha256', salt_length=16),
                'totp_secret': totp_secret,
                'role': 'user'
            })

            session['user_id'] = user_id
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Invalid TOTP code. Please try again.', 'error')

    user_email = session['registration_data']['email']
    qr = qrcode.QRCode()
    qr.add_data(pyotp.totp.TOTP(totp_secret).provisioning_uri(user_email, issuer_name="YourAppName"))
    qr.make()
    img = qr.make_image()
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code_data = b64encode(buffer.getvalue()).decode()

    return render_template('totp_verification.html', qr_code=qr_code_data)


@user_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        form = request.form
        username = form.get('username')
        email = form.get('email')
        password = form.get('password')

        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return redirect(url_for('user.register'))

        if not validate_input_type(username, str, r'[a-zA-Z0-9_-]{3,50}'):
            flash('Username must be 3-50 characters and contain only letters, numbers, underscores, and hyphens.',
                  'error')
            return redirect(url_for('user.register'))

        if not validate_input_type(email, str, r'.+@.+\..+'):
            flash('Please enter a valid email address.', 'error')
            return redirect(url_for('user.register'))

        check_db_connection()

        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('user.register'))

        existing_email = mongo.db.users.find_one({'email': email})
        if existing_email:
            flash('Email already registered. Please use a different email.', 'error')
            return redirect(url_for('user.register'))

        totp_secret = pyotp.random_base32()

        session['registration_data'] = {
            'username': username,
            'email': email,
            'password': password
        }
        session['totp_secret'] = totp_secret

        return redirect(url_for('user.verify_totp'))

    return render_template('register.html')


@user_bp.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('You need to log in first.', 'error')
        return redirect(url_for('auth.login'))

    user_id = session['user_id']

    if not validate_input_type(user_id, str):
        flash('Invalid session. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    check_db_connection()

    user = mongo.db.users.find_one({'user_id': user_id})
    if not user:
        flash('User not found. Please log in again.', 'error')
        return redirect(url_for('auth.login'))

    username = user.get('username')
    email = user.get('email')
    role = user.get('role')

    if user.get('role') == 'admin':
        client_list = list(mongo.db.clients.find({'user_id': user_id}, {'_id': 0}))
        return render_template('dashboard.html', username=username, email=email, clients=client_list, role=role)

    return render_template('dashboard.html', username=username, email=email, role=role)


@user_bp.route('/userinfo', methods=['GET'])
def userinfo():
    logging.info("=== /userinfo endpoint called ===")

    if 'Authorization' not in request.headers or not request.headers['Authorization'].startswith('Bearer '):
        logging.warning("Missing or invalid Authorization header")
        return jsonify({'error': 'missing_token'}), 401

    access_token = request.headers['Authorization'].split(' ', 1)[1]

    decoded_token = validate_jwt_token(access_token)
    if not decoded_token:
        return jsonify({'error': 'invalid_token'}), 401

    user_id = decoded_token.get('sub')
    client_id = decoded_token.get('aud')

    logging.info(
        f"Token validated for user: {user_id[:8] if user_id else 'None'}***, client: {client_id[:8] if client_id else 'None'}***")

    if not client_id:
        return jsonify({'error': 'missing_client_id'}), 400

    if not validate_input_type(user_id, str) or not validate_input_type(client_id, str):
        return jsonify({'error': 'invalid_token_claims'}), 400

    check_db_connection()

    token_record = mongo.db.tokens.find_one({
        'user_id': user_id,
        'client_id': client_id
    })

    if not token_record:
        logging.warning("Token not found in database")
        return jsonify({'error': 'token_revoked'}), 401

    mapping = mongo.db.user_client_ids.find_one({'user_id': user_id, 'client_id': client_id})
    if mapping:
        sub = mapping['sub']
    else:
        sub = token_urlsafe(16)
        mongo.db.user_client_ids.insert_one({'user_id': user_id, 'client_id': client_id, 'sub': sub})

    user = mongo.db.users.find_one({'user_id': user_id})
    if not user:
        return jsonify({'error': 'user_not_found'}), 404

    userinfo_response = {
        'sub': sub,
        'name': user.get('username'),
        'email': user.get('email')
    }

    logging.info("=== /userinfo endpoint success ===")
    return jsonify(userinfo_response), 200


@user_bp.route('/forgotPasswd')
def forgot_passwd():
    return render_template('forgotPasswd.html')