from flask import Blueprint, request, jsonify, session, redirect, url_for, flash, render_template

from auth import query_client

from werkzeug.security import check_password_hash

from webauthn.helpers.structs import AuthenticatorAttestationResponse, AuthenticatorAssertionResponse

from webauthn import (
generate_registration_options, verify_registration_response,
generate_authentication_options, verify_authentication_response,
)

from webauthn.helpers.structs import (
RegistrationCredential, AuthenticationCredential,
AuthenticatorSelectionCriteria, UserVerificationRequirement,
ResidentKeyRequirement, AttestationConveyancePreference
)

import webauthn
import base64
from models import mongo, check_db_connection
import logging
import uuid
import os
import json
from authlib.oauth2.rfc6749 import OAuth2Request
from auth import CustomAuthorizationCodeGrant
from models import User
import pyotp
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta

def is_safe_url_target(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def regenerate_session():
    old_data = dict(session)
    session.clear()
    session.update(old_data)
    session.permanent = True

def safe_error_response(error_type, debug_info=None):
    from app import app
    if app.debug and debug_info:
        return jsonify({'error': error_type, 'debug': debug_info})
    return jsonify({'error': 'An error occurred. Please try again.'})

def safe_log_client_info(client_id, operation):
    masked_id = f"{client_id[:8]}***" if len(client_id) > 8 else "***"
    logging.info(f"{operation} for client: {masked_id}")

def safe_base64_decode(data_string):
    if not data_string:
        raise ValueError("Empty data string")
    try:
        return base64.urlsafe_b64decode(data_string)
    except Exception:
        try:
            missing_padding = len(data_string) % 4
            if missing_padding:
                data_string += '=' * (4 - missing_padding)
            return base64.urlsafe_b64decode(data_string)
        except Exception:
            try:
                return base64.b64decode(data_string)
            except Exception:
                missing_padding = len(data_string) % 4
                if missing_padding:
                    data_string += '=' * (4 - missing_padding)
                return base64.b64decode(data_string)

def create_auth_bp():
    auth_bp = Blueprint('auth', __name__)
    from app import csrf, limiter

    def extract_client_id(request):
        logging.info("Extracting client ID...")
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic '):
            base64_credentials = request.headers['Authorization'].split(' ', 1)[1]
            decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
            client_id, _ = decoded_credentials.split(':', 1)
        else:
            client_id = request.form.get('client_id') or request.json.get('client_id')
        safe_log_client_info(client_id if client_id else "unknown", "Client ID extraction")
        return client_id

    def extract_client_secret(request):
        logging.info("Extracting client secret...")
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic '):
            base64_credentials = request.headers['Authorization'].split(' ', 1)[1]
            decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
            _, client_secret = decoded_credentials.split(':', 1)
        else:
            client_secret = request.form.get('client_secret') or request.json.get('client_secret')
        logging.info("Client secret extracted successfully")
        return client_secret

    def hostname():
        return os.environ.get('HOSTNAME', 'idp-project-d92b6ed87815.herokuapp.com')

    @auth_bp.route('/')
    def home():
        return redirect(url_for('auth.login'))

    @auth_bp.route('/authorize', methods=['GET'])
    def authorize():
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope')
        state = request.args.get('state')
        response_type = request.args.get('response_type')
        confirm = request.args.get('confirm')

        logging.info(f"Authorization request with response_type: {response_type}")

        next_url = request.args.get('next')
        if next_url and is_safe_url_target(next_url):
            session['next'] = next_url
        else:
            session.pop('next', None)

        if response_type != 'code':
            return jsonify({'error': 'unsupported_response_type'}), 400

        client = query_client(client_id)
        if not client:
            return "Invalid client", 400

        registered_uris = client.redirect_uri if hasattr(client, 'redirect_uri') else [client.redirect_uri]
        if redirect_uri not in registered_uris:
            logging.error(f"Invalid redirect_uri: {redirect_uri}")
            return jsonify({'error': 'invalid_redirect_uri'}), 400

        client_name = client.client_name

        if 'user_id' not in session:
            flash('You need to log in first.', 'error')
            session['next'] = request.url
            return redirect(url_for('auth.login'))

        user_id = session['user_id']
        user = User(user_id=user_id)
        csrf_token = session['csrf_token']

        if confirm == 'yes':
            logging.info(f"User confirmed authorization. Generating code and redirecting to {redirect_uri}.")
            auth_code = str(uuid.uuid4())

            # Create OAuth2Request without deprecated 'body' parameter
            oauth2_request = OAuth2Request(method=request.method, uri=request.url)

            # Manually create a simple payload object for the request
            class AuthPayload:
                def __init__(self, **kwargs):
                    for key, value in kwargs.items():
                        setattr(self, key, value)

            oauth2_request.payload = AuthPayload(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                response_type=response_type,
                state=state,
                next_url=session.get('next')
            )

            oauth2_request.client = client
            oauth2_request.user = user

            grant = CustomAuthorizationCodeGrant(oauth2_request, None)
            grant.save_authorization_code(auth_code, oauth2_request)

            redirection_url = f"{redirect_uri}?code={auth_code}&state={state}"
            logging.info(f"Redirection URL: {redirection_url}")
            session.pop('next', None)
            return redirect(redirection_url)

        elif confirm == 'no':
            logging.info(f"User denied authorization. Redirecting to {redirect_uri} with error.")
            error_url = f"{redirect_uri}?error=access_denied&state={state}"
            session.pop('next', None)
            return redirect(error_url)

        return render_template('authorize.html', client=client, scope=scope, state=state,
                               redirect_uri=redirect_uri, csrf_token=csrf_token, client_name=client_name)



    @auth_bp.route('/token', methods=['POST'])
    @csrf.exempt
    def issue_token():
        logging.info("=== TOKEN ENDPOINT CALLED ===")
        try:
            logging.info(f"Request method: {request.method}")
            logging.info(f"Request form data: {dict(request.form)}")
            logging.info(f"Request headers: {dict(request.headers)}")

            client_id = None
            client_secret = None

            if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic '):
                import base64
                try:
                    base64_credentials = request.headers['Authorization'].split(' ', 1)[1]
                    decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
                    client_id, client_secret = decoded_credentials.split(':', 1)
                    logging.info(f"Extracted credentials from Authorization header")
                except Exception as e:
                    logging.error(f"Error parsing Authorization header: {e}")

            if not client_id:
                client_id = request.form.get('client_id')
                client_secret = request.form.get('client_secret')
                logging.info(f"Using credentials from form data")

            if not client_id or not client_secret:
                logging.error("Client ID or secret is missing.")
                return jsonify({'error': 'invalid_request'}), 400

            logging.info(f"Looking up client: {client_id}")
            from auth import query_client
            client = query_client(client_id)

            if not client:
                logging.error(f"Client not found: {client_id}")
                return jsonify({'error': 'invalid_client'}), 400

            if not client.check_client_secret(client_secret):
                logging.error("Invalid client credentials.")
                return jsonify({'error': 'invalid_client'}), 400

            logging.info("Client authenticated successfully")

            grant_type = request.form.get('grant_type')
            authorization_code = request.form.get('code')
            redirect_uri = request.form.get('redirect_uri')

            logging.info(f"Grant type: {grant_type}")
            logging.info(f"Authorization code: {authorization_code[:10] if authorization_code else None}...")
            logging.info(f"Redirect URI: {redirect_uri}")

            if grant_type != 'authorization_code':
                logging.error(f"Unsupported grant type: {grant_type}")
                return jsonify({'error': 'unsupported_grant_type'}), 400

            if not authorization_code:
                logging.error("Authorization code is missing")
                return jsonify({'error': 'invalid_request'}), 400

            logging.info("Querying authorization code from database...")

            try:
                from models import mongo
                from datetime import datetime

                code_data = mongo.db.authorization_codes.find_one({
                    'code': authorization_code,
                    'client_id': client_id
                })

                if not code_data:
                    logging.error(f"Authorization code not found in database")
                    return jsonify({'error': 'invalid_grant'}), 400

                if 'expires_at' in code_data and datetime.utcnow() > code_data['expires_at']:
                    logging.error("Authorization code has expired")
                    mongo.db.authorization_codes.delete_one({'_id': code_data['_id']})
                    return jsonify({'error': 'invalid_grant'}), 400

                if code_data['redirect_uri'] != redirect_uri:
                    logging.error(f"Redirect URI mismatch. Expected: {code_data['redirect_uri']}, Got: {redirect_uri}")
                    return jsonify({'error': 'invalid_grant'}), 400

                logging.info("Authorization code validated successfully")

                import secrets
                import jwt
                from datetime import datetime, timedelta
                from config import Config

                access_token = secrets.token_urlsafe(32)
                payload = {
                    'sub': code_data['user'],
                    'aud': client_id,
                    'iss': 'idp-project',
                    'exp': datetime.utcnow() + timedelta(hours=1),
                    'iat': datetime.utcnow(),
                    'scope': code_data['scope']
                }

                jwt_token = jwt.encode(payload, Config.SECRET_KEY, algorithm='HS256')

                from models import Token
                token_data = {
                    'access_token': access_token,
                    'client_id': client_id,
                    'user_id': code_data['user'],
                    'expires_at': datetime.utcnow() + timedelta(hours=1),
                    'scope': code_data['scope'],
                    'token_type': 'Bearer'
                }

                mongo.db.tokens.update_one(
                    {'client_id': client_id, 'user_id': code_data['user']},
                    {'$set': token_data},
                    upsert=True
                )

                mongo.db.authorization_codes.delete_one({'code': authorization_code})
                logging.info("Token created and saved successfully")

                response = {
                    'access_token': jwt_token,
                    'token_type': 'Bearer',
                    'expires_in': 3600,
                    'scope': code_data['scope']
                }

                logging.info("=== TOKEN ENDPOINT SUCCESS ===")
                return jsonify(response), 200

            except Exception as db_error:
                logging.error(f"Database error: {str(db_error)}")
                import traceback
                logging.error(f"Database error traceback: {traceback.format_exc()}")
                return jsonify({'error': 'server_error'}), 500

        except Exception as e:
            logging.error(f"Token endpoint error: {str(e)}")
            import traceback
            logging.error(f"Full traceback: {traceback.format_exc()}")
            return jsonify({'error': 'server_error'}), 500

    @auth_bp.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute")
    def login():
        if 'user_id' in session:
            next_url = session.pop('next', None)
            if next_url and is_safe_url_target(next_url):
                return redirect(next_url)
            return redirect(url_for('user.dashboard'))

        form = request.form

        if request.method == 'POST':
            username = form.get('username')
            password = form.get('password')

            failed_attempts = session.get('failed_login_attempts', 0)
            last_attempt_time = session.get('last_failed_attempt')

            if failed_attempts >= 3:
                if last_attempt_time:
                    time_diff = datetime.now() - datetime.fromisoformat(last_attempt_time)
                    if time_diff < timedelta(minutes=5):
                        flash('Account temporarily locked due to too many failed attempts. Try again in 5 minutes.',
                              'error')
                        return render_template('login.html')
                    else:
                        session['failed_login_attempts'] = 0

            if not username or not password:
                flash('All fields are required.', 'error')
                return redirect(url_for('auth.login'))

            check_db_connection()
            user = mongo.db.users.find_one({'username': username})

            if not user:
                session['failed_login_attempts'] = failed_attempts + 1
                session['last_failed_attempt'] = datetime.now().isoformat()
                flash('Invalid username or password', 'error')
                return redirect(url_for('auth.login'))

            if user.get('password') is None:
                flash('This account uses passkey for authentication. Please use passkey to log in.', 'error')
                return redirect(url_for('auth.login'))

            if not check_password_hash(user['password'], password):
                session['failed_login_attempts'] = failed_attempts + 1
                session['last_failed_attempt'] = datetime.now().isoformat()
                flash('Invalid username or password', 'error')
                return redirect(url_for('auth.login'))

            session.pop('failed_login_attempts', None)
            session.pop('last_failed_attempt', None)

            totp_secret = user.get('totp_secret')
            if totp_secret:
                session['login_user_id'] = user['user_id']
                session['login_username'] = username
                return redirect(url_for('auth.verify_login_totp'))

            regenerate_session()
            session['user_id'] = user['user_id']
            flash('Login successful!', 'success')

            next_url = session.pop('next', None)
            if next_url and is_safe_url_target(next_url):
                return redirect(next_url)
            return redirect(url_for('user.dashboard'))

        return render_template('login.html')

    @auth_bp.route('/verify_login_totp', methods=['GET', 'POST'])
    def verify_login_totp():
        user_id = session.get('login_user_id')
        username = session.get('login_username')

        if not user_id or not username:
            flash('Session expired. Please start the login process again.', 'error')
            return redirect(url_for('auth.login'))

        check_db_connection()
        user = mongo.db.users.find_one({'user_id': user_id})

        if not user:
            flash('User not found. Please try again.', 'error')
            return redirect(url_for('auth.login'))

        totp_secret = user.get('totp_secret')

        form = request.form
        if request.method == 'POST':
            totp_code = form.get('totp_code')

            if not totp_code:
                flash('TOTP code is required.', 'error')
                return redirect(url_for('auth.verify_login_totp'))

            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                session.pop('login_user_id', None)
                session.pop('login_username', None)

                regenerate_session()
                session['user_id'] = user_id
                flash('Login successful!', 'success')

                next_url = session.pop('next', None)
                if next_url and is_safe_url_target(next_url):
                    return redirect(next_url)
                return redirect(url_for('user.dashboard'))
            else:
                flash('Invalid TOTP code. Please try again.', 'error')

        return render_template('login_totp_verification.html')

    @auth_bp.route('/logout', methods=['GET', 'POST'])
    def logout():
        session.clear()
        flash('You have been logged out.', 'success')
        return redirect(url_for('auth.login'))

    @auth_bp.route('/start_passkey_registration', methods=['POST'])
    def start_passkey_registration():
        try:
            user_id = str(uuid.uuid4())
            username = request.form.get('username')
            email = request.form.get('email')

            if not username or not email:
                return jsonify({'status': 'error', 'message': 'Username and email are required'}), 400

            check_db_connection()
            existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
            if existing_user:
                return jsonify({'status': 'error', 'message': 'User or email already exists!'}), 400

            session['registration_username'] = username
            session['registration_email'] = email

            rp_id = hostname()
            rp_name = "IDP Project"
            display_name = request.form.get('display_name', username)

            registration_options = generate_registration_options(
                rp_id=rp_id,
                rp_name=rp_name,
                user_id=user_id.encode('utf-8'),
                user_name=username,
                user_display_name=display_name,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    require_resident_key=True,
                    resident_key=ResidentKeyRequirement.REQUIRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                attestation=AttestationConveyancePreference.DIRECT,
            )

            session['registration_challenge'] = base64.urlsafe_b64encode(registration_options.challenge).decode('utf-8')
            session['registration_user_id'] = user_id

            registration_options_json = json.loads(webauthn.options_to_json(registration_options))

            return jsonify({
                'status': 'success',
                'registrationOptions': registration_options_json,
                'user': {
                    'id': base64.urlsafe_b64encode(user_id.encode('utf-8')).decode('utf-8'),
                    'name': username,
                    'displayName': display_name,
                },
                'username': username,
                'email': email
            })

        except Exception as e:
            logging.error(f"Error starting passkey registration: {str(e)}")
            import traceback
            logging.error(f"Full traceback: {traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': f'Registration start failed: {str(e)}'}), 400

    @auth_bp.route('/verify_passkey_registration', methods=['POST'])
    def verify_passkey_registration():
        data = request.get_json()

        try:
            attestation_object = safe_base64_decode(data['response']['attestationObject'])
            client_data_json = safe_base64_decode(data['response']['clientDataJSON'])
            credential_id = data['id']
            raw_id = data['rawId']

            raw_id_bytes = safe_base64_decode(raw_id)

            registration_credential = RegistrationCredential(
                id=credential_id,
                raw_id=raw_id_bytes,
                response=AuthenticatorAttestationResponse(
                    attestation_object=attestation_object,
                    client_data_json=client_data_json,
                ),
            )

            user_id = session.pop('registration_user_id')
            if not user_id:
                return jsonify({'status': 'error', 'message': 'User ID not found'}), 400

            expected_challenge = safe_base64_decode(session.pop('registration_challenge'))
            if not expected_challenge:
                return jsonify({'status': 'error', 'message': 'Challenge not found or expired'}), 400

            verification_result = verify_registration_response(
                credential=registration_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=hostname(),
                expected_origin=f"https://{hostname()}"
            )

            username = session.pop('registration_username')
            email = session.pop('registration_email')

            check_db_connection()
            mongo.db.users.update_one(
                {'user_id': user_id},
                {'$set': {
                    'username': username,
                    'email': email,
                    'credentialId': base64.b64encode(verification_result.credential_id).decode('utf-8'),
                    'publicKeyJwk': verification_result.credential_public_key,
                    'role': 'user',
                    'password': None
                }},
                upsert=True
            )

            regenerate_session()
            session['user_id'] = user_id
            flash('Passkey registration successful!', 'success')

            return jsonify({
                'status': 'success',
                'message': 'Passkey registered successfully',
                'redirect': url_for('user.dashboard')
            })

        except Exception as e:
            logging.error(f"Error during passkey registration: {str(e)}")
            import traceback
            logging.error(f"Full traceback: {traceback.format_exc()}")
            error_message = str(e)
            if "Incorrect padding" in error_message:
                error_message = "Base64 decoding error - check WebAuthn data format"
            elif "Invalid" in error_message:
                error_message = "WebAuthn validation failed"
            return jsonify({'status': 'error', 'message': f'Registration failed: {error_message}'}), 400

    @auth_bp.route('/start_passkey_authentication', methods=['POST'])
    def start_passkey_authentication():
        try:
            rp_id = hostname()

            authentication_options = generate_authentication_options(
                rp_id=rp_id,
                user_verification=UserVerificationRequirement.REQUIRED,
            )

            session['authentication_challenge'] = base64.urlsafe_b64encode(authentication_options.challenge).decode('utf-8')

            return jsonify({
                'status': 'success',
                'authenticationOptions': {
                    'challenge': base64.urlsafe_b64encode(authentication_options.challenge).decode('utf-8'),
                    'rpId': rp_id,
                    'userVerification': authentication_options.user_verification.value
                }
            })

        except Exception as e:
            logging.error(f"Error starting passkey authentication: {str(e)}")
            import traceback
            logging.error(f"Full start auth traceback: {traceback.format_exc()}")
            return jsonify({'status': 'error', 'message': f'Authentication start failed: {str(e)}'}), 400

    @auth_bp.route('/verify_passkey_authentication', methods=['POST'])
    def verify_passkey_authentication():
        try:
            data = request.get_json()
            credential_id = data['id']
            raw_id = data['rawId']
            response = data['response']

            raw_id_bytes = safe_base64_decode(raw_id)
            authenticator_data = safe_base64_decode(response['authenticatorData'])
            client_data_json = safe_base64_decode(response['clientDataJSON'])
            signature = safe_base64_decode(response['signature'])

            user_handle = None
            if response.get('userHandle'):
                user_handle = safe_base64_decode(response['userHandle'])

            authentication_credential = AuthenticationCredential(
                id=credential_id,
                raw_id=raw_id_bytes,
                response=AuthenticatorAssertionResponse(
                    authenticator_data=authenticator_data,
                    client_data_json=client_data_json,
                    signature=signature,
                    user_handle=user_handle,
                )
            )

            check_db_connection()
            user = None

            user = mongo.db.users.find_one({
                'credentialId': base64.b64encode(authentication_credential.raw_id).decode('utf-8')
            })

            if not user and user_handle:
                try:
                    user_id_from_handle = user_handle.decode('utf-8')
                    user = mongo.db.users.find_one({'user_id': user_id_from_handle})
                    logging.info(f"Found user by userHandle: {user_id_from_handle[:8]}***")
                except:
                    logging.warning("Failed to decode userHandle as user_id")

            if not user:
                logging.error('User not found for passkey authentication')
                return jsonify({'status': 'error', 'message': 'User not found or passkey not recognized'}), 400

            expected_challenge = safe_base64_decode(session.pop('authentication_challenge', ''))
            if not expected_challenge:
                return jsonify({'status': 'error', 'message': 'Challenge not found or expired'}), 400

            verification_result = verify_authentication_response(
                credential=authentication_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=hostname(),
                expected_origin=f"https://{hostname()}",
                credential_public_key=user['publicKeyJwk'],
                credential_current_sign_count=user.get('sign_count', 0)
            )

            mongo.db.users.update_one(
                {'user_id': user['user_id']},
                {'$set': {'sign_count': verification_result.new_sign_count}}
            )

            regenerate_session()
            session['user_id'] = user['user_id']
            flash('Passkey authentication successful!', 'success')

            next_url = session.pop('next', None)
            if next_url and is_safe_url_target(next_url):
                redirect_url = next_url
            else:
                redirect_url = url_for('user.dashboard')

            logging.info(f"Usernameless passkey auth successful for user: {user['username']}, redirecting to: {redirect_url}")

            return jsonify({
                'status': 'success',
                'message': f'Welcome back, {user["username"]}!',  # Show username after authentication
                'next_url': redirect_url
            })

        except Exception as e:
            logging.error(f"Error during passkey authentication: {str(e)}")
            import traceback
            logging.error(f"Full authentication traceback: {traceback.format_exc()}")
            error_message = str(e)
            if "Incorrect padding" in error_message:
                error_message = "Base64 decoding error in WebAuthn data"
            elif "Invalid" in error_message:
                error_message = "WebAuthn authentication validation failed"
            elif "Challenge" in error_message:
                error_message = "Authentication challenge expired or invalid"
            return jsonify({'status': 'error', 'message': f'Authentication failed: {error_message}'}), 500

    return auth_bp