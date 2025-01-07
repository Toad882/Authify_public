from flask import Blueprint, request, jsonify, session, redirect, url_for, flash, render_template
from auth import query_client, generate_csrf_token
from werkzeug.security import generate_password_hash, check_password_hash
from webauthn.helpers.structs import AuthenticatorAttestationResponse
from webauthn.helpers.structs import AuthenticatorAssertionResponse
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AttestationConveyancePreference
)
import webauthn
import base64
from models import mongo, check_db_connection
import logging
from routes.oauth_server import oauth
import uuid
import os
import json
from authlib.oauth2.rfc6749 import OAuth2Request
from auth import CustomAuthorizationCodeGrant
from flask_wtf.csrf import CSRFProtect
from models import User
import pyotp

def create_auth_bp():
    auth_bp = Blueprint('auth', __name__)
    from app import csrf


    def extract_client_id(request):
        logging.info("Extracting client ID...")
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic '):
            base64_credentials = request.headers['Authorization'].split(' ')[1]
            decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
            client_id, _ = decoded_credentials.split(':', 1)
        else:
            client_id = request.form.get('client_id') or request.data.get('client_id')
            logging.info(f"Extracted Client ID: {client_id}")
        return client_id


    def extract_client_secret(request):
        logging.info("Extracting client secret...")
        if 'Authorization' in request.headers and request.headers['Authorization'].startswith('Basic '):
            base64_credentials = request.headers['Authorization'].split(' ')[1]
            decoded_credentials = base64.b64decode(base64_credentials).decode('utf-8')
            _, client_secret = decoded_credentials.split(':', 1)
        else:
            client_secret = request.form.get('client_secret') or request.data.get('client_secret')
        logging.info(f"Extracted Client Secret: {client_secret}")
        return client_secret

    def _hostname():
        return os.environ.get('HOSTNAME', 'idpproject-d92b6ed87815.herokuapp.com')

    @auth_bp.route('/')
    def home():
        # Redirect the user to the login page
        return redirect(url_for('auth.login'))

    @auth_bp.route('/authorize', methods=['GET'])
    def authorize():
        client_id = request.args.get('client_id')
        redirect_uri = request.args.get('redirect_uri')
        scope = request.args.get('scope')
        state = request.args.get('state')  # Extract the state parameter
        response_type = request.args.get('response_type')
        confirm = request.args.get('confirm')

        logging.info(f"Authorization request with response_type: {response_type}")
        logging.info(f"Incoming GET request parameters: {request.args}")

        if response_type != 'code':
            return jsonify({'error': 'unsupported_response_type'}), 400

        client = query_client(client_id)
        if not client:
            return "Invalid client", 400

        if 'user_id' not in session:
            session['next'] = request.url
            flash('You need to log in first.', 'error')
            return redirect(url_for('auth.login'))

        user_id = session['user_id']
        user = User(user_id=user_id)

        csrf_token = generate_csrf_token()

        if confirm == 'yes':
            logging.info(f"User confirmed authorization. Generating code and redirecting to {redirect_uri}.")
            auth_code = str(uuid.uuid4())

            # Create an OAuth2Request object
            params = {
                'client_id': client_id,
                'redirect_uri': redirect_uri,
                'scope': scope,
                'state': state,  # Ensure the state parameter is included
                'response_type': response_type
            }

            oauth2_request = OAuth2Request(
                method=request.method,
                uri=request.url,
                body=params
            )
            oauth2_request.client = client  # Ensure request.client is set
            oauth2_request.user = user  # Ensure request.user is set

            # Use the method from AuthorizationCodeGrant
            grant = CustomAuthorizationCodeGrant(oauth2_request, None)
            grant.save_authorization_code(auth_code, oauth2_request)

            redirection_url = f"{redirect_uri}?code={auth_code}&state={state}"
            logging.info(f"Redirection URL: {redirection_url}")
            return redirect(redirection_url)

        elif confirm == 'no':
            logging.info(f"User denied authorization. Redirecting to {redirect_uri} with error.")
            error_url = f"{redirect_uri}?error=access_denied&state={state}"
            return redirect(error_url)

        return render_template(
            'authorize.html',
            client=client,
            scope=scope,
            state=state,  # Pass the state parameter to the template
            redirect_uri=redirect_uri,
            csrf_token=csrf_token
        )

    @auth_bp.route('/token', methods=['POST'])
    @csrf.exempt
    def issue_token():
        logging.info(f"Handling token request: {request.data}")
        logging.info(f"Request headers: {request.headers}")
        logging.info(f"Request form data: {request.form}")

        try:
            csrf_token = request.form.get('csrf_token')
            session_csrf_token = session.get('csrf_token')
            logging.info(f"CSRF token in session: {session_csrf_token}")
            logging.info(f"CSRF token received: {csrf_token}")
            if not csrf_token or csrf_token != session_csrf_token:
                logging.error("CSRF token mismatch.")
                #return jsonify({'error': 'invalid_csrf_token'}), 403
            client_id = extract_client_id(request)
            client_secret = extract_client_secret(request)

            if not client_id or not client_secret:
                logging.error("Client ID or secret is missing.")
                return jsonify({'error': 'invalid_request'}), 400

            client = query_client(client_id)
            if not client:
                logging.error(f"Client with ID {client_id} not found.")
                return jsonify({'error': 'invalid_client'}), 400

            if not client.check_client_secret(client_secret):
                logging.error("Invalid client credentials.")
                return jsonify({'error': 'invalid_client'}), 400

            # Create an OAuth2Request object
            params = {
                'grant_type': request.form.get('grant_type'),
                'redirect_uri': request.form.get('redirect_uri'),
                'code': request.form.get('code')
            }

            headers = dict(request.headers)

            oauth2_request = OAuth2Request(
                method=request.method,
                uri=request.url,
                body=params,
                headers=headers
            )
            oauth2_request.client = client  # Ensure request.client is set

            logging.info(f"OAuth2Request object created with client: {oauth2_request.client.get_client_id() if oauth2_request.client else 'None'}")

            response = oauth.create_token_response(oauth2_request)
            logging.info(f"Token response: {response[0]}")
            return response

        except Exception as e:
            logging.error(f"Error creating token response: {str(e)}")
            return jsonify({'error': str(e)}), 400

    @auth_bp.route('/login', methods=['GET', 'POST'])
    def login():
        if 'user_id' in session:
            next_url = session.pop('next', None)  # Provide a default value of None
            if next_url:
                return redirect(next_url)
            return redirect(url_for('user.dashboard'))

        form = request.form
        if request.method == 'POST':
            username = form.get('username')
            password = form.get('password')

            if not username or not password:
                flash('All fields are required.', 'error')
                return redirect(url_for('auth.login'))
            check_db_connection()
            user = mongo.db.users.find_one({'username': username})
            if not user:
                flash('Invalid username or password', 'error')
                return redirect(url_for('auth.login'))

            if user['password'] is None:
                flash('This account uses passkey for authentication. Please use passkey to log in.', 'error')
                return redirect(url_for('auth.login'))

            if not check_password_hash(user['password'], password):
                flash('Invalid username or password', 'error')
                return redirect(url_for('auth.login'))

            # Check if the user has a TOTP secret
            totp_secret = user.get('totp_secret')
            if totp_secret:
                # Store user details in session for later use
                session['login_user_id'] = user['user_id']
                session['login_username'] = username
                return redirect(url_for('auth.verify_login_totp'))

            # If no TOTP secret, proceed with login
            session['user_id'] = user['user_id']
            flash('Login successful!', 'success')
            next_url = session.pop('next', None)  # Provide a default value of None
            if next_url:
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
                return redirect(url_for('auth.verify_totp'))

            # Verify the TOTP token
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(totp_code):
                session['user_id'] = user_id
                flash('Login successful!', 'success')
                next_url = session.pop('next', None)  # Provide a default value of None
                if next_url:
                    return redirect(next_url)
                return redirect(url_for('user.dashboard'))
            else:
                flash('Invalid TOTP code. Please try again.', 'error')

        return render_template('login_totp_verification.html')

    @auth_bp.route('/logout', methods=['GET', 'POST'])
    def logout():
        session.pop('user_id', None)
        flash('You have been logged out.', 'success')
        return redirect(url_for('auth.login'))

    @auth_bp.route('/start_passkey_registration', methods=['POST'])
    def start_passkey_registration():
        user_id = str(uuid.uuid4())  # Generate a unique user ID

        username = request.form.get('username')
        email = request.form.get('email')

        if not username or not email:
            return jsonify({'status': 'error', 'message': 'Username and email are required'}), 400

        #if not csrf_token or csrf_token != session_csrf_token:
            #logging.error("Invalid CSRF token.")
            #logging.info(f"CSRF token received: {csrf_token}")
            #logging.info(f"CSRF token in session: {session_csrf_token}")
            #return jsonify({'status': 'error', 'message': 'Invalid CSRF token'}), 403
        check_db_connection()
        existing_user = mongo.db.users.find_one({'$or': [{'username': username}, {'email': email}]})
        if existing_user:
            return jsonify({'status': 'error', 'message': 'User or email already exists!'}), 400

        session['registration_username'] = username
        session['registration_email'] = email

        rp_id = _hostname()
        rp_name = "IDP Project"
        display_name = request.form.get('display_name', username)

        registration_options = generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_id=user_id.encode('utf-8'),
            user_name=username,
            user_display_name=display_name,
            authenticator_selection=AuthenticatorSelectionCriteria(
                require_resident_key=False,
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.PREFERRED
            ),
            attestation=AttestationConveyancePreference.DIRECT,
        )

        session['registration_challenge'] = base64.b64encode(registration_options.challenge).decode('utf-8')
        session['registration_user_id'] = user_id

        registration_options_json = json.loads(webauthn.options_to_json(registration_options))

        return jsonify({
            'status': 'success',
            'registrationOptions': {
                **registration_options_json,
                'user': {
                    'id': base64.b64encode(user_id.encode('utf-8')).decode('utf-8'),
                    'name': username,
                    'displayName': display_name
                }
            },
            'username': username,
            'email': email
        })


    @auth_bp.route('/verify_passkey_registration', methods=['POST'])
    def verify_passkey_registration():
        data = request.get_json()

        try:
            attestation_object = base64.urlsafe_b64decode(data['response']['attestationObject'] + '==')
            client_data_json = base64.urlsafe_b64decode(data['response']['clientDataJSON'] + '==')
            credential_id = data['id']
            raw_id = data['rawId']
            response = data['response']

            raw_id_bytes = base64.urlsafe_b64decode(raw_id + '==')

            registration_credential = RegistrationCredential(
                id=credential_id,
                raw_id=raw_id_bytes,
                response=AuthenticatorAttestationResponse(
                    attestation_object=attestation_object,
                    client_data_json=client_data_json
                )
            )

            user_id = session.pop('registration_user_id')
            if not user_id:
                return jsonify({'status': 'error', 'message': 'User ID not found'}), 400

            expected_challenge = base64.urlsafe_b64decode(session.pop('registration_challenge') + '==')
            if not expected_challenge:
                return jsonify({'status': 'error', 'message': 'Challenge not found or expired'}), 400

            verification_result = verify_registration_response(
                credential=registration_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=_hostname(),
                expected_origin="https://" + _hostname()
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

            session['user_id'] = user_id
            flash('Passkey registration successful!', 'success')
            return jsonify(
                {'status': 'success', 'message': 'Passkey registered successfully', 'redirect': url_for('user.dashboard')})
        except Exception as e:
            logging.error(f"Error during passkey registration: {str(e)}")
            return jsonify({'status': 'error', 'message': str(e)}), 400


    @auth_bp.route('/start_passkey_authentication', methods=['POST'])
    def start_passkey_authentication():
        rp_id = _hostname()

        username = request.form.get('username')
        check_db_connection()
        user = mongo.db.users.find_one({'username': username})
        if not user:
            return jsonify({'status': 'error', 'message': 'User not found'}), 400

        if user['credentialId'] is None:
            return jsonify({'status': 'error',
                            'message': 'This account uses password for authentication. Please use password to log in.'}), 400

        authentication_options = generate_authentication_options(
            rp_id=rp_id,
            user_verification=UserVerificationRequirement.PREFERRED
        )

        allow_credentials = [
            {
                'type': 'public-key',
                'id': base64.b64encode(cred.id).decode('utf-8')
            } for cred in authentication_options.allow_credentials
        ]

        session['authentication_challenge'] = base64.b64encode(authentication_options.challenge).decode('utf-8')

        return jsonify({
            'status': 'success',
            'authenticationOptions': {
                'challenge': base64.b64encode(authentication_options.challenge).decode('utf-8'),
                'rpId': rp_id,
                'allowCredentials': allow_credentials,
                'userVerification': authentication_options.user_verification.value
            }
        })

    @auth_bp.route('/verify_passkey_authentication', methods=['POST'])
    def verify_passkey_authentication():
        try:
            data = request.get_json()

            credential_id = data['id']
            raw_id = data['rawId']
            response = data['response']

            raw_id_bytes = base64.urlsafe_b64decode(raw_id + '==')

            authentication_credential = AuthenticationCredential(
                id=credential_id,
                raw_id=raw_id_bytes,
                response=AuthenticatorAssertionResponse(
                    authenticator_data=base64.urlsafe_b64decode(response['authenticatorData'] + '=='),
                    client_data_json=base64.urlsafe_b64decode(response['clientDataJSON'] + '=='),
                    signature=base64.urlsafe_b64decode(response['signature'] + '=='),
                    user_handle=base64.urlsafe_b64decode(response['userHandle'] + '==') if response.get('userHandle') else None
                )
            )
            check_db_connection()
            user = mongo.db.users.find_one(
                {'credentialId': base64.b64encode(authentication_credential.raw_id).decode('utf-8')}
            )
            if not user:
                flash('User not found.', 'error')
                return jsonify({'status': 'error', 'message': 'User not found'}), 400

            expected_challenge = base64.urlsafe_b64decode(session.pop('authentication_challenge') + '==')
            if not expected_challenge:
                return jsonify({'status': 'error', 'message': 'Challenge not found or expired'}), 400

            verification_result = verify_authentication_response(
                credential=authentication_credential,
                expected_challenge=expected_challenge,
                expected_rp_id=_hostname(),
                expected_origin="https://" + _hostname(),
                credential_public_key=user['publicKeyJwk'],
                credential_current_sign_count=user.get('signCount', 0)
            )

            mongo.db.users.update_one(
                {'user_id': user['user_id']},
                {'$set': {
                    'signCount': verification_result.new_sign_count
                }}
            )

            session['user_id'] = user['user_id']
            flash('Passkey authentication successful!', 'success')

            next_url = session.pop('next', url_for('user.dashboard'))
            logging.info(f"Redirecting to: {next_url}")
            return jsonify({'status': 'success', 'message': 'Passkey authentication successful!', 'next_url': next_url})

        except Exception as e:
            logging.error(f"Error during passkey authentication: {str(e)}")
            flash('Error during passkey authentication.', 'error')
            return jsonify({'status': 'error', 'message': str(e)}), 500

    return auth_bp