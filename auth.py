import logging
import secrets
from authlib.integrations.flask_oauth2 import ResourceProtector, AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc6749.errors import InvalidGrantError
from models import mongo, Client, Token, AuthorizationCode, User
from flask import session
from datetime import datetime, timedelta
import re


def validate_input_string(value, pattern=None, max_length=255):
    if not isinstance(value, str):
        return False
    if len(value) > max_length:
        return False
    if pattern and not re.match(pattern, value):
        return False
    return True


def safe_error_response(error_type, debug_info=None):
    import os
    debug_mode = os.environ.get('FLASK_ENV') == 'development'

    if debug_mode and debug_info:
        return {'error': error_type, 'debug': debug_info}

    error_messages = {
        'invalid_request': 'The request is invalid.',
        'invalid_client': 'Client authentication failed.',
        'invalid_grant': 'The authorization grant is invalid.',
        'unauthorized_client': 'The client is not authorized.',
        'unsupported_grant_type': 'The authorization grant type is not supported.',
        'invalid_scope': 'The requested scope is invalid.',
        'server_error': 'The server encountered an unexpected condition.',
        'temporarily_unavailable': 'The service is temporarily overloaded.',
        'access_denied': 'The request was denied.',
        'unsupported_response_type': 'The response type is not supported.'
    }

    return {'error': error_messages.get(error_type, 'An error occurred. Please try again.')}


class SecurityLogger:
    def __init__(self):
        self.logger = logging.getLogger('security')
        if not self.logger.handlers:
            handler = logging.FileHandler('security.log')
            formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def log_auth_event(self, event_type, user_id=None, client_id=None, ip_address=None, details=None):
        masked_user = f"{user_id[:8]}***" if user_id and len(user_id) > 8 else "unknown"
        masked_client = f"{client_id[:8]}***" if client_id and len(client_id) > 8 else "unknown"

        log_message = f"{event_type} - User: {masked_user}, Client: {masked_client}, IP: {ip_address or 'unknown'}"
        if details:
            log_message += f", Details: {details}"

        self.logger.info(log_message)


security_logger = SecurityLogger()


def query_client(client_id):
    try:
        if not validate_input_string(client_id):
            return None

        client_data = mongo.db.clients.find_one({'client_id': client_id})
        if client_data:
            return Client(
                client_id=client_data['client_id'],
                client_secret=client_data.get('client_secret'),
                redirect_uri=client_data.get('redirect_uri', []),
                client_name=client_data.get('client_name', 'Unknown Client')
            )
        return None
    except Exception as e:
        logging.error(f"Error querying client: {str(e)}")
        return None


def save_token(token, request, *args, **kwargs):
    try:
        if not validate_input_string(request.client.client_id):
            raise InvalidGrantError("Invalid client ID")

        if request.user and hasattr(request.user, 'id'):
            user_id = request.user.id
        else:
            user_id = session.get('user_id')

        if not user_id:
            raise InvalidGrantError("User not authenticated")

        token_data = Token(
            client_id=request.client.client_id,
            user_id=user_id,
            access_token=token.get('access_token'),
            refresh_token=token.get('refresh_token', None),
            expires_at=datetime.utcnow() + timedelta(seconds=token.get('expires_in', 3600)),
            scope=token.get('scope', '')
        )

        mongo.db.tokens.update_one(
            {'client_id': request.client.client_id, 'user_id': user_id},
            {'$set': token_data.__dict__},
            upsert=True
        )

        # Log successful token creation (without sensitive data)
        security_logger.log_auth_event(
            'TOKEN_CREATED',
            user_id=user_id,
            client_id=request.client.client_id,
            ip_address=request.environ.get('REMOTE_ADDR') if hasattr(request, 'environ') else None
        )

    except Exception as e:
        logging.error(f"Error saving token: {str(e)}")
        raise InvalidGrantError("Failed to save token")


def generate_csrf_token():
    return secrets.token_urlsafe(32)


class CustomAuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ['client_secret_basic', 'client_secret_post']

    def save_authorization_code(self, code, request):
        try:
            if not validate_input_string(code):
                raise InvalidGrantError("Invalid authorization code format")

            if not validate_input_string(request.client.client_id):
                raise InvalidGrantError("Invalid client ID format")

            # Use the correct attribute name based on models.py User class
            if request.user and hasattr(request.user, 'id'):
                user_id = request.user.id
            else:
                user_id = session.get('user_id')

            if not user_id:
                raise InvalidGrantError("User not authenticated")

            code_data = AuthorizationCode(
                code=code,
                client_id=request.client.client_id,
                redirect_uri=request.redirect_uri,
                scope=request.scope,
                user=user_id,
                state=getattr(request, 'state', None)
            )

            code_dict = code_data.__dict__.copy()
            code_dict['expires_at'] = datetime.utcnow() + timedelta(minutes=10)

            mongo.db.authorization_codes.insert_one(code_dict)

            security_logger.log_auth_event(
                'AUTH_CODE_CREATED',
                user_id=user_id,
                client_id=request.client.client_id,
                ip_address=getattr(request, 'remote_addr', None)
            )

        except Exception as e:
            logging.error(f"Error saving authorization code: {str(e)}")
            raise InvalidGrantError("Failed to save authorization code")

    def query_authorization_code(self, code, client):
        try:
            if not validate_input_string(code):
                return None

            if not validate_input_string(client.client_id):
                return None

            code_data = mongo.db.authorization_codes.find_one({
                'code': code,
                'client_id': client.client_id
            })

            if code_data:
                if 'expires_at' in code_data and datetime.utcnow() > code_data['expires_at']:
                    mongo.db.authorization_codes.delete_one({'_id': code_data['_id']})
                    return None

                return AuthorizationCode(
                    code=code_data['code'],
                    client_id=code_data['client_id'],
                    redirect_uri=code_data['redirect_uri'],
                    scope=code_data['scope'],
                    user=code_data['user'],
                    state=code_data.get('state')
                )
            return None

        except Exception as e:
            logging.error(f"Error querying authorization code: {str(e)}")
            return None

    def delete_authorization_code(self, authorization_code):
        try:
            mongo.db.authorization_codes.delete_one({'code': authorization_code.code})
        except Exception as e:
            logging.error(f"Error deleting authorization code: {str(e)}")

    def authenticate_user(self, authorization_code):
        try:
            user_id = authorization_code.user

            if not validate_input_string(user_id):
                return None

            user_data = mongo.db.users.find_one({'user_id': user_id})
            if user_data:
                return User(user_id=user_data['user_id'])
            return None

        except Exception as e:
            logging.error(f"Error authenticating user: {str(e)}")
            return None


class CustomAuthorizationServer(AuthorizationServer):
    def create_oauth2_request(self, request):
        try:
            return super().create_oauth2_request(request)
        except Exception as e:
            logging.error(f"Error creating OAuth2 request: {str(e)}")
            return None

    def handle_response(self, response_data, headers):
        try:
            import os
            if os.environ.get('FLASK_ENV') != 'development':
                if isinstance(response_data, dict) and 'debug' in response_data:
                    response_data = {k: v for k, v in response_data.items() if k != 'debug'}

            return super().handle_response(response_data, headers)
        except Exception as e:
            logging.error(f"Error handling response: {str(e)}")
            return safe_error_response('server_error'), 500


require_oauth = ResourceProtector()


def create_revoke_token_validator():
    from authlib.oauth2.rfc7009 import RevocationEndpoint

    class TokenRevocationEndpoint(RevocationEndpoint):
        def query_token(self, token, token_type_hint):
            try:
                if not validate_input_string(token):
                    return None

                token_data = mongo.db.tokens.find_one({'access_token': token})
                if not token_data:
                    token_data = mongo.db.tokens.find_one({'refresh_token': token})

                if token_data:
                    return Token(
                        client_id=token_data['client_id'],
                        user_id=token_data['user_id'],
                        access_token=token_data['access_token'],
                        refresh_token=token_data.get('refresh_token'),
                        expires_at=token_data['expires_at'],
                        scope=token_data.get('scope', '')
                    )
                return None

            except Exception as e:
                logging.error(f"Error querying token for revocation: {str(e)}")
                return None

        def revoke_token(self, token):
            try:
                mongo.db.tokens.delete_many({
                    '$or': [
                        {'access_token': token.access_token},
                        {'refresh_token': token.refresh_token}
                    ]
                })

                security_logger.log_auth_event(
                    'TOKEN_REVOKED',
                    user_id=token.user_id,
                    client_id=token.client_id
                )

            except Exception as e:
                logging.error(f"Error revoking token: {str(e)}")

    return TokenRevocationEndpoint()


def validate_token_request(token_string):
    try:
        if not validate_input_string(token_string):
            return None

        token_data = mongo.db.tokens.find_one({'access_token': token_string})
        if token_data:
            if datetime.utcnow() > token_data['expires_at']:
                mongo.db.tokens.delete_one({'_id': token_data['_id']})
                return None

            return Token(
                client_id=token_data['client_id'],
                user_id=token_data['user_id'],
                access_token=token_data['access_token'],
                refresh_token=token_data.get('refresh_token'),
                expires_at=token_data['expires_at'],
                scope=token_data.get('scope', '')
            )
        return None

    except Exception as e:
        logging.error(f"Error validating token: {str(e)}")
        return None