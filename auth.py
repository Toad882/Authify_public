import logging
from authlib.integrations.flask_oauth2 import ResourceProtector, AuthorizationServer
from authlib.oauth2.rfc6749 import grants
from models import mongo, Client, Token, AuthorizationCode, User
import secrets
from flask import jsonify, session, request, redirect, url_for, flash

class CustomAuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    GRANT_TYPE = 'authorization_code'  # Ensure the grant type is set

    def save_authorization_code(self, code, request):
        logging.info(f"Saving authorization code: {code} for client: {request.client.get_client_id()}")
        if request.user is None:
            logging.error("Request user is None. Cannot save authorization code.")
            return

        try:
            mongo.db.authorization_codes.insert_one({
                'code': code,
                'client_id': request.client.get_client_id(),
                'redirect_uri': request.redirect_uri,
                'scope': request.scope,
                'user_id': request.user.id,
                'state': request.state
            })
            logging.info(f"Authorization code {code} saved successfully.")
        except Exception as e:
            logging.error(f"Failed to save authorization code: {str(e)}")

    def query_authorization_code(self, code, client):
        if client is None:
            logging.error(f"Client not found for authorization code: {code}")
            return None

        logging.info(f"Querying authorization code: {code} for client: {client.client_id}")
        try:
            auth_code = mongo.db.authorization_codes.find_one({'code': code})
            if auth_code:
                logging.info(f"Authorization code found: {auth_code}")
                return AuthorizationCode(
                    code=auth_code['code'],
                    client_id=auth_code['client_id'],
                    redirect_uri=auth_code['redirect_uri'],
                    scope=auth_code['scope'],
                    user=User(user_id=auth_code['user_id']),
                    state=auth_code['state']
                )
            else:
                logging.warning(f"Authorization code not found for code: {code}")
        except Exception as e:
            logging.error(f"Error querying authorization code: {str(e)}")
        return None

    def delete_authorization_code(self, authorization_code):
        # Delete the authorization code from your database
        try:
            mongo.db.authorization_codes.delete_one({'code': authorization_code.code})
            logging.info(f"Authorization code {authorization_code.code} deleted successfully.")
        except Exception as e:
            logging.error(f"Failed to delete authorization code: {str(e)}")

    def authenticate_user(self, authorization_code):
        # Authenticate user based on the authorization code
        return User(user_id=authorization_code.user.id)

    def validate_token_request(self):
        logging.info("Validating token request...")
        code = self.request.data.get('code')
        if not code:
            raise InvalidGrantError()

        client_id = self.request.client.get_client_id()
        logging.info(f"Client ID: {client_id}")
        logging.info(f"Authorization Code: {code}")

        authorization_code = self.query_authorization_code(code, self.request.client)
        if not authorization_code:
            logging.error("Invalid authorization code.")
            raise InvalidGrantError()

        if authorization_code.redirect_uri != self.request.redirect_uri:
            logging.error("Mismatched redirect URI.")
            raise InvalidGrantError()

        self.request.user = self.authenticate_user(authorization_code)
        self.delete_authorization_code(authorization_code)

    def create_token_response(self):
        logging.info("Custom create_token_response method called...")
        try:
            logging.info(
                f"Request client before validation: {self.request.client.get_client_id() if self.request.client else 'None'}")
            self.validate_token_request()
            logging.info(
                f"Request client after validation: {self.request.client.get_client_id() if self.request.client else 'None'}")

            user = self.request.user
            client = self.request.client

            if not user or not client:
                raise InvalidGrantError(description="User or client is None")

            # Create the token data
            token_data = {
                'access_token': generate_access_token(user, client),
                'token_type': 'Bearer',
                'expires_in': 3600,
                'refresh_token': generate_refresh_token(user, client),
                'scope': self.request.scope,
                'user_id': user.id,
                'client_id': client.get_client_id()
            }

            # Save the token to the database
            save_token(token_data, self.request)

            logging.info(f"Generated Token Data: {token_data}")
            return jsonify(token_data), 200
        except Exception as e:
            logging.error(f"Error creating token response: {str(e)}")
            raise InvalidGrantError(description=str(e))

class CustomAuthorizationServer(AuthorizationServer):
    def create_token_response(self, request=None, *args, **kwargs):
        logging.info("Custom create_token_response method in CustomAuthorizationServer called...")

        # Access the grant type from self._token_grants
        grant_type = request.data.get('grant_type')
        if not grant_type:
            raise InvalidGrantError(description="Missing grant type")

        # Find the grant class with the matching GRANT_TYPE
        grant_class = next((grant[0] for grant in self._token_grants if grant[0].GRANT_TYPE == grant_type), None)

        if not grant_class:
            logging.error(f"Unsupported grant type: {grant_type}")
            logging.info(f"Available grants: {[grant[0].__name__ for grant in self._token_grants]}")
            raise InvalidGrantError(description=f"Unsupported grant type: {grant_type}")

        grant = grant_class(request, None)

        try:
            return grant.create_token_response()
        except Exception as e:
            logging.error(f"Error creating token response: {str(e)}")
            raise InvalidGrantError(description=str(e))

def query_client(client_id):
    logging.info(f"Querying client with client_id: {client_id}")
    try:
        client_data = mongo.db.clients.find_one({'client_id': client_id})
        if client_data:
            logging.info(f"Client found: {client_data}")
            return Client(
                client_id=client_data['client_id'],
                client_secret=client_data['client_secret'],
                redirect_uri=client_data['redirect_uri']
            )
        else:
            logging.error(f"Client not found for client_id: {client_id}")
    except Exception as e:
        logging.error(f"Error querying client: {str(e)}")
    return None

def save_token(token, request):
    # Save the token to your database
    try:
        mongo.db.tokens.insert_one({
            'access_token': token.get('access_token'),
            'token_type': token.get('token_type', 'Bearer'),
            'expires_in': token.get('expires_in', 3600),
            'refresh_token': token.get('refresh_token'),
            'scope': token.get('scope', ''),
            'user_id': request.user.id,
            'client_id': request.client.get_client_id()
        })
        logging.info(f"Token saved successfully: {token}")
    except Exception as e:
        logging.error(f"Failed to save token: {str(e)}")

def generate_access_token(user, client):
    # Generate a random access token
    return secrets.token_urlsafe(32)

def generate_refresh_token(user, client):
    # Generate a random refresh token
    return secrets.token_urlsafe(48)

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = os.urandom(32).hex()
    return session['csrf_token']