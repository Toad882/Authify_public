from flask_pymongo import PyMongo
import logging
from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin
from werkzeug.security import check_password_hash

mongo = PyMongo()

def check_db_connection():
    if mongo is None:
        logging.error("MongoDB is not initialized. Connection failed.")
        return "MongoDB is not connected", 500
    try:
        mongo.db.command('ping')
        logging.info("MongoDB connection check passed.")
    except Exception as e:
        logging.error(f"Error connecting to MongoDB: {str(e)}")
        return "Error connecting to MongoDB", 500

def init_db(app):
    global mongo
    try:
        mongo = PyMongo(app)
        mongo.db.command('ping')
        logging.info("MongoDB connected successfully.")
    except Exception as e:
        logging.error(f"Error initializing MongoDB connection: {str(e)}")
        mongo = None

class Client(ClientMixin):
    def __init__(self, client_id, client_secret, redirect_uri):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_client_id(self):
        return self.client_id

    def check_client_secret(self, client_secret):
        logging.info(f"Checking client secret for client: {self.client_id}")
        return check_password_hash(self.client_secret, client_secret)

    @property
    def default_redirect_uri(self):
        return self.redirect_uri

    @property
    def allowed_scopes(self):
        return ['openid', 'profile', 'email']

    def check_grant_type(self, grant_type):
        # Check if the client supports the specified grant type
        return grant_type == 'authorization_code'

    def check_endpoint_auth_method(self, method, endpoint):
        if endpoint == 'token':
            # Check if the client supports the specified authentication method for the token endpoint
            return method in ['client_secret_basic', 'client_secret_post']
        return False

    @property
    def client_auth_methods(self):
        return ['client_secret_basic', 'client_secret_post']

class Token(TokenMixin):
    def __init__(self, access_token=None, token_type='Bearer', expires_in=3600, refresh_token=None,
                 scope='', user_id=None, client_id=None):
        self.access_token = access_token
        self.token_type = token_type
        self.expires_in = expires_in
        self.refresh_token = refresh_token
        self.scope = scope
        self.user_id = user_id
        self.client_id = client_id

    def get_client_id(self):
        return self.client_id

    def get_scope(self):
        return self.scope

class AuthorizationCode:
    def __init__(self, code, client_id, redirect_uri, scope, user, state=None):
        self.code = code
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.user = user
        self.state = state

class User:
    def __init__(self, user_id):
        self.id = user_id