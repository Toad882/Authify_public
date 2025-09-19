import os
import certifi
import platform
import keyring
import secrets


class Config:
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 1800

    SESSION_COOKIE_NAME = 'idp_session'
    SESSION_REFRESH_EACH_REQUEST = True

    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_urlsafe(32)

    os_name = platform.system()
    MONGO_HOSTNAME = os.environ.get('MONGO_HOSTNAME') or 'localhost'

    if os_name == "Darwin":  # macOS
        MONGO_USERNAME = os.environ.get('MONGO_USERNAME') or keyring.get_password("mongodb_username", "mongodb")
        MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD') or keyring.get_password("mongodb_password", "mongodb")
    elif os_name == "Windows":
        MONGO_USERNAME = os.environ.get('MONGO_USERNAME') or keyring.get_password("mongodb", "mongodb_username")
        MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD') or keyring.get_password("mongodb", "mongodb_password")
    else:
        MONGO_USERNAME = os.environ.get('MONGO_USERNAME')
        MONGO_PASSWORD = os.environ.get('MONGO_PASSWORD')

    # Secure MongoDB URI construction with validation
    if MONGO_USERNAME and MONGO_PASSWORD:
        MONGO_URI = f'mongodb+srv://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOSTNAME}?retryWrites=true&w=majority&tlsCAFile={certifi.where()}'
    else:
        raise ValueError(
            "MongoDB credentials not found. Please set MONGO_USERNAME and MONGO_PASSWORD environment variables.")

    # SECURITY ENHANCEMENT: Enhanced Content Security Policy
    CSP_POLICY = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline'",
        "style-src": "'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src": "'self' https://fonts.gstatic.com",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'",
        "upgrade-insecure-requests": "",
        "block-all-mixed-content": ""
    }

    SECURITY_HEADERS = {
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }

    RATELIMIT_STORAGE_URL = MONGO_URI
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_DEFAULT = "200 per day, 50 per hour"

    RATE_LIMITS = {
        'login': "5 per minute",
        'token': "10 per minute",
        'register': "3 per hour",
        'password_reset': "3 per hour"
    }

    SSL_REDIRECT = True
    SSL_REDIRECT_PERMANENT = True

    FLASK_ENV = os.environ.get('FLASK_ENV', 'production')

    LOGGING_CONFIG = {
        'version': 1,
        'formatters': {
            'default': {
                'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
            },
            'security': {
                'format': '[%(asctime)s] SECURITY - %(levelname)s: %(message)s',
            }
        },
        'handlers': {
            'wsgi': {
                'class': 'logging.StreamHandler',
                'stream': 'ext://flask.logging.wsgi_errors_stream',
                'formatter': 'default'
            },
            'security': {
                'class': 'logging.FileHandler',
                'filename': 'security.log',
                'formatter': 'security',
                'level': 'INFO'
            },
            'app': {
                'class': 'logging.FileHandler',
                'filename': 'app.log',
                'formatter': 'default',
                'level': 'WARNING'
            }
        },
        'root': {
            'level': 'WARNING',
            'handlers': ['wsgi', 'app']
        },
        'loggers': {
            'security': {
                'level': 'INFO',
                'handlers': ['security'],
                'propagate': False
            }
        }
    }

    OAUTH2_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour
    OAUTH2_REFRESH_TOKEN_EXPIRES = 86400 * 30  # 30 days
    OAUTH2_AUTHORIZATION_CODE_EXPIRES = 600  # 10 minutes

    WEBAUTHN_RP_ID = os.environ.get('HOSTNAME')
    WEBAUTHN_RP_NAME = "IDP Project"
    WEBAUTHN_ORIGIN = f"https://{WEBAUTHN_RP_ID}"

    TOTP_ISSUER_NAME = "IDP Project"
    TOTP_VALIDITY_PERIOD = 30  # seconds

    MAX_LOGIN_ATTEMPTS = 3
    LOGIN_LOCKOUT_DURATION = 300  # 5 minutes

    if FLASK_ENV == 'development':
        DEBUG = True
        TESTING = False
        SSL_REDIRECT = False
        SESSION_COOKIE_SECURE = False
    else:
        DEBUG = False
        TESTING = False
        SSL_REDIRECT = True
        SESSION_COOKIE_SECURE = True

        PERMANENT_SESSION_LIFETIME = 1800
        SECURITY_HEADERS['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'