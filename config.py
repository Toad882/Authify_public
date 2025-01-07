import os
import certifi
import platform
import keyring

class Config:
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SECRET_KEY = os.environ.get('SECRET_KEY', 'a')
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes

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

    MONGO_URI = f'mongodb+srv://{MONGO_USERNAME}:{MONGO_PASSWORD}@{MONGO_HOSTNAME}' + certifi.where()
    local=os.environ.get('LOCAL') or False

    # Define your CSP policy
    CSP_POLICY = {
        "default-src": "'self'",
        "script-src": "'self' 'unsafe-inline' https://example.com",
        "style-src": "'self' 'unsafe-inline' https://example.com",
        "img-src": "'self' data:",
        "connect-src": "'self'",
        "font-src": "'self'",
        "object-src": "'none'",
        "frame-ancestors": "'none'",
        "base-uri": "'self'",
        "form-action": "'self'"
    }

    # Convert the CSP policy dictionary to a string
    CSP_HEADER_VALUE = "; ".join(f"{key} {value}" for key, value in CSP_POLICY.items())
