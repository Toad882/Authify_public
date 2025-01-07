# app.py

from flask import Flask, request, render_template, flash, redirect
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from models import init_db, check_db_connection
import logging
# Import the new module

app = Flask(__name__, template_folder='site1/templates', static_folder='site1/static')
logging.basicConfig(level=logging.WARNING)
app.config.from_object(Config)

csrf = CSRFProtect(app)
csrf.init_app(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"], storage_uri=Config.MONGO_URI)

init_db(app)
from routes.user_routes import user_bp
from routes.client_routes import client_bp
from routes.oauth_server import create_oauth
from routes.auth_routes import create_auth_bp
app.register_blueprint(client_bp)
app.register_blueprint(user_bp)
app.register_blueprint(create_auth_bp())

# Initialize OAuth server using the new module
global oauth  # Declare 'oauth' as a global variable if needed elsewhere in the application
oauth = create_oauth(app)  # Use the function from the new module



@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = Config.CSP_HEADER_VALUE
    return response

@app.before_request
def before_request():
    if Config.local==False:
        if not request.is_secure:
            return redirect(request.url.replace("http://", "https://"))


@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f"Page not found: {request.url}")
    #flash('Page not found. Redirecting to login.', 'error')
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Server Error: {error}")
    return "An error occurred, please try again later.", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8443)