from flask import Flask, render_template, redirect, url_for
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import Config
from models import init_db
import logging

app = Flask(__name__, template_folder='site1/templates', static_folder='site1/static')

logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

app.config.from_object(Config)

csrf = CSRFProtect(app)
csrf.init_app(app)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=Config.MONGO_URI
)

init_db(app)
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response


from routes.user_routes import user_bp
from routes.client_routes import client_bp
from routes.oauth_server import create_oauth
from routes.auth_routes import create_auth_bp
app.register_blueprint(client_bp)
app.register_blueprint(user_bp)
app.register_blueprint(create_auth_bp())

global oauth
oauth = create_oauth(app)


@app.route('/health')
def health_check():
    return {'status': 'healthy', 'timestamp': str(datetime.utcnow())}, 200


@app.route('/')
def index():
    return redirect(url_for('auth.login'))


@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    logging.error(f"Internal server error: {str(error)}")
    return render_template('404.html'), 500


@app.errorhandler(403)
def forbidden_error(error):
    return render_template('404.html'), 403


@app.errorhandler(429)
def rate_limit_error(error):
    return render_template('404.html'), 429


if __name__ == '__main__':
    import os

    debug_mode = os.environ.get('FLASK_ENV') == 'development'

    if not debug_mode:
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False,
            threaded=True
        )
    else:
        app.run(
            host='127.0.0.1',
            port=5010,
            debug=True
        )