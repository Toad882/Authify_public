from .auth_routes import create_auth_bp
from .client_routes import client_bp
from .user_routes import user_bp

def init_routes(app):
    app.register_blueprint(auth_bp)
    app.register_blueprint(client_bp)
    app.register_blueprint(user_bp)