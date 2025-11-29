"""
SecureShare Flask Application
Multi-Algorithm File Encryption & Verification System
"""

from flask import Flask
from app.config import Config
from app.models import db
from app.crypto.asymmetric import get_or_create_rsa_keys


def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize directories
    Config.init_app()
    
    # Initialize database
    db.init_app(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        
        # Initialize RSA keys
        get_or_create_rsa_keys(
            Config.RSA_PRIVATE_KEY_PATH,
            Config.RSA_PUBLIC_KEY_PATH
        )
    
    # Register blueprints
    from app.routes.auth import auth_bp
    from app.routes.files import files_bp
    from app.routes.share import share_bp
    from app.routes.performance import performance_bp
    from app.routes.verify import verify_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(files_bp)
    app.register_blueprint(share_bp)
    app.register_blueprint(performance_bp)
    app.register_blueprint(verify_bp)
    
    return app
