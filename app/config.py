import os

class Config:
    """Application configuration"""
    
    # Secret key for session management (in production, use environment variable)
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    
    # Database configuration
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(BASE_DIR, '..', 'instance', 'secureShare.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload configuration
    UPLOAD_FOLDER = os.path.join(BASE_DIR, '..', 'uploads')
    ENCRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'encrypted')
    DECRYPTED_FOLDER = os.path.join(UPLOAD_FOLDER, 'decrypted')
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB max file size
    
    # RSA key paths
    RSA_KEY_DIR = os.path.join(BASE_DIR, '..', 'instance')
    RSA_PRIVATE_KEY_PATH = os.path.join(RSA_KEY_DIR, 'rsa_private.pem')
    RSA_PUBLIC_KEY_PATH = os.path.join(RSA_KEY_DIR, 'rsa_public.pem')
    
    # Ensure directories exist
    @staticmethod
    def init_app():
        """Initialize application directories"""
        os.makedirs(Config.ENCRYPTED_FOLDER, exist_ok=True)
        os.makedirs(Config.DECRYPTED_FOLDER, exist_ok=True)
        os.makedirs(Config.RSA_KEY_DIR, exist_ok=True)
