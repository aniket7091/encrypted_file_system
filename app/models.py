from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    files = db.relationship('File', backref='owner', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'


class File(db.Model):
    """File model for encrypted files"""
    __tablename__ = 'files'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # File information
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename = db.Column(db.String(255), nullable=False)
    algorithm = db.Column(db.String(50), nullable=False)  # AES, 3DES, Blowfish, ChaCha20
    
    # Size metrics
    original_size_bytes = db.Column(db.Integer, nullable=False)
    encrypted_size_bytes = db.Column(db.Integer, nullable=False)
    
    # Cryptographic data (stored as bytes)
    rsa_encrypted_key = db.Column(db.LargeBinary, nullable=False)  # Symmetric key encrypted with RSA
    iv_or_nonce = db.Column(db.LargeBinary, nullable=False)  # IV or nonce for symmetric encryption
    
    # Integrity hashes
    original_hash_sha256 = db.Column(db.String(64), nullable=False)
    encrypted_hash_sha256 = db.Column(db.String(64), nullable=False)
    
    # Performance metrics
    encryption_time_ms = db.Column(db.Integer, nullable=False)
    decryption_time_ms = db.Column(db.Integer, nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sharing_links = db.relationship('SharingLink', backref='file', lazy=True, cascade='all, delete-orphan')
    verification_logs = db.relationship('VerificationLog', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<File {self.original_filename} ({self.algorithm})>'


class SharingLink(db.Model):
    """Sharing link model for secure file sharing"""
    __tablename__ = 'sharing_links'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    
    # Sharing configuration
    share_token = db.Column(db.String(255), unique=True, nullable=False)
    access_code_hash = db.Column(db.String(255), nullable=True)  # Optional access code (bcrypt hashed)
    
    # Limits
    expiry_datetime = db.Column(db.DateTime, nullable=False)
    max_downloads = db.Column(db.Integer, default=3)
    download_count = db.Column(db.Integer, default=0)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<SharingLink {self.share_token}>'
    
    def is_expired(self):
        """Check if the sharing link has expired"""
        return datetime.utcnow() > self.expiry_datetime
    
    def is_download_limit_reached(self):
        """Check if download limit has been reached"""
        return self.download_count >= self.max_downloads


class VerificationLog(db.Model):
    """Verification log model for tracking file integrity checks"""
    __tablename__ = 'verification_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey('files.id'), nullable=False)
    
    verified_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False)  # SUCCESS or FAIL
    details = db.Column(db.Text, nullable=True)
    
    def __repr__(self):
        return f'<VerificationLog {self.status} at {self.verified_at}>'
