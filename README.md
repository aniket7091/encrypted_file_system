# SecureShare: Multi-Algorithm File Encryption & Verification Website

A production-ready web application for secure file encryption, sharing, and integrity verification using multiple cryptographic algorithms.

## 🔐 Overview

SecureShare is a comprehensive cryptography and network security project that implements:

- **Multi-Algorithm Encryption**: AES-256-GCM, 3DES-CBC, Blowfish-CBC, and ChaCha20
- **Hybrid Encryption**: Symmetric encryption for files + RSA-2048 for key protection
- **Integrity Verification**: SHA-256 hashing with tamper detection
- **Secure Sharing**: Token-based links with expiry, download limits, and access codes
- **Performance Analytics**: Algorithm comparison and metrics dashboard

## 🎯 Features

### Authentication & Security
- User registration with bcrypt password hashing
- Session-based authentication
- Secure password storage (no plaintext passwords)

### File Encryption
- Upload files up to 100MB
- Choose from 4 encryption algorithms:
  - **AES-256-GCM**: Industry standard, authenticated encryption
  - **3DES-CBC**: Legacy compatibility, triple DES
  - **Blowfish-CBC**: Fast symmetric cipher
  - **ChaCha20**: Modern stream cipher
- Automatic random key generation (no hardcoded keys)
- RSA-2048 key wrapping for secure key storage
- SHA-256 hash computation for integrity

### File Decryption
- Automatic RSA key unwrapping
- Integrity verification during decryption
- Download decrypted files
- Performance timing

### Secure Sharing
- Generate unique, unguessable share tokens
- Set expiry time (1 hour to 30 days)
- Download limit enforcement
- Optional access code protection
- Automatic decryption for recipients

### Verification Tool
- File integrity checking
- Tamper detection
- Hash comparison (encrypted and original)
- Verification logging
- Clear success/failure reporting

### Performance Dashboard
- Algorithm comparison statistics
- Average encryption/decryption times
- Size overhead analysis
- Interactive charts (Chart.js)
- Algorithm recommendations

## 🛠️ Technology Stack

- **Backend**: Flask 3.0.0 (Python)
- **Database**: SQLite with SQLAlchemy ORM
- **Cryptography**: PyCryptodome 3.19.0
- **Password Hashing**: bcrypt 4.1.1
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Charts**: Chart.js 4.4.0

## 📋 Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## 🚀 Installation

### 1. Clone or Download the Project

```bash
cd "CNS project"
```

### 2. Create Virtual Environment

**On macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

**On Windows:**
```bash
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python run.py
```

The application will:
- Create the SQLite database automatically
- Generate RSA key pair (2048-bit) on first run
- Start the development server on `http://localhost:5000`

### 5. Access the Application

Open your web browser and navigate to:
```
http://localhost:5000
```

## 📁 Project Structure

```
CNS project/
├── app/
│   ├── __init__.py              # Flask app factory
│   ├── config.py                # Configuration settings
│   ├── models.py                # Database models
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── symmetric.py         # AES, 3DES, Blowfish, ChaCha20
│   │   ├── asymmetric.py        # RSA key management
│   │   └── hashing.py           # SHA-256 utilities
│   ├── routes/
│   │   ├── auth.py              # Authentication routes
│   │   ├── files.py             # File encryption/decryption
│   │   ├── share.py             # Secure sharing
│   │   ├── performance.py       # Performance analytics
│   │   └── verify.py            # Verification tool
│   ├── templates/               # HTML templates
│   │   ├── base.html
│   │   ├── auth_login.html
│   │   ├── auth_register.html
│   │   ├── dashboard.html
│   │   ├── encrypt.html
│   │   ├── encrypt_success.html
│   │   ├── my_files.html
│   │   ├── share_*.html
│   │   ├── performance.html
│   │   ├── verify.html
│   │   └── verify_result.html
│   └── static/
│       └── css/
│           └── styles.css       # Modern CSS styling
├── uploads/
│   ├── encrypted/               # Encrypted files storage
│   └── decrypted/               # Decrypted files (temporary)
├── instance/
│   ├── secureShare.db          # SQLite database
│   ├── rsa_private.pem         # RSA private key
│   └── rsa_public.pem          # RSA public key
├── requirements.txt             # Python dependencies
├── run.py                       # Application entry point
└── README.md                    # This file
```

## 🔒 Cryptographic Implementation

### Hybrid Encryption Architecture

SecureShare uses a **hybrid encryption** approach combining symmetric and asymmetric cryptography:

1. **File Encryption** (Symmetric):
   - Random symmetric key generated for each file
   - File encrypted with chosen algorithm (AES/3DES/Blowfish/ChaCha20)
   - Fast encryption of large files

2. **Key Protection** (Asymmetric):
   - Symmetric key encrypted with RSA-2048 public key
   - Encrypted key stored in database
   - Only server's RSA private key can decrypt

3. **Integrity Verification**:
   - SHA-256 hash of original file
   - SHA-256 hash of encrypted file
   - Both hashes stored for verification

### Algorithm Details

#### AES-256-GCM
- **Mode**: Galois/Counter Mode (authenticated encryption)
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 16 bytes
- **Features**: Authentication tag, best performance

#### 3DES-CBC
- **Mode**: Cipher Block Chaining
- **Key Size**: 192 bits (24 bytes)
- **IV**: 8 bytes
- **Features**: Legacy compatibility, PKCS7 padding

#### Blowfish-CBC
- **Mode**: Cipher Block Chaining
- **Key Size**: 128 bits (16 bytes)
- **IV**: 8 bytes
- **Features**: Fast encryption, PKCS7 padding

#### ChaCha20
- **Type**: Stream cipher
- **Key Size**: 256 bits (32 bytes)
- **Nonce**: 12 bytes
- **Features**: Constant-time operations, no padding

#### RSA-2048
- **Key Size**: 2048 bits
- **Padding**: OAEP (Optimal Asymmetric Encryption Padding)
- **Purpose**: Symmetric key encryption/decryption

## 📊 Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `email`: Unique email
- `password_hash`: bcrypt hashed password
- `created_at`: Registration timestamp

### Files Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `original_filename`: Original file name
- `stored_filename`: Server-side filename
- `algorithm`: Encryption algorithm used
- `original_size_bytes`: Original file size
- `encrypted_size_bytes`: Encrypted file size
- `rsa_encrypted_key`: RSA-encrypted symmetric key
- `iv_or_nonce`: Initialization vector or nonce
- `original_hash_sha256`: Original file hash
- `encrypted_hash_sha256`: Encrypted file hash
- `encryption_time_ms`: Encryption duration
- `decryption_time_ms`: Decryption duration
- `created_at`: Creation timestamp

### Sharing Links Table
- `id`: Primary key
- `file_id`: Foreign key to files
- `share_token`: Unique share token
- `access_code_hash`: Optional access code (bcrypt)
- `expiry_datetime`: Link expiration time
- `max_downloads`: Maximum download limit
- `download_count`: Current download count
- `created_at`: Creation timestamp

### Verification Logs Table
- `id`: Primary key
- `file_id`: Foreign key to files
- `verified_at`: Verification timestamp
- `status`: SUCCESS or FAIL
- `details`: Verification details

## 🎨 User Interface

The application features a modern, clean UI with:

- **Responsive Design**: Works on desktop, tablet, and mobile
- **Color-Coded Algorithms**: Easy visual identification
- **Card-Based Layout**: Clean, organized information display
- **Interactive Charts**: Visual performance comparisons
- **Flash Messages**: Clear success/error feedback
- **Action Buttons**: Intuitive user interactions

## 🔧 Configuration

### Environment Variables (Optional)

You can set these environment variables for production:

```bash
export SECRET_KEY="your-secret-key-here"
export DATABASE_URL="sqlite:///path/to/database.db"
```

### File Upload Limits

Maximum file size: **100MB** (configurable in `app/config.py`)

### RSA Key Generation

RSA keys are automatically generated on first run and stored in:
- `instance/rsa_private.pem`
- `instance/rsa_public.pem`

**⚠️ Important**: Keep the private key secure! Never share it or commit it to version control.

## 🧪 Usage Examples

### 1. Register and Login
1. Navigate to `http://localhost:5000`
2. Click "Register here"
3. Create account with username, email, password
4. Login with credentials

### 2. Encrypt a File
1. Go to "Encrypt File"
2. Select a file from your computer
3. Choose encryption algorithm (e.g., AES-256)
4. Click "Encrypt Now"
5. View encryption statistics

### 3. Generate Sharing Link
1. From "My Files", click "Share" on any file
2. Set expiry time (e.g., 24 hours)
3. Set max downloads (e.g., 3)
4. Optionally add access code
5. Copy and share the generated link

### 4. Verify File Integrity
1. Go to "Verify"
2. Select a file from dropdown
3. Click "Verify File Integrity"
4. View verification result (✅ success or ❌ failure)

### 5. Compare Algorithm Performance
1. Go to "Performance"
2. View comparison charts and statistics
3. Review algorithm recommendations

## 🔍 Security Features

✅ **Password Security**: bcrypt hashing with salt  
✅ **Session Management**: Secure session-based auth  
✅ **Random Key Generation**: Cryptographically secure random  
✅ **Key Protection**: RSA encryption for symmetric keys  
✅ **Integrity Verification**: SHA-256 hash validation  
✅ **Tamper Detection**: Multi-level hash checking  
✅ **Secure Sharing**: Token-based with expiry  
✅ **No Key Exposure**: Keys never logged or displayed  

## 🚨 Important Notes

### For Academic/Development Use

This project is designed for educational purposes and demonstrates cryptographic concepts. For production deployment:

1. Use HTTPS/TLS for all communications
2. Store RSA private key in secure key management system
3. Use environment variables for sensitive configuration
4. Implement rate limiting
5. Add CSRF protection
6. Use production-grade database (PostgreSQL/MySQL)
7. Implement proper logging and monitoring
8. Add file type validation
9. Implement virus scanning for uploads
10. Use proper session management with secure cookies

### Database Migration

To switch from SQLite to PostgreSQL/MySQL:

1. Update `SQLALCHEMY_DATABASE_URI` in `config.py`
2. Install appropriate database driver (`psycopg2` or `mysqlclient`)
3. No code changes required (SQLAlchemy handles the rest)

## 📝 API Endpoints

### Authentication
- `GET/POST /register` - User registration
- `GET/POST /login` - User login
- `GET /logout` - User logout

### File Management
- `GET /dashboard` - User dashboard
- `GET/POST /encrypt` - File encryption
- `GET /my-files` - List encrypted files
- `POST /decrypt/<id>` - Decrypt file
- `GET /download/<id>/<type>` - Download file

### Sharing
- `GET/POST /generate-share/<id>` - Generate share link
- `GET/POST /share/<token>` - Access shared file
- `GET /my-shares` - List sharing links

### Analytics
- `GET /performance` - Performance dashboard

### Verification
- `GET/POST /verify` - Verify file integrity
- `GET /verification-logs` - View verification history

## 🛠️ Troubleshooting

### Issue: "Module not found"
**Solution**: Ensure virtual environment is activated and dependencies are installed:
```bash
source venv/bin/activate  # or .\venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Issue: "Database locked"
**Solution**: Close any other instances of the application. SQLite doesn't support high concurrency.

### Issue: "RSA key files not found"
**Solution**: Delete the `instance` folder and restart. Keys will regenerate automatically.

### Issue: "Permission denied on uploads folder"
**Solution**: Ensure write permissions:
```bash
chmod -R 755 uploads/
```

## 📚 Dependencies

- **Flask**: Web framework
- **Flask-SQLAlchemy**: ORM for database operations
- **PyCryptodome**: Cryptographic algorithms
- **bcrypt**: Password hashing
- **Werkzeug**: WSGI utilities and security helpers
- **Chart.js**: Performance visualization (CDN)

## 👨‍💻 Development

### Adding New Algorithms

1. Implement encryption/decryption in `app/crypto/symmetric.py`
2. Update `encrypt_file()` and `decrypt_file()` functions
3. Add algorithm option in `templates/encrypt.html`
4. Add badge color in `static/css/styles.css`

### Database Migrations

For schema changes, recommended to use Flask-Migrate:
```bash
pip install Flask-Migrate
```

## 📄 License

This project is created for academic purposes as part of a Cryptography & Network Security course.

## 🙏 Acknowledgments

- **PyCryptodome**: For comprehensive cryptographic primitives
- **Flask**: For the excellent web framework
- **Chart.js**: For beautiful data visualization

## 📧 Support

For issues or questions about this project, please review the code comments and documentation.

---

**Built with ❤️ for Cryptography & Network Security**

*Remember: This is an educational project. Always consult security professionals for production cryptographic systems.*
