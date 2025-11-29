"""
File management routes for SecureShare
Handles file encryption, decryption, and file listing
"""

import os
import time
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from werkzeug.utils import secure_filename
from app.models import db, File
from app.routes.auth import login_required
from app.config import Config
from app.crypto.symmetric import encrypt_file, decrypt_file
from app.crypto.asymmetric import load_rsa_keys, encrypt_key_with_rsa, decrypt_key_with_rsa
from app.crypto.hashing import compute_sha256_file, compute_sha256_bytes

files_bp = Blueprint('files', __name__)


@files_bp.route('/dashboard')
@login_required
def dashboard():
    """User dashboard"""
    user_id = session['user_id']
    
    # Get user's file statistics
    total_files = File.query.filter_by(user_id=user_id).count()
    
    # Get recent files
    recent_files = File.query.filter_by(user_id=user_id)\
        .order_by(File.created_at.desc())\
        .limit(5)\
        .all()
    
    return render_template('dashboard.html', 
                         total_files=total_files,
                         recent_files=recent_files)


@files_bp.route('/encrypt', methods=['GET', 'POST'])
@login_required
def encrypt():
    """File encryption page"""
    if request.method == 'POST':
        # Check if file was uploaded
        if 'file' not in request.files:
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        algorithm = request.form.get('algorithm')
        
        if file.filename == '':
            flash('No file selected.', 'error')
            return redirect(request.url)
        
        if not algorithm:
            flash('Please select an encryption algorithm.', 'error')
            return redirect(request.url)
        
        try:
            # Secure filename
            original_filename = secure_filename(file.filename)
            
            # Read file data
            file_data = file.read()
            original_size = len(file_data)
            
            # Compute original file hash
            original_hash = compute_sha256_bytes(file_data)
            
            # Start encryption timer
            start_time = time.time()
            
            # Encrypt file with selected algorithm
            encrypted_data, symmetric_key, iv_or_nonce = encrypt_file(file_data, algorithm)
            
            # End encryption timer
            encryption_time_ms = int((time.time() - start_time) * 1000)
            
            # Compute encrypted file hash
            encrypted_hash = compute_sha256_bytes(encrypted_data)
            encrypted_size = len(encrypted_data)
            
            # Load RSA keys
            private_key, public_key = load_rsa_keys(
                Config.RSA_PRIVATE_KEY_PATH,
                Config.RSA_PUBLIC_KEY_PATH
            )
            
            # Encrypt symmetric key with RSA public key
            rsa_encrypted_key = encrypt_key_with_rsa(symmetric_key, public_key)
            
            # Generate unique filename for encrypted file
            stored_filename = f"{session['user_id']}_{int(time.time())}_{original_filename}.enc"
            encrypted_file_path = os.path.join(Config.ENCRYPTED_FOLDER, stored_filename)
            
            # Save encrypted file
            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Save file metadata to database
            new_file = File(
                user_id=session['user_id'],
                original_filename=original_filename,
                stored_filename=stored_filename,
                algorithm=algorithm.upper(),
                original_size_bytes=original_size,
                encrypted_size_bytes=encrypted_size,
                rsa_encrypted_key=rsa_encrypted_key,
                iv_or_nonce=iv_or_nonce,
                original_hash_sha256=original_hash,
                encrypted_hash_sha256=encrypted_hash,
                encryption_time_ms=encryption_time_ms
            )
            
            db.session.add(new_file)
            db.session.commit()
            
            flash('File encrypted successfully!', 'success')
            
            # Render success page with details
            return render_template('encrypt_success.html',
                                 file=new_file,
                                 overhead_percent=round((encrypted_size / original_size - 1) * 100, 2))
        
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('encrypt.html')


@files_bp.route('/my-files')
@login_required
def my_files():
    """List user's encrypted files"""
    user_id = session['user_id']
    
    # Get all user's files
    files = File.query.filter_by(user_id=user_id)\
        .order_by(File.created_at.desc())\
        .all()
    
    return render_template('my_files.html', files=files)


@files_bp.route('/decrypt/<int:file_id>', methods=['POST'])
@login_required
def decrypt(file_id):
    """Decrypt a file"""
    user_id = session['user_id']
    
    # Get file from database
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('files.my_files'))
    
    try:
        # Load encrypted file
        encrypted_file_path = os.path.join(Config.ENCRYPTED_FOLDER, file_record.stored_filename)
        
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Load RSA keys
        private_key, public_key = load_rsa_keys(
            Config.RSA_PRIVATE_KEY_PATH,
            Config.RSA_PUBLIC_KEY_PATH
        )
        
        # Decrypt symmetric key with RSA private key
        symmetric_key = decrypt_key_with_rsa(file_record.rsa_encrypted_key, private_key)
        
        # Start decryption timer
        start_time = time.time()
        
        # Decrypt file
        decrypted_data = decrypt_file(
            encrypted_data,
            symmetric_key,
            file_record.iv_or_nonce,
            file_record.algorithm
        )
        
        # End decryption timer
        decryption_time_ms = int((time.time() - start_time) * 1000)
        
        # Verify integrity by comparing hash
        decrypted_hash = compute_sha256_bytes(decrypted_data)
        integrity_verified = (decrypted_hash == file_record.original_hash_sha256)
        
        # Save decrypted file
        decrypted_filename = f"decrypted_{file_record.original_filename}"
        decrypted_file_path = os.path.join(Config.DECRYPTED_FOLDER, decrypted_filename)
        
        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Update decryption time in database
        file_record.decryption_time_ms = decryption_time_ms
        db.session.commit()
        
        if integrity_verified:
            flash('File decrypted successfully! Integrity verified ✓', 'success')
        else:
            flash('File decrypted but integrity check failed! File may be corrupted.', 'warning')
        
        # Return decrypted file for download
        return send_file(
            decrypted_file_path,
            as_attachment=True,
            download_name=file_record.original_filename
        )
    
    except Exception as e:
        flash(f'Decryption failed: {str(e)}', 'error')
        return redirect(url_for('files.my_files'))


@files_bp.route('/download/<int:file_id>/<file_type>')
@login_required
def download(file_id, file_type):
    """Download encrypted or decrypted file"""
    user_id = session['user_id']
    
    # Get file from database
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('files.my_files'))
    
    try:
        if file_type == 'encrypted':
            file_path = os.path.join(Config.ENCRYPTED_FOLDER, file_record.stored_filename)
            download_name = f"{file_record.original_filename}.enc"
        else:
            flash('Invalid file type.', 'error')
            return redirect(url_for('files.my_files'))
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=download_name
        )
    
    except Exception as e:
        flash(f'Download failed: {str(e)}', 'error')
        return redirect(url_for('files.my_files'))
