"""
Verification routes for SecureShare
Handles file integrity verification and tamper detection
"""

import os
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from app.models import db, File, VerificationLog
from app.routes.auth import login_required
from app.config import Config
from app.crypto.hashing import compute_sha256_file, compute_sha256_bytes, verify_hash
from app.crypto.asymmetric import load_rsa_keys, decrypt_key_with_rsa
from app.crypto.symmetric import decrypt_file

verify_bp = Blueprint('verify', __name__)


@verify_bp.route('/verify', methods=['GET', 'POST'])
@login_required
def verify():
    """File integrity verification tool"""
    user_id = session['user_id']
    
    # Get user's files for dropdown
    user_files = File.query.filter_by(user_id=user_id)\
        .order_by(File.created_at.desc())\
        .all()
    
    if request.method == 'POST':
        file_id = request.form.get('file_id', type=int)
        
        if not file_id:
            flash('Please select a file to verify.', 'error')
            return render_template('verify.html', files=user_files)
        
        # Get file record
        file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
        
        if not file_record:
            flash('File not found.', 'error')
            return render_template('verify.html', files=user_files)
        
        try:
            # Verify encrypted file hash
            encrypted_file_path = os.path.join(Config.ENCRYPTED_FOLDER, file_record.stored_filename)
            
            if not os.path.exists(encrypted_file_path):
                # Log verification failure
                log = VerificationLog(
                    file_id=file_id,
                    status='FAIL',
                    details='Encrypted file not found on disk.'
                )
                db.session.add(log)
                db.session.commit()
                
                return render_template('verify_result.html',
                                     file=file_record,
                                     success=False,
                                     error='File not found',
                                     details='The encrypted file does not exist on the server.')
            
            # Compute hash of encrypted file
            encrypted_hash = compute_sha256_file(encrypted_file_path)
            encrypted_hash_match = verify_hash(encrypted_hash, file_record.encrypted_hash_sha256)
            
            if not encrypted_hash_match:
                # Encrypted file has been tampered with
                log = VerificationLog(
                    file_id=file_id,
                    status='FAIL',
                    details=f'Encrypted file hash mismatch. Expected: {file_record.encrypted_hash_sha256}, Got: {encrypted_hash}'
                )
                db.session.add(log)
                db.session.commit()
                
                return render_template('verify_result.html',
                                     file=file_record,
                                     success=False,
                                     error='Encrypted file tampered',
                                     details='The encrypted file has been modified or corrupted. Hash verification failed.')
            
            # Decrypt and verify original file hash
            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Load RSA keys
            private_key, public_key = load_rsa_keys(
                Config.RSA_PRIVATE_KEY_PATH,
                Config.RSA_PUBLIC_KEY_PATH
            )
            
            # Decrypt symmetric key
            symmetric_key = decrypt_key_with_rsa(file_record.rsa_encrypted_key, private_key)
            
            # Decrypt file
            decrypted_data = decrypt_file(
                encrypted_data,
                symmetric_key,
                file_record.iv_or_nonce,
                file_record.algorithm
            )
            
            # Compute hash of decrypted data
            decrypted_hash = compute_sha256_bytes(decrypted_data)
            original_hash_match = verify_hash(decrypted_hash, file_record.original_hash_sha256)
            
            if not original_hash_match:
                # Decrypted data doesn't match original
                log = VerificationLog(
                    file_id=file_id,
                    status='FAIL',
                    details=f'Original file hash mismatch after decryption. Expected: {file_record.original_hash_sha256}, Got: {decrypted_hash}'
                )
                db.session.add(log)
                db.session.commit()
                
                return render_template('verify_result.html',
                                     file=file_record,
                                     success=False,
                                     error='Decrypted data mismatch',
                                     details='The decrypted data does not match the original file hash. File may be corrupted.')
            
            # All checks passed
            log = VerificationLog(
                file_id=file_id,
                status='SUCCESS',
                details='All integrity checks passed. File is authentic and unmodified.'
            )
            db.session.add(log)
            db.session.commit()
            
            return render_template('verify_result.html',
                                 file=file_record,
                                 success=True,
                                 encrypted_hash=encrypted_hash,
                                 decrypted_hash=decrypted_hash,
                                 details='File integrity verified successfully. No tampering detected.')
        
        except Exception as e:
            # Log verification error
            log = VerificationLog(
                file_id=file_id,
                status='FAIL',
                details=f'Verification error: {str(e)}'
            )
            db.session.add(log)
            db.session.commit()
            
            return render_template('verify_result.html',
                                 file=file_record,
                                 success=False,
                                 error='Verification error',
                                 details=f'An error occurred during verification: {str(e)}')
    
    return render_template('verify.html', files=user_files)


@verify_bp.route('/verify-local', methods=['POST'])
@login_required
def verify_local():
    """Verify a local file against stored record"""
    user_id = session['user_id']
    
    if 'local_file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('verify.verify'))
        
    local_file = request.files['local_file']
    file_id = request.form.get('file_id', type=int)
    
    if local_file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('verify.verify'))
        
    if not file_id:
        flash('Please select a file record to compare against.', 'error')
        return redirect(url_for('verify.verify'))
        
    # Get file record
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        flash('File record not found.', 'error')
        return redirect(url_for('verify.verify'))
        
    try:
        # Read local file data
        file_data = local_file.read()
        
        # Compute hash of local file
        local_hash = compute_sha256_bytes(file_data)
        
        # Compare with stored original hash
        hash_match = verify_hash(local_hash, file_record.original_hash_sha256)
        
        # Log verification attempt
        status = 'SUCCESS' if hash_match else 'FAIL'
        details = 'Local file verification: ' + ('Match' if hash_match else 'Mismatch')
        
        log = VerificationLog(
            file_id=file_id,
            status=status,
            details=details
        )
        db.session.add(log)
        db.session.commit()
        
        return render_template('verify_result.html',
                             file=file_record,
                             success=hash_match,
                             local_verification=True,
                             local_hash=local_hash,
                             original_hash=file_record.original_hash_sha256,
                             details='Local file matches the original encrypted file.' if hash_match else 'Local file does NOT match the original encrypted file.',
                             error=None if hash_match else 'Hash Mismatch')
                             
    except Exception as e:
        flash(f'Verification failed: {str(e)}', 'error')
        return redirect(url_for('verify.verify'))


@verify_bp.route('/verification-logs')
@login_required
def verification_logs():
    """View verification history"""
    user_id = session['user_id']
    
    # Get all verification logs for user's files
    logs = db.session.query(VerificationLog, File)\
        .join(File, VerificationLog.file_id == File.id)\
        .filter(File.user_id == user_id)\
        .order_by(VerificationLog.verified_at.desc())\
        .all()
    
    return render_template('verification_logs.html', logs=logs)
