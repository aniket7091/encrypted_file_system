"""
Secure sharing routes for SecureShare
Handles generation and access of secure sharing links
"""

import os
import uuid
import time
import bcrypt
from datetime import datetime, timedelta
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file
from app.models import db, File, SharingLink, User
from app.routes.auth import login_required
from app.config import Config
from app.crypto.asymmetric import load_rsa_keys, decrypt_key_with_rsa
from app.crypto.symmetric import decrypt_file

share_bp = Blueprint('share', __name__)


@share_bp.route('/generate-share/<int:file_id>', methods=['GET', 'POST'])
@login_required
def generate_share(file_id):
    """Generate a secure sharing link for a file"""
    user_id = session['user_id']
    
    # Get file from database
    file_record = File.query.filter_by(id=file_id, user_id=user_id).first()
    
    if not file_record:
        flash('File not found.', 'error')
        return redirect(url_for('files.my_files'))
    
    if request.method == 'POST':
        expiry_hours = request.form.get('expiry_hours', type=int)
        max_downloads = request.form.get('max_downloads', type=int, default=3)
        access_code = request.form.get('access_code', '').strip()
        
        # Validation
        if not expiry_hours or expiry_hours <= 0:
            flash('Please select a valid expiry time.', 'error')
            return render_template('share_generate.html', file=file_record)
        
        if max_downloads <= 0:
            flash('Max downloads must be at least 1.', 'error')
            return render_template('share_generate.html', file=file_record)
        
        # Calculate expiry datetime
        expiry_datetime = datetime.utcnow() + timedelta(hours=expiry_hours)
        
        # Generate unique share token
        share_token = str(uuid.uuid4()) + str(uuid.uuid4()).replace('-', '')[:16]
        
        # Hash access code if provided
        access_code_hash = None
        if access_code:
            access_code_hash = bcrypt.hashpw(access_code.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Create sharing link
        sharing_link = SharingLink(
            file_id=file_id,
            share_token=share_token,
            access_code_hash=access_code_hash,
            expiry_datetime=expiry_datetime,
            max_downloads=max_downloads,
            download_count=0
        )
        
        db.session.add(sharing_link)
        db.session.commit()
        
        flash('Sharing link generated successfully!', 'success')
        
        # Show the generated link
        share_url = url_for('share.access_share', token=share_token, _external=True)
        return render_template('share_generated.html',
                             file=file_record,
                             share_url=share_url,
                             expiry_datetime=expiry_datetime,
                             max_downloads=max_downloads,
                             has_access_code=bool(access_code))
    
    return render_template('share_generate.html', file=file_record)


@share_bp.route('/share/<token>', methods=['GET', 'POST'])
def access_share(token):
    """Public endpoint to access shared files"""
    # Find sharing link
    sharing_link = SharingLink.query.filter_by(share_token=token).first()
    
    if not sharing_link:
        return render_template('share_error.html', 
                             error='Invalid sharing link.',
                             message='This link does not exist or has been removed.')
    
    # Check if expired
    if sharing_link.is_expired():
        return render_template('share_error.html',
                             error='Link expired',
                             message='This sharing link has expired and is no longer valid.')
    
    # Check if download limit reached
    if sharing_link.is_download_limit_reached():
        return render_template('share_error.html',
                             error='Download limit reached',
                             message='This file has reached its maximum number of downloads.')
    
    # Get file record
    file_record = File.query.get(sharing_link.file_id)
    
    if not file_record:
        return render_template('share_error.html',
                             error='File not found',
                             message='The shared file could not be found.')
    
    # If access code is required, show form
    if sharing_link.access_code_hash and request.method == 'GET':
        return render_template('share_public.html',
                             file=file_record,
                             sharing_link=sharing_link,
                             requires_code=True)
    
    # Verify access code if required
    if sharing_link.access_code_hash:
        access_code = request.form.get('access_code', '')
        
        if not bcrypt.checkpw(access_code.encode('utf-8'), 
                             sharing_link.access_code_hash.encode('utf-8')):
            flash('Incorrect access code.', 'error')
            return render_template('share_public.html',
                                 file=file_record,
                                 sharing_link=sharing_link,
                                 requires_code=True)
    
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
        
        # Decrypt symmetric key
        symmetric_key = decrypt_key_with_rsa(file_record.rsa_encrypted_key, private_key)
        
        # Decrypt file
        decrypted_data = decrypt_file(
            encrypted_data,
            symmetric_key,
            file_record.iv_or_nonce,
            file_record.algorithm
        )
        
        # Save decrypted file temporarily
        temp_filename = f"shared_{int(time.time())}_{file_record.original_filename}"
        temp_file_path = os.path.join(Config.DECRYPTED_FOLDER, temp_filename)
        
        with open(temp_file_path, 'wb') as f:
            f.write(decrypted_data)
        
        # Increment download count
        sharing_link.download_count += 1
        db.session.commit()
        
        # Send file
        return send_file(
            temp_file_path,
            as_attachment=True,
            download_name=file_record.original_filename
        )
    
    except Exception as e:
        return render_template('share_error.html',
                             error='Download failed',
                             message=f'An error occurred while processing your request: {str(e)}')


@share_bp.route('/my-shares')
@login_required
def my_shares():
    """List user's sharing links"""
    user_id = session['user_id']
    
    # Get all sharing links for user's files
    user_files = File.query.filter_by(user_id=user_id).all()
    file_ids = [f.id for f in user_files]
    
    sharing_links = SharingLink.query.filter(SharingLink.file_id.in_(file_ids))\
        .order_by(SharingLink.created_at.desc())\
        .all()
    
    return render_template('my_shares.html', sharing_links=sharing_links)
