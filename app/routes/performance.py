"""
Performance analytics routes for SecureShare
Displays algorithm comparison and performance metrics
"""

from flask import Blueprint, render_template, session
from sqlalchemy import func
from app.models import File
from app.routes.auth import login_required

performance_bp = Blueprint('performance', __name__)


@performance_bp.route('/performance')
@login_required
def performance():
    """Performance dashboard showing algorithm statistics"""
    user_id = session['user_id']
    
    # Get statistics for each algorithm
    stats = db.session.query(
        File.algorithm,
        func.count(File.id).label('count'),
        func.avg(File.encryption_time_ms).label('avg_encryption_time'),
        func.avg(File.decryption_time_ms).label('avg_decryption_time'),
        func.avg(File.encrypted_size_bytes * 1.0 / File.original_size_bytes).label('avg_overhead')
    ).filter_by(user_id=user_id)\
     .group_by(File.algorithm)\
     .all()
    
    # Format statistics
    algorithm_stats = []
    for stat in stats:
        algorithm_stats.append({
            'algorithm': stat.algorithm,
            'count': stat.count,
            'avg_encryption_time': round(stat.avg_encryption_time, 2) if stat.avg_encryption_time else 0,
            'avg_decryption_time': round(stat.avg_decryption_time, 2) if stat.avg_decryption_time else 0,
            'avg_overhead': round((stat.avg_overhead - 1) * 100, 2) if stat.avg_overhead else 0
        })
    
    # Get total files count
    total_files = File.query.filter_by(user_id=user_id).count()
    
    return render_template('performance.html',
                         algorithm_stats=algorithm_stats,
                         total_files=total_files)


# Import db here to avoid circular import
from app.models import db
