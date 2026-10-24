from flask import Blueprint, jsonify
from flask_login import login_required, current_user
from app.models.scan import Scan, Vulnerability
from app.models.user import User
from app import db
from sqlalchemy import func

api_bp = Blueprint('api', __name__)


@api_bp.route('/stats')
@login_required
def global_stats():
    """Stats globales pour le dashboard."""
    if current_user.is_admin():
        data = {
            'total_scans': Scan.query.count(),
            'total_vulns': Vulnerability.query.count(),
            'total_users': User.query.count(),
            'running_scans': Scan.query.filter_by(status='running').count(),
            'critical_vulns': Vulnerability.query.filter_by(severity='critical', status='open').count(),
        }
    else:
        data = {
            'total_scans': Scan.query.filter_by(user_id=current_user.id).count(),
            'total_vulns': db.session.query(func.count(Vulnerability.id))
                .join(Scan).filter(Scan.user_id == current_user.id).scalar() or 0,
            'total_users': 1,
            'running_scans': Scan.query.filter_by(user_id=current_user.id, status='running').count(),
            'critical_vulns': Vulnerability.query.join(Scan)
                .filter(Scan.user_id == current_user.id, Vulnerability.severity == 'critical',
                        Vulnerability.status == 'open').count(),
        }
    return jsonify(data)


@api_bp.route('/scans')
@login_required
def list_scans():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(20).all()
    return jsonify([s.to_dict() for s in scans])


@api_bp.route('/vulns/chart-data')
@login_required
def vulns_chart_data():
    """Données pour les graphiques."""
    if current_user.is_admin():
        data = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))\
            .group_by(Vulnerability.severity).all()
    else:
        data = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))\
            .join(Scan).filter(Scan.user_id == current_user.id)\
            .group_by(Vulnerability.severity).all()
    
    return jsonify({sev: count for sev, count in data})
