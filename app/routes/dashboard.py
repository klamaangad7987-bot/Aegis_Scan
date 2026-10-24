from flask import Blueprint, render_template, jsonify
from flask_login import login_required, current_user
from app.models.scan import Scan, Vulnerability
from app.models.user import User
from app import db
from sqlalchemy import func
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
dashboard_bp = Blueprint('dashboard', __name__)

@dashboard_bp.route('/')
@dashboard_bp.route('/dashboard')
@login_required
def index():
    try:
        if current_user.is_admin():
            total_scans     = Scan.query.count()
            running_scans   = Scan.query.filter_by(status='running').count() + Scan.query.filter_by(status='pending').count()
            completed_scans = Scan.query.filter_by(status='completed').count()
            failed_scans    = Scan.query.filter_by(status='failed').count()
            recent_scans    = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
            total_vulns     = Vulnerability.query.count()
        else:
            total_scans     = Scan.query.filter_by(user_id=current_user.id).count()
            running_scans   = Scan.query.filter_by(user_id=current_user.id, status='running').count() + \
                              Scan.query.filter_by(user_id=current_user.id, status='pending').count()
            completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
            failed_scans    = Scan.query.filter_by(user_id=current_user.id, status='failed').count()
            recent_scans    = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(5).all()
            total_vulns     = db.session.query(func.count(Vulnerability.id)).join(Scan).filter(Scan.user_id == current_user.id).scalar() or 0

        # Stats sévérité filtrées par utilisateur
        if current_user.is_admin():
            severity_stats = db.session.query(Vulnerability.severity, func.count(Vulnerability.id)).group_by(Vulnerability.severity).all()
        else:
            severity_stats = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))\
                .join(Scan).filter(Scan.user_id == current_user.id)\
                .group_by(Vulnerability.severity).all()

        severity_data = {s: 0 for s in ['critical','high','medium','low','info']}
        for sev, count in severity_stats:
            if sev in severity_data:
                severity_data[sev] = count

    except Exception as e:
        logger.error(f"Erreur dashboard: {e}")
        total_scans = running_scans = completed_scans = failed_scans = total_vulns = 0
        recent_scans = []
        severity_data = {s: 0 for s in ['critical','high','medium','low','info']}

    return render_template('dashboard/index.html',
        total_scans=total_scans,
        running_scans=running_scans,
        completed_scans=completed_scans,
        failed_scans=failed_scans,
        recent_scans=recent_scans,
        total_vulns=total_vulns,
        severity_data=severity_data,
    )
