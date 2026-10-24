import os
import json
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models.scan import Scan, Vulnerability
from app.services.scanner import SecurityScanner

scan_bp = Blueprint('scan', __name__)


def allowed_file(filename):
    allowed = current_app.config.get('ALLOWED_EXTENSIONS', {'py', 'js', 'java', 'php', 'zip'})
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed


@scan_bp.route('/')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    type_filter = request.args.get('type', '')
    
    query = Scan.query.filter_by(user_id=current_user.id) if not current_user.is_admin() \
        else Scan.query
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    if type_filter:
        query = query.filter_by(scan_type=type_filter)
    
    scans = query.order_by(Scan.created_at.desc())\
        .paginate(page=page, per_page=current_app.config.get('ITEMS_PER_PAGE', 10))
    
    return render_template('scan/index.html', scans=scans,
                           status_filter=status_filter, type_filter=type_filter)


@scan_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    if request.method == 'POST':
        scan_type = request.form.get('scan_type', 'sast')
        name = request.form.get('name', '').strip()
        target = request.form.get('target', '').strip()
        
        if not name:
            name = f'Scan {scan_type.upper()} - {datetime.utcnow().strftime("%d/%m/%Y %H:%M")}'
        
        scan = Scan(
            name=name,
            scan_type=scan_type,
            target=target,
            status='pending',
            user_id=current_user.id
        )
        
        # Gérer l'upload de fichier pour SAST
        if scan_type == 'sast' and 'file' in request.files:
            file = request.files['file']
            if file and file.filename and allowed_file(file.filename):
                try:
                    filename = secure_filename(file.filename)
                    upload_path = current_app.config['UPLOAD_FOLDER']
                    os.makedirs(upload_path, exist_ok=True)
                    filepath = os.path.join(upload_path, filename)
                    file.save(filepath)
                    scan.file_path = filepath
                    scan.target = filename
                except Exception as e:
                    current_app.logger.error(f"Erreur upload fichier: {e}")
        
        try:
            db.session.add(scan)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Erreur création scan: {e}")
            flash('Erreur lors de la création du scan.', 'error')
            return render_template('scan/new.html')
        
        # Lancer le scan immédiatement
        try:
            scanner = SecurityScanner(scan)
            scanner.run()
        except Exception as e:
            current_app.logger.error(f"Erreur scanner: {e}")
            try:
                scan.status = 'failed'
                scan.error_message = str(e)[:500]
                db.session.commit()
            except Exception:
                db.session.rollback()
            flash(f'Erreur lors du scan: {str(e)}', 'error')
            return redirect(url_for('scan.detail', scan_id=scan.id))
        
        flash(f'Scan "{name}" lancé avec succès!', 'success')
        return redirect(url_for('scan.detail', scan_id=scan.id))
    
    return render_template('scan/new.html')


@scan_bp.route('/<int:scan_id>')
@login_required
def detail(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.user_id != current_user.id:
        flash('Accès refusé.', 'error')
        return redirect(url_for('scan.index'))
    
    page = request.args.get('page', 1, type=int)
    severity_filter = request.args.get('severity', '')
    status_filter = request.args.get('vuln_status', '')
    
    vuln_query = scan.vulnerabilities
    if severity_filter:
        vuln_query = vuln_query.filter_by(severity=severity_filter)
    if status_filter:
        vuln_query = vuln_query.filter_by(status=status_filter)
    
    vulns = vuln_query.order_by(
        db.case(
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4},
            value=Vulnerability.severity
        ),
        Vulnerability.cvss_score.desc()
    ).paginate(page=page, per_page=20)
    
    # Stats pour les graphiques
    severity_counts = {
        'critical': scan.critical_count,
        'high': scan.high_count,
        'medium': scan.medium_count,
        'low': scan.low_count,
        'info': scan.info_count,
    }
    
    # Catégories des vulns
    from sqlalchemy import func
    category_stats = db.session.query(
        Vulnerability.category, func.count(Vulnerability.id)
    ).filter_by(scan_id=scan_id).group_by(Vulnerability.category).all()
    
    return render_template('scan/detail.html',
        scan=scan,
        vulns=vulns,
        severity_counts=severity_counts,
        category_stats=category_stats,
        severity_filter=severity_filter,
    )


@scan_bp.route('/<int:scan_id>/delete', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.user_id != current_user.id:
        return jsonify({'error': 'Accès refusé'}), 403
    
    # Supprimer le fichier uploadé
    if scan.file_path and os.path.exists(scan.file_path):
        os.remove(scan.file_path)
    
    db.session.delete(scan)
    db.session.commit()
    flash('Scan supprimé.', 'info')
    return redirect(url_for('scan.index'))


@scan_bp.route('/vulnerability/<int:vuln_id>/status', methods=['POST'])
@login_required
def update_vuln_status(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    new_status = request.json.get('status')
    
    if new_status in ('open', 'fixed', 'false_positive', 'acknowledged'):
        vuln.status = new_status
        db.session.commit()
        return jsonify({'success': True, 'status': new_status})
    
    return jsonify({'error': 'Statut invalide'}), 400


@scan_bp.route('/api/status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify(scan.to_dict())
