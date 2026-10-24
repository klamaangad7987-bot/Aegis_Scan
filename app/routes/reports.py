from flask import Blueprint, render_template, send_file, jsonify, abort
from flask_login import login_required, current_user
from app.models.scan import Scan, Report
from app.services.report_generator import generate_pdf_report
from app import db

reports_bp = Blueprint('reports', __name__)


@reports_bp.route('/')
@login_required
def index():
    if current_user.is_admin():
        reports = Report.query.order_by(Report.created_at.desc()).all()
    else:
        reports = Report.query.join(Scan)\
            .filter(Scan.user_id == current_user.id)\
            .order_by(Report.created_at.desc()).all()
    return render_template('reports/index.html', reports=reports)


@reports_bp.route('/generate/<int:scan_id>', methods=['POST'])
@login_required
def generate(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.is_admin() and scan.user_id != current_user.id:
        abort(403)
    
    try:
        report = generate_pdf_report(scan)
        return jsonify({'success': True, 'report_id': report.id, 
                        'filename': report.filename})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@reports_bp.route('/download/<int:report_id>')
@login_required
def download(report_id):
    report = Report.query.get_or_404(report_id)
    scan = db.session.get(Scan, report.scan_id)
    
    if not current_user.is_admin() and scan.user_id != current_user.id:
        abort(403)
    
    import os
    if not os.path.exists(report.file_path):
        abort(404)
    
    return send_file(report.file_path, as_attachment=True,
                     download_name=report.filename, mimetype='application/pdf')
