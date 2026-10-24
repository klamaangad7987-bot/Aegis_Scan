from datetime import datetime
import json
from app import db


class Scan(db.Model):
    """Modèle représentant un scan de sécurité."""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Informations du scan
    name = db.Column(db.String(200), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # sast, dast, docker, dependency
    target = db.Column(db.String(500))  # URL, chemin fichier, image Docker
    
    # Statut: pending, running, completed, failed
    status = db.Column(db.String(20), default='pending', nullable=False, index=True)
    progress = db.Column(db.Integer, default=0)  # 0-100%
    
    # Résultats
    total_vulnerabilities = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    info_count = db.Column(db.Integer, default=0)
    
    # Score de risque global (0-100)
    risk_score = db.Column(db.Float, default=0.0)
    
    # Métadonnées
    file_path = db.Column(db.String(500))  # fichier uploadé
    scan_config = db.Column(db.Text)  # JSON config
    error_message = db.Column(db.Text)
    raw_output = db.Column(db.Text)  # Output brut de l'outil
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    
    # Relations
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy='dynamic',
                                       cascade='all, delete-orphan')
    report = db.relationship('Report', backref='scan', uselist=False, cascade='all, delete-orphan')
    
    @property
    def duration(self):
        """Durée du scan en secondes."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        return None
    
    @property
    def duration_str(self):
        """Durée formatée."""
        d = self.duration
        if d is None:
            return '-'
        if d < 60:
            return f"{d}s"
        return f"{d // 60}m {d % 60}s"
    
    def get_config(self):
        if self.scan_config:
            return json.loads(self.scan_config)
        return {}
    
    def set_config(self, config_dict):
        self.scan_config = json.dumps(config_dict)
    
    def update_counts(self):
        """Recalculer les compteurs depuis les vulnérabilités."""
        vulns = self.vulnerabilities.all()
        self.total_vulnerabilities = len(vulns)
        self.critical_count = sum(1 for v in vulns if v.severity == 'critical')
        self.high_count = sum(1 for v in vulns if v.severity == 'high')
        self.medium_count = sum(1 for v in vulns if v.severity == 'medium')
        self.low_count = sum(1 for v in vulns if v.severity == 'low')
        self.info_count = sum(1 for v in vulns if v.severity == 'info')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'scan_type': self.scan_type,
            'target': self.target,
            'status': self.status,
            'progress': self.progress,
            'total_vulnerabilities': self.total_vulnerabilities,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'medium_count': self.medium_count,
            'low_count': self.low_count,
            'risk_score': self.risk_score,
            'duration': self.duration_str,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
        }
    
    def __repr__(self):
        return f'<Scan {self.name} [{self.status}]>'


class Vulnerability(db.Model):
    """Modèle représentant une vulnérabilité trouvée."""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    
    # Classification
    title = db.Column(db.String(300), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), nullable=False, index=True)  # critical, high, medium, low, info
    category = db.Column(db.String(100))  # XSS, SQL Injection, etc.
    cwe_id = db.Column(db.String(20))     # CWE-79, CWE-89, etc.
    cve_id = db.Column(db.String(20))     # CVE-2024-xxxx
    
    # Localisation
    file_path = db.Column(db.String(500))
    line_number = db.Column(db.Integer)
    code_snippet = db.Column(db.Text)
    
    # Scoring
    cvss_score = db.Column(db.Float, default=0.0)
    ai_confidence = db.Column(db.Float, default=0.0)  # Score IA de confiance (0-1)
    risk_score = db.Column(db.Float, default=0.0)     # Score de risque calculé par IA
    
    # Remédiation
    recommendation = db.Column(db.Text)
    references = db.Column(db.Text)  # JSON list of URLs
    
    # Statut: open, fixed, false_positive, acknowledged
    status = db.Column(db.String(30), default='open', index=True)
    
    # Source de détection
    tool = db.Column(db.String(50))  # bandit, zap, trivy, safety
    
    # IA classification
    ai_category = db.Column(db.String(100))
    ai_severity = db.Column(db.String(20))
    ai_notes = db.Column(db.Text)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    SEVERITY_COLORS = {
        'critical': '#ef4444',
        'high': '#f97316',
        'medium': '#eab308',
        'low': '#22c55e',
        'info': '#3b82f6'
    }
    SEVERITY_BADGES = {
        'critical': 'badge-critical',
        'high': 'badge-high',
        'medium': 'badge-medium',
        'low': 'badge-low',
        'info': 'badge-info'
    }
    
    def get_references(self):
        if self.references:
            try:
                return json.loads(self.references)
            except:
                return []
        return []
    
    def set_references(self, refs_list):
        self.references = json.dumps(refs_list)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'category': self.category,
            'cwe_id': self.cwe_id,
            'cve_id': self.cve_id,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'cvss_score': self.cvss_score,
            'ai_confidence': self.ai_confidence,
            'risk_score': self.risk_score,
            'recommendation': self.recommendation,
            'status': self.status,
            'tool': self.tool,
        }
    
    def __repr__(self):
        return f'<Vulnerability {self.title} [{self.severity}]>'


class Report(db.Model):
    """Modèle pour les rapports générés."""
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    report_type = db.Column(db.String(50), default='pdf')  # pdf, json, html
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relations
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    
    def __repr__(self):
        return f'<Report {self.filename}>'
