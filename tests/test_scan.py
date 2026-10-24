"""Tests du module scan et IA classifier."""
import pytest
from app.models.scan import Scan, Vulnerability
from app.services.ai_classifier import AIClassifier


class TestScanModel:

    def test_scan_creation(self, sample_scan):
        assert sample_scan.name == 'Test Scan SAST'
        assert sample_scan.scan_type == 'sast'
        assert sample_scan.status == 'completed'

    def test_scan_vulnerability_count(self, sample_scan):
        assert sample_scan.total_vulnerabilities == 1
        assert sample_scan.high_count == 1
        assert sample_scan.critical_count == 0

    def test_scan_to_dict(self, sample_scan):
        d = sample_scan.to_dict()
        assert d['name'] == 'Test Scan SAST'
        assert d['scan_type'] == 'sast'
        assert d['total_vulnerabilities'] == 1

    def test_scan_duration_str(self, sample_scan):
        assert sample_scan.duration_str in ('-', '0s') or 's' in sample_scan.duration_str


class TestVulnerabilityModel:

    def test_vuln_creation(self, sample_scan):
        vuln = sample_scan.vulnerabilities.first()
        assert vuln is not None
        assert vuln.title == 'SQL Injection test'
        assert vuln.severity == 'high'

    def test_vuln_to_dict(self, sample_scan):
        vuln = sample_scan.vulnerabilities.first()
        d = vuln.to_dict()
        assert d['severity'] == 'high'
        assert d['cvss_score'] == 7.5


class TestAIClassifier:

    def test_classify_vuln(self, sample_scan):
        classifier = AIClassifier()
        vuln = sample_scan.vulnerabilities.first()
        classifier.classify(vuln)
        assert vuln.ai_confidence is not None
        assert 0 <= vuln.ai_confidence <= 1
        assert vuln.risk_score is not None
        assert vuln.ai_severity in ('critical', 'high', 'medium', 'low', 'info')

    def test_confidence_increases_with_cwe(self, sample_scan):
        classifier = AIClassifier()
        vuln = sample_scan.vulnerabilities.first()
        vuln.cwe_id = 'CWE-89'
        vuln.code_snippet = "cursor.execute(f'SELECT * FROM users WHERE id={id}')"
        classifier.classify(vuln)
        assert vuln.ai_confidence > 0.5

    def test_risk_score_bounds(self, sample_scan):
        classifier = AIClassifier()
        vuln = sample_scan.vulnerabilities.first()
        vuln.severity = 'critical'
        vuln.cvss_score = 9.8
        classifier.classify(vuln)
        assert 0 <= vuln.risk_score <= 100

    def test_recommendation_filled(self, sample_scan):
        classifier = AIClassifier()
        vuln = sample_scan.vulnerabilities.first()
        vuln.recommendation = None
        classifier.classify(vuln)
        assert vuln.recommendation is not None
        assert len(vuln.recommendation) > 0


class TestScannerDemo:

    def test_scanner_injects_demo_vulns(self, db, admin_user, app):
        with app.app_context():
            scan = Scan(
                name='Demo Test',
                scan_type='sast',
                status='pending',
                user_id=admin_user.id,
            )
            db.session.add(scan)
            db.session.commit()

            from app.services.scanner import SecurityScanner
            scanner = SecurityScanner(scan)
            scanner._inject_demo_vulns('sast')

            vulns = scan.vulnerabilities.all()
            assert len(vulns) > 0
            severities = {v.severity for v in vulns}
            assert severities & {'critical', 'high', 'medium', 'low'}
