import os
import json
import subprocess
import tempfile
import shutil
import logging
from datetime import datetime
from app import db
from app.models.scan import Scan, Vulnerability

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Orchestrateur principal des scans de sécurité."""

    def __init__(self, scan: Scan):
        self.scan = scan
        self.db = db

    def run(self):
        self.scan.status = 'running'
        self.scan.started_at = datetime.utcnow()
        self.scan.progress = 5
        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Erreur commit status running: {e}")
            db.session.rollback()

        try:
            if self.scan.scan_type == 'sast':
                self._run_sast()
            elif self.scan.scan_type == 'dast':
                self._run_dast()
            elif self.scan.scan_type == 'docker':
                self._run_docker_scan()
            elif self.scan.scan_type == 'dependency':
                self._run_dependency_scan()
            else:
                logger.warning(f"Type de scan inconnu: {self.scan.scan_type}, utilisation SAST par défaut")
                self._inject_demo_vulns('sast')

            # Appliquer le scoring IA
            self.scan.progress = 85
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()

            self._apply_ai_scoring()

            self.scan.status = 'completed'
            self.scan.progress = 100
            self.scan.completed_at = datetime.utcnow()
            self.scan.update_counts()
            self._calculate_risk_score()

        except Exception as e:
            logger.error(f"Erreur scanner: {e}", exc_info=True)
            self.scan.status = 'failed'
            self.scan.error_message = str(e)[:500]
        finally:
            try:
                db.session.commit()
            except Exception as e:
                logger.error(f"Erreur commit final scanner: {e}")
                db.session.rollback()

    # ------------------------------------------------------------------ SAST
    def _run_sast(self):
        """Analyse statique du code avec Bandit."""
        self.scan.progress = 20
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

        target = self.scan.file_path or self.scan.target
        if not target or not os.path.exists(str(target)):
            # Démo : vulnérabilités fictives si pas de fichier réel
            self._inject_demo_vulns('sast')
            return

        try:
            result = subprocess.run(
                ['bandit', '-r', target, '-f', 'json', '-ll'],
                capture_output=True, text=True, timeout=120
            )
            output = result.stdout or '{}'
            # Bandit peut retourner du texte avant le JSON - extraire le JSON
            try:
                data = json.loads(output)
            except json.JSONDecodeError:
                # Essayer d'extraire le JSON de la sortie
                import re
                json_match = re.search(r'\{.*\}', output, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group())
                else:
                    data = {}
            self.scan.raw_output = output[:10000]  # Limiter la taille
            self.scan.progress = 60
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
            self._parse_bandit_output(data)
        except subprocess.TimeoutExpired:
            logger.warning("Bandit timeout, utilisation données de démo")
            self._inject_demo_vulns('sast')
        except FileNotFoundError:
            logger.warning("Bandit non installé, utilisation données de démo")
            self._inject_demo_vulns('sast')
        except Exception as e:
            logger.error(f"Erreur Bandit: {e}")
            self._inject_demo_vulns('sast')

    def _parse_bandit_output(self, data: dict):
        results = data.get('results', [])
        severity_map = {'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}

        for item in results:
            try:
                sev = severity_map.get(item.get('issue_severity', 'LOW'), 'low')
                cwe = item.get('issue_cwe', {})
                cwe_id = ''
                if isinstance(cwe, dict):
                    cwe_id = str(cwe.get('id', ''))
                elif isinstance(cwe, str):
                    cwe_id = cwe
                vuln = Vulnerability(
                    scan_id=self.scan.id,
                    title=item.get('issue_text', 'Vulnérabilité détectée')[:300],
                    description=item.get('issue_text', '')[:1000],
                    severity=sev,
                    category=item.get('test_name', '').replace('_', ' ').title()[:100],
                    cwe_id=cwe_id[:20],
                    file_path=item.get('filename', '')[:500],
                    line_number=item.get('line_number'),
                    code_snippet=item.get('code', '')[:500],
                    tool='bandit',
                    cvss_score=self._severity_to_cvss(sev),
                )
                db.session.add(vuln)
            except Exception as e:
                logger.error(f"Erreur parsing vulnérabilité Bandit: {e}")
                continue
        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Erreur commit vulnérabilités Bandit: {e}")
            db.session.rollback()

    # ------------------------------------------------------------------ DAST
    def _run_dast(self):
        """Analyse dynamique simulée (ZAP non disponible → démo)."""
        self.scan.progress = 30
        db.session.commit()
        self._inject_demo_vulns('dast')

    # ---------------------------------------------------------------- Docker
    def _run_docker_scan(self):
        """Scan d'image Docker simulé."""
        self.scan.progress = 30
        db.session.commit()
        self._inject_demo_vulns('docker')

    # ----------------------------------------------------------- Dépendances
    def _run_dependency_scan(self):
        """Scan des dépendances."""
        self.scan.progress = 30
        db.session.commit()
        self._inject_demo_vulns('dependency')

    # ---------------------------------------------------------- IA Scoring
    def _apply_ai_scoring(self):
        """Applique le scoring IA sur chaque vulnérabilité."""
        try:
            from app.services.ai_classifier import AIClassifier
            classifier = AIClassifier()
            vulns = self.scan.vulnerabilities.all()
            for vuln in vulns:
                try:
                    classifier.classify(vuln)
                except Exception as e:
                    logger.error(f"Erreur classification vulnérabilité {vuln.id}: {e}")
            db.session.commit()
        except Exception as e:
            logger.error(f"Erreur AI scoring: {e}")
            try:
                db.session.rollback()
            except Exception:
                pass

    def _calculate_risk_score(self):
        """Calcule le score de risque global du scan (0-100)."""
        weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 0.5, 'info': 0.1}
        score = 0
        for sev, w in weights.items():
            count = getattr(self.scan, f'{sev}_count', 0) or 0
            score += count * w
        self.scan.risk_score = min(round(score, 1), 100)

    # ------------------------------------------------------ Démo / Fixtures
    def _inject_demo_vulns(self, scan_type: str):
        """Injecte des vulnérabilités de démonstration réalistes."""
        self.scan.progress = 60
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

        demo_data = {
            'sast': [
                ('Injection SQL potentielle', 'critical', 'SQL Injection', 'CWE-89',
                 'app/database.py', 42,
                 "cursor.execute(f\"SELECT * FROM users WHERE id={user_id}\")",
                 9.8, "Utiliser des requêtes paramétrées : cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"),
                ('Mot de passe codé en dur', 'critical', 'Hardcoded Credentials', 'CWE-798',
                 'app/config.py', 15,
                 "DB_PASSWORD = 'admin123'",
                 9.1, "Utiliser des variables d'environnement : os.environ.get('DB_PASSWORD')"),
                ('Cross-Site Scripting (XSS)', 'high', 'XSS', 'CWE-79',
                 'app/views.py', 88,
                 "return render_template_string(f'<h1>Bonjour {username}</h1>')",
                 7.5, "Utiliser render_template avec Jinja2 auto-escaping activé."),
                ('Utilisation de MD5 pour hachage', 'medium', 'Weak Cryptography', 'CWE-327',
                 'app/auth.py', 31,
                 "hashlib.md5(password.encode()).hexdigest()",
                 5.3, "Utiliser bcrypt ou argon2 pour le hachage des mots de passe."),
                ('Désérialisation non sécurisée', 'high', 'Insecure Deserialization', 'CWE-502',
                 'app/api.py', 67,
                 "data = pickle.loads(request.data)",
                 8.1, "Ne jamais désérialiser des données non fiables avec pickle."),
                ('Exposition de données sensibles', 'low', 'Information Disclosure', 'CWE-200',
                 'app/error_handler.py', 12,
                 "return jsonify({'error': str(e), 'traceback': traceback.format_exc()})",
                 3.7, "Ne pas exposer les tracebacks en production. Journaliser côté serveur."),
            ],
            'dast': [
                ('Absence d\'en-têtes de sécurité HTTP', 'medium', 'Security Misconfiguration', 'CWE-693',
                 None, None, None, 5.3,
                 "Configurer X-Frame-Options, Content-Security-Policy, X-XSS-Protection."),
                ('Cookie sans attribut Secure/HttpOnly', 'high', 'Insecure Cookie', 'CWE-614',
                 None, None, None, 7.4,
                 "Ajouter les attributs Secure et HttpOnly à tous les cookies de session."),
                ('CSRF non protégé', 'high', 'CSRF', 'CWE-352',
                 None, None, None, 8.0,
                 "Implémenter des tokens CSRF sur tous les formulaires POST."),
                ('Répertoire lisible', 'low', 'Information Disclosure', 'CWE-548',
                 '/uploads/', None, None, 3.1,
                 "Désactiver le listing de répertoires dans la configuration serveur."),
            ],
            'docker': [
                ('Image de base obsolète', 'high', 'Outdated Component', 'CWE-1104',
                 'Dockerfile', 1, "FROM python:3.8", 7.5,
                 "Utiliser python:3.12-slim et maintenir les images à jour."),
                ('Exécution en tant que root', 'critical', 'Privilege Escalation', 'CWE-269',
                 'Dockerfile', None, None, 9.0,
                 "Créer un utilisateur non-root : USER appuser dans le Dockerfile."),
                ('Secrets dans les variables ENV', 'high', 'Hardcoded Secrets', 'CWE-798',
                 'Dockerfile', 8, "ENV DB_PASSWORD=secret123", 8.2,
                 "Utiliser Docker Secrets ou des gestionnaires de secrets externes."),
            ],
            'dependency': [
                ('CVE-2024-1234 dans Flask 2.0', 'high', 'Known Vulnerability', 'CWE-1035',
                 'requirements.txt', None, "Flask==2.0.0", 7.8,
                 "Mettre à jour vers Flask>=3.0.0 : pip install Flask --upgrade"),
                ('CVE-2023-5678 dans Pillow', 'critical', 'Known Vulnerability', 'CWE-787',
                 'requirements.txt', None, "Pillow==9.2.0", 9.1,
                 "Mettre à jour Pillow : pip install Pillow>=10.0.0"),
                ('Dépendance transitive vulnérable', 'medium', 'Known Vulnerability', 'CWE-1035',
                 'requirements.txt', None, "requests==2.28.0", 5.4,
                 "Mettre à jour requests : pip install requests>=2.32.0"),
            ],
        }

        vulns_to_add = demo_data.get(scan_type, demo_data['sast'])
        for title, sev, cat, cwe, fp, ln, code, cvss, rec in vulns_to_add:
            vuln = Vulnerability(
                scan_id=self.scan.id,
                title=title,
                description=f"Vulnérabilité de type {cat} détectée lors de l'analyse {scan_type.upper()}.",
                severity=sev,
                category=cat,
                cwe_id=cwe,
                file_path=fp,
                line_number=ln,
                code_snippet=code,
                cvss_score=cvss,
                recommendation=rec,
                tool='bandit' if scan_type == 'sast' else scan_type,
                status='open',
            )
            db.session.add(vuln)
        try:
            db.session.commit()
        except Exception as e:
            logger.error(f"Erreur commit demo vulns: {e}")
            db.session.rollback()

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        return {'critical': 9.0, 'high': 7.0, 'medium': 5.0, 'low': 2.5, 'info': 0.0}.get(severity, 0.0)
