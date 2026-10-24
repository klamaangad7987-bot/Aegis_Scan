"""
Module IA : classification et scoring intelligent des vulnérabilités.
Utilise des règles expertes + scoring CVSS pour simuler un modèle ML.
"""
import re


class AIClassifier:
    """
    Classificateur IA des vulnérabilités.
    En production : remplacer par un modèle scikit-learn entraîné sur NVD/CVE.
    """

    SEVERITY_WEIGHTS = {
        'critical': 1.0,
        'high': 0.75,
        'medium': 0.50,
        'low': 0.25,
        'info': 0.05,
    }

    CATEGORY_RISK = {
        'SQL Injection': 0.95,
        'Command Injection': 0.95,
        'Hardcoded Credentials': 0.90,
        'Insecure Deserialization': 0.88,
        'CSRF': 0.82,
        'XSS': 0.78,
        'Insecure Cookie': 0.72,
        'Weak Cryptography': 0.65,
        'Security Misconfiguration': 0.60,
        'Information Disclosure': 0.45,
        'Privilege Escalation': 0.92,
        'Known Vulnerability': 0.85,
        'Outdated Component': 0.60,
    }

    RECOMMENDATIONS = {
        'SQL Injection': (
            "Utiliser des requêtes paramétrées (ORM ou prepared statements). "
            "Ne jamais interpoler directement l'entrée utilisateur dans une requête SQL."
        ),
        'XSS': (
            "Activer l'auto-échappement Jinja2, valider et encoder toutes les sorties HTML. "
            "Mettre en place une Content-Security-Policy stricte."
        ),
        'Hardcoded Credentials': (
            "Stocker les secrets dans des variables d'environnement ou un gestionnaire de secrets "
            "(HashiCorp Vault, AWS Secrets Manager). Ne jamais committer de secrets dans Git."
        ),
        'CSRF': (
            "Utiliser Flask-WTF pour la protection CSRF automatique. "
            "Vérifier le token CSRF sur chaque requête POST/PUT/DELETE."
        ),
        'Weak Cryptography': (
            "Remplacer MD5/SHA1 par bcrypt, argon2id ou SHA-256 pour les mots de passe. "
            "Pour les données, utiliser AES-256-GCM."
        ),
        'Insecure Deserialization': (
            "Éviter pickle pour les données non fiables. "
            "Préférer JSON ou des formats de sérialisation sûrs avec validation de schéma."
        ),
        'Security Misconfiguration': (
            "Configurer tous les en-têtes de sécurité HTTP : "
            "CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy."
        ),
        'Information Disclosure': (
            "Masquer les messages d'erreur en production. "
            "Journaliser les erreurs côté serveur, ne retourner que des messages génériques."
        ),
        'Known Vulnerability': (
            "Mettre à jour immédiatement la dépendance concernée. "
            "Utiliser pip-audit ou safety pour surveiller les CVE en continu."
        ),
    }

    def classify(self, vuln) -> None:
        """Enrichit une vulnérabilité avec le scoring IA."""
        confidence = self._compute_confidence(vuln)
        risk_score = self._compute_risk_score(vuln)
        ai_severity = self._predict_severity(vuln)
        ai_category = self._predict_category(vuln)
        recommendation = self._get_recommendation(vuln)

        vuln.ai_confidence = round(confidence, 3)
        vuln.risk_score = round(risk_score, 2)
        vuln.ai_severity = ai_severity
        vuln.ai_category = ai_category
        vuln.ai_notes = self._generate_notes(vuln, confidence)

        if recommendation and not vuln.recommendation:
            vuln.recommendation = recommendation

    def _compute_confidence(self, vuln) -> float:
        score = 0.5
        if vuln.cwe_id:
            score += 0.15
        if vuln.cvss_score and vuln.cvss_score > 0:
            score += 0.10
        if vuln.code_snippet:
            score += 0.10
        if vuln.category in self.CATEGORY_RISK:
            score += 0.15
        return min(score, 0.99)

    def _compute_risk_score(self, vuln) -> float:
        base = self.SEVERITY_WEIGHTS.get(vuln.severity, 0.5)
        cat_risk = self.CATEGORY_RISK.get(vuln.category, 0.5)
        cvss_norm = (vuln.cvss_score or 0) / 10.0
        exploitability = 1.0 if vuln.status == 'open' else 0.3
        score = (base * 0.35 + cat_risk * 0.35 + cvss_norm * 0.30) * exploitability
        return min(score * 100, 100)

    def _predict_severity(self, vuln) -> str:
        risk = self._compute_risk_score(vuln)
        if risk >= 85:
            return 'critical'
        elif risk >= 65:
            return 'high'
        elif risk >= 40:
            return 'medium'
        elif risk >= 20:
            return 'low'
        return 'info'

    def _predict_category(self, vuln) -> str:
        text = f"{vuln.title} {vuln.description or ''}".lower()
        patterns = {
            'SQL Injection': r'sql|inject|query|cursor',
            'XSS': r'xss|cross.site|script|html',
            'Hardcoded Credentials': r'password|secret|credential|token|key',
            'CSRF': r'csrf|cross.site.request',
            'Weak Cryptography': r'md5|sha1|weak|crypt',
            'Insecure Deserialization': r'pickle|deserializ|marshal',
            'Information Disclosure': r'disclos|traceback|debug|error',
            'Security Misconfiguration': r'header|config|misconfig|cors',
            'Known Vulnerability': r'cve|vuln|outdated|version',
        }
        for category, pattern in patterns.items():
            if re.search(pattern, text):
                return category
        return vuln.category or 'Unknown'

    def _get_recommendation(self, vuln) -> str:
        cat = vuln.category or self._predict_category(vuln)
        return self.RECOMMENDATIONS.get(cat, '')

    def _generate_notes(self, vuln, confidence: float) -> str:
        level = "haute" if confidence > 0.85 else "moyenne" if confidence > 0.65 else "faible"
        notes = [f"Confiance de classification : {level} ({confidence:.0%})."]
        if vuln.cvss_score and vuln.cvss_score >= 7.0:
            notes.append("Score CVSS élevé — priorité de correction recommandée.")
        if vuln.cwe_id:
            notes.append(f"Référence CWE : {vuln.cwe_id} — consultez cwe.mitre.org pour les détails.")
        return " ".join(notes)
