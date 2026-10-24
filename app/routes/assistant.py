from flask import Blueprint, render_template, request, jsonify
from flask_login import login_required, current_user
from app.models.scan import Scan, Vulnerability
from app import db
from sqlalchemy import func
import logging

logger = logging.getLogger(__name__)

assistant_bp = Blueprint('assistant', __name__)


@assistant_bp.route('/assistant-vocal')
@login_required
def voice_assistant():
    """Page de l'assistant vocal."""
    try:
        if current_user.is_admin():
            total_scans = Scan.query.count()
            total_vulns = Vulnerability.query.count()
            critical = Vulnerability.query.filter_by(severity='critical', status='open').count()
            high = Vulnerability.query.filter_by(severity='high', status='open').count()
            recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(3).all()
        else:
            total_scans = Scan.query.filter_by(user_id=current_user.id).count()
            total_vulns = db.session.query(func.count(Vulnerability.id))\
                .join(Scan).filter(Scan.user_id == current_user.id).scalar() or 0
            critical = db.session.query(func.count(Vulnerability.id))\
                .join(Scan).filter(Scan.user_id == current_user.id,
                                   Vulnerability.severity == 'critical',
                                   Vulnerability.status == 'open').scalar() or 0
            high = db.session.query(func.count(Vulnerability.id))\
                .join(Scan).filter(Scan.user_id == current_user.id,
                                   Vulnerability.severity == 'high',
                                   Vulnerability.status == 'open').scalar() or 0
            recent_scans = Scan.query.filter_by(user_id=current_user.id)\
                .order_by(Scan.created_at.desc()).limit(3).all()
    except Exception as e:
        logger.error(f"Erreur chargement assistant vocal: {e}")
        total_scans = total_vulns = critical = high = 0
        recent_scans = []

    context = {
        'total_scans': total_scans,
        'total_vulns': total_vulns,
        'critical': critical,
        'high': high,
        'recent_scans': [s.to_dict() for s in recent_scans],
        'username': current_user.full_name or current_user.username,
    }

    return render_template('assistant/voice.html', context=context)


@assistant_bp.route('/assistant-vocal/query', methods=['POST'])
@login_required
def voice_query():
    """Traiter une question vocale et retourner une réponse IA."""
    try:
        data = request.get_json(silent=True) or {}
        question = (data.get('question') or '').strip()

        if not question:
            return jsonify({'response': "Je n'ai pas compris votre question. Pouvez-vous répéter ?"})

        # Récupérer le contexte utilisateur
        try:
            if current_user.is_admin():
                total_scans = Scan.query.count()
                total_vulns = Vulnerability.query.count()
                critical = Vulnerability.query.filter_by(severity='critical', status='open').count()
                high = Vulnerability.query.filter_by(severity='high', status='open').count()
                medium = Vulnerability.query.filter_by(severity='medium', status='open').count()
                low = Vulnerability.query.filter_by(severity='low', status='open').count()
                recent = Scan.query.order_by(Scan.created_at.desc()).first()
            else:
                total_scans = Scan.query.filter_by(user_id=current_user.id).count()
                total_vulns = db.session.query(func.count(Vulnerability.id))\
                    .join(Scan).filter(Scan.user_id == current_user.id).scalar() or 0
                critical = db.session.query(func.count(Vulnerability.id))\
                    .join(Scan).filter(Scan.user_id == current_user.id,
                                       Vulnerability.severity == 'critical').scalar() or 0
                high = db.session.query(func.count(Vulnerability.id))\
                    .join(Scan).filter(Scan.user_id == current_user.id,
                                       Vulnerability.severity == 'high').scalar() or 0
                medium = db.session.query(func.count(Vulnerability.id))\
                    .join(Scan).filter(Scan.user_id == current_user.id,
                                       Vulnerability.severity == 'medium').scalar() or 0
                low = db.session.query(func.count(Vulnerability.id))\
                    .join(Scan).filter(Scan.user_id == current_user.id,
                                       Vulnerability.severity == 'low').scalar() or 0
                recent = Scan.query.filter_by(user_id=current_user.id)\
                    .order_by(Scan.created_at.desc()).first()
        except Exception as e:
            logger.error(f"Erreur DB assistant query: {e}")
            total_scans = total_vulns = critical = high = medium = low = 0
            recent = None

        username = current_user.full_name or current_user.username
        response = _generate_response(question, {
            'username': username,
            'total_scans': total_scans,
            'total_vulns': total_vulns,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'recent_scan': recent,
        })

        return jsonify({'response': response})

    except Exception as e:
        logger.error(f"Erreur assistant vocal query: {e}")
        return jsonify({'response': "Une erreur est survenue. Veuillez réessayer."}), 200


def _generate_response(question: str, ctx: dict) -> str:
    """Moteur de réponse intelligent basé sur le contexte."""
    q = question.lower().strip()  # normalisation ici
    name = ctx.get('username', 'Utilisateur')
    total_scans = ctx.get('total_scans', 0)
    total_vulns = ctx.get('total_vulns', 0)
    critical = ctx.get('critical', 0)
    high = ctx.get('high', 0)
    medium = ctx.get('medium', 0)
    low = ctx.get('low', 0)
    recent = ctx.get('recent_scan')

    # ── Salutations
    if any(w in q for w in ['bonjour', 'salut', 'hello', 'bonsoir', 'coucou', 'hi']):
        return f"Bonjour {name} ! Je suis votre assistant vocal Aegis Scan. Comment puis-je vous aider aujourd'hui ?"

    # ── Identité
    if any(w in q for w in ['qui es-tu', 'qui es tu', 'présente', 'c\'est quoi', 'aegis', 'assistant']):
        return ("Je suis l'assistant vocal d'Aegis Scan, votre plateforme DevSecOps intelligente. "
                "Je peux vous informer sur vos scans, vos vulnérabilités, et vous conseiller sur la sécurité de vos applications.")

    # ── Scans
    if any(w in q for w in ['scan', 'analyse', 'analyses', 'combien de scan']):
        if total_scans == 0:
            return "Vous n'avez encore effectué aucune analyse. Rendez-vous dans l'onglet Nouveau Scan pour commencer."
        msg = f"Vous avez effectué {total_scans} analyse{'s' if total_scans > 1 else ''} au total."
        if recent:
            msg += f" La dernière analyse s'appelle '{recent.name}' et son statut est {recent.status}."
        return msg

    # ── Vulnérabilités total
    if any(w in q for w in ['vulnérabilité', 'vulnerabilite', 'faille', 'failles', 'problème', 'probleme']):
        if total_vulns == 0:
            return "Aucune vulnérabilité détectée. Votre code semble sécurisé, mais je vous recommande de lancer régulièrement de nouvelles analyses."
        return (f"Au total, {total_vulns} vulnérabilité{'s ont été détectées' if total_vulns > 1 else ' a été détectée'}. "
                f"Dont {critical} critique{'s' if critical != 1 else ''}, "
                f"{high} élevée{'s' if high != 1 else ''}, "
                f"{medium} moyenne{'s' if medium != 1 else ''}, "
                f"et {low} faible{'s' if low != 1 else ''}.")

    # ── Critiques
    if any(w in q for w in ['critique', 'critical', 'urgent', 'danger', 'grave']):
        if critical == 0:
            return "Bonne nouvelle ! Aucune vulnérabilité critique détectée en ce moment."
        return (f"Attention ! Vous avez {critical} vulnérabilité{'s' if critical > 1 else ''} critique{'s' if critical > 1 else ''}. "
                "Ces failles doivent être corrigées en priorité absolue car elles représentent un risque majeur pour votre application.")

    # ── Score de risque
    if any(w in q for w in ['score', 'risque', 'niveau', 'état', 'etat', 'sécurité', 'securite']):
        if total_vulns == 0:
            return f"Excellent ! Votre score de risque est très bas. Aucune vulnérabilité détectée."
        score = min((critical * 25 + high * 15 + medium * 7 + low * 3), 100)
        niveau = "critique" if score >= 75 else "élevé" if score >= 50 else "moyen" if score >= 25 else "faible"
        return (f"Votre score de risque global est de {score} sur 100, ce qui représente un niveau {niveau}. "
                f"Il est calculé à partir de vos {total_vulns} vulnérabilités détectées.")

    # ── SQL Injection
    if any(w in q for w in ['sql', 'injection', 'sql injection']):
        return ("L'injection SQL est une vulnérabilité critique classée CWE-89. "
                "Elle permet à un attaquant d'exécuter des requêtes SQL malveillantes. "
                "Pour la corriger, utilisez toujours des requêtes paramétrées et un ORM sécurisé.")

    # ── XSS
    if any(w in q for w in ['xss', 'cross site', 'script']):
        return ("Le Cross-Site Scripting ou XSS est classé CWE-79. "
                "Il permet d'injecter du code JavaScript malveillant dans une page web. "
                "La solution est d'échapper toutes les sorties HTML et d'activer une Content Security Policy.")

    # ── CSRF
    if any(w in q for w in ['csrf', 'cross site request']):
        return ("Le CSRF ou Cross-Site Request Forgery force un utilisateur authentifié à exécuter des actions non désirées. "
                "Protégez vos formulaires avec des tokens CSRF. Flask-WTF le fait automatiquement.")

    # ── Docker
    if any(w in q for w in ['docker', 'conteneur', 'container', 'image']):
        return ("Pour sécuriser vos images Docker, utilisez toujours une image de base officielle à jour, "
                "créez un utilisateur non-root dans votre Dockerfile, "
                "et ne stockez jamais de secrets dans les variables ENV.")

    # ── Rapport
    if any(w in q for w in ['rapport', 'report', 'pdf', 'télécharger', 'telecharger']):
        return ("Vous pouvez générer un rapport PDF depuis la page de détail d'un scan terminé. "
                "Cliquez sur le bouton 'Rapport PDF' en haut à droite de la page d'analyse.")

    # ── Aide
    if any(w in q for w in ['aide', 'help', 'que faire', 'comment', 'comment faire']):
        return ("Je peux vous aider avec : le nombre de scans et vulnérabilités, "
                "votre score de risque global, les explications sur les types de failles comme SQL Injection, XSS ou CSRF, "
                "et les conseils de sécurité. Posez-moi votre question !")

    # ── Merci
    if any(w in q for w in ['merci', 'thank', 'thanks', 'super', 'parfait', 'ok']):
        return f"De rien {name} ! N'hésitez pas si vous avez d'autres questions sur la sécurité de vos applications."

    # ── Au revoir
    if any(w in q for w in ['au revoir', 'bye', 'bonne nuit', 'à plus', 'ciao']):
        return f"Au revoir {name} ! Bonne continuation et restez vigilant sur la sécurité de vos applications."

    # ── Réponse par défaut
    return (f"Je n'ai pas trouvé de réponse précise à '{question}'. "
            "Vous pouvez me demander : combien de scans j'ai effectués, "
            "mon score de risque, les vulnérabilités critiques, "
            "ou des explications sur SQL Injection, XSS, CSRF, Docker.")
