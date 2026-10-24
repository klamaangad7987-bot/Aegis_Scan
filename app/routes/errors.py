import logging
from flask import render_template, jsonify, request
from app import db

logger = logging.getLogger(__name__)


def register_error_handlers(app):

    @app.errorhandler(400)
    def bad_request(e):
        if request.is_json:
            return jsonify(error='Requête invalide'), 400
        return render_template('errors/404.html'), 400

    @app.errorhandler(403)
    def forbidden(e):
        if request.is_json:
            return jsonify(error='Accès interdit'), 403
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.is_json:
            return jsonify(error='Ressource introuvable'), 404
        return render_template('errors/404.html'), 404

    @app.errorhandler(413)
    def too_large(e):
        if request.is_json:
            return jsonify(error='Fichier trop volumineux (max 50 Mo)'), 413
        from flask import flash, redirect, url_for
        flash('Fichier trop volumineux. La taille maximale est de 50 Mo.', 'error')
        return redirect(url_for('scan.new_scan'))

    @app.errorhandler(500)
    def server_error(e):
        logger.error(f"Erreur 500: {e}", exc_info=True)
        # Tenter un rollback de session pour éviter les transactions bloquées
        try:
            db.session.rollback()
        except Exception:
            pass
        if request.is_json:
            return jsonify(error='Erreur serveur interne'), 500
        return render_template('errors/500.html'), 500

    @app.errorhandler(Exception)
    def unhandled_exception(e):
        logger.error(f"Exception non gérée: {e}", exc_info=True)
        try:
            db.session.rollback()
        except Exception:
            pass
        if request.is_json:
            return jsonify(error='Erreur serveur interne'), 500
        return render_template('errors/500.html'), 500
