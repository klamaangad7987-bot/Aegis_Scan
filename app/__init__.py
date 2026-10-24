from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from config import config
import os

# Extensions
db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()



def _setup_logging(app):
    """Configurer le logging de l'application."""
    import logging
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG if app.debug else logging.INFO)

def create_app(config_name=None):
    """Factory pattern pour créer l'application Flask."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    
    # Initialiser les extensions
    db.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    
    # Config LoginManager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    login_manager.login_message_category = 'warning'
    
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        try:
            return db.session.get(User, int(user_id))
        except Exception:
            return None
    
    # Enregistrer les blueprints
    from app.routes.auth import auth_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.scan import scan_bp
    from app.routes.reports import reports_bp
    from app.routes.api import api_bp
    from app.routes.assistant import assistant_bp

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(dashboard_bp, url_prefix='/')
    app.register_blueprint(scan_bp, url_prefix='/scan')
    app.register_blueprint(reports_bp, url_prefix='/reports')
    app.register_blueprint(api_bp, url_prefix='/api/v1')
    app.register_blueprint(assistant_bp, url_prefix='/')
    
    # Gestionnaires d'erreurs
    from app.routes.errors import register_error_handlers
    register_error_handlers(app)
    
    # Template globals
    @app.context_processor
    def inject_globals():
        from flask_login import current_user
        return {
            'app_name': app.config.get('APP_NAME', 'Aegis Scan'),
            'app_version': app.config.get('APP_VERSION', '1.0.0'),
            'current_user': current_user,
        }
    
    # Créer les tables
    with app.app_context():
        db.create_all()
        _create_admin_user()
    
    # Fermeture propre des sessions SQLAlchemy à chaque requête
    @app.teardown_appcontext
    def shutdown_session(exception=None):
        if exception:
            db.session.rollback()
        db.session.remove()

    _setup_logging(app)
    return app


def _create_admin_user():
    """Créer l'admin initial UNIQUEMENT si ADMIN_PASSWORD est défini dans .env.

    Aucun mot de passe n'est écrit en dur dans le code. Si la variable
    n'est pas définie, aucun compte n'est créé : utiliser `flask create-admin`.
    """
    import os
    from app.models.user import User

    password = os.environ.get('ADMIN_PASSWORD')
    if not password or User.query.count() > 0:
        return
    if len(password) < 12:
        print('[SECURITE] ADMIN_PASSWORD trop court (min 12 caracteres) : admin non cree.')
        return

    admin = User(
        username=os.environ.get('ADMIN_USERNAME', 'admin'),
        email=os.environ.get('ADMIN_EMAIL', 'admin@example.com'),
        full_name='Administrateur',
        role='admin',
        is_active=True,
        is_verified=True,
    )
    admin.set_password(password)
    db.session.add(admin)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
