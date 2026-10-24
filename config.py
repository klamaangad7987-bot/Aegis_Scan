import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    """Configuration de base."""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-me'
    
    # Base de données SQLite
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        f"sqlite:///{os.path.join(BASE_DIR, 'devsecops.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload de fichiers
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports_output')
    MAX_CONTENT_LENGTH = int(os.environ.get('MAX_CONTENT_LENGTH', 52428800))  # 50MB
    ALLOWED_EXTENSIONS = set(
        os.environ.get('ALLOWED_EXTENSIONS', 'py,js,java,php,go,rb,zip,tar,gz').split(',')
    )
    
    # Celery
    CELERY_BROKER_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    
    # Mail
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # ZAP DAST
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY', '')
    ZAP_BASE_URL = os.environ.get('ZAP_BASE_URL', 'http://localhost:8080')
    
    # App Info
    APP_NAME = os.environ.get('APP_NAME', 'Aegis Scan')
    APP_VERSION = os.environ.get('APP_VERSION', '1.0.0')
    
    # Pagination
    ITEMS_PER_PAGE = 10
    
    # Session
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = 86400  # 24 heures (au lieu de 1h)
    REMEMBER_COOKIE_DURATION = 604800  # 7 jours pour "se souvenir de moi"
    WTF_CSRF_TIME_LIMIT = None  # Pas d'expiration CSRF (évite les erreurs après longue session)
    
    @staticmethod
    def init_app(app):
        # Créer les dossiers nécessaires
        os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
        os.makedirs(Config.REPORTS_FOLDER, exist_ok=True)


class DevelopmentConfig(Config):
    """Configuration développement."""
    DEBUG = True
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    """Configuration production."""
    DEBUG = False
    SESSION_COOKIE_SECURE = True
    
    @classmethod
    def init_app(cls, app):
        Config.init_app(app)


class TestingConfig(Config):
    """Configuration test."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
