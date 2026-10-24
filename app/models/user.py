from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db


class User(UserMixin, db.Model):
    """Modèle utilisateur."""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Rôles: admin, analyst, viewer
    role = db.Column(db.String(20), default='viewer', nullable=False)
    
    # Statut
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Profil
    full_name = db.Column(db.String(120))
    avatar = db.Column(db.String(200))
    organization = db.Column(db.String(120))
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relations
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def set_password(self, password):
        """Hasher le mot de passe."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Vérifier le mot de passe."""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_analyst(self):
        return self.role in ('admin', 'analyst')
    
    def get_avatar_url(self):
        if self.avatar:
            return self.avatar
        # Gravatar par défaut
        import hashlib
        email_hash = hashlib.md5(self.email.lower().encode()).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?d=identicon&s=80"
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role,
            'full_name': self.full_name,
            'organization': self.organization,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
        }
    
    def __repr__(self):
        return f'<User {self.username}>'
