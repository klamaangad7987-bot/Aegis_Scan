from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models.user import User

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)
        
        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()
        
        if user and user.check_password(password) and user.is_active:
            login_user(user, remember=bool(remember))
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            flash(f'Bienvenue, {user.full_name or user.username}!', 'success')
            return redirect(next_page or url_for('dashboard.index'))
        else:
            flash('Identifiants incorrects ou compte désactivé.', 'error')
    
    return render_template('auth/login.html')


@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()
        organization = request.form.get('organization', '').strip()
        
        # Validation
        errors = []
        if len(username) < 3:
            errors.append('Le nom d\'utilisateur doit contenir au moins 3 caractères.')
        if User.query.filter_by(username=username).first():
            errors.append('Ce nom d\'utilisateur est déjà pris.')
        if User.query.filter_by(email=email).first():
            errors.append('Cet email est déjà utilisé.')
        if len(password) < 8:
            errors.append('Le mot de passe doit contenir au moins 8 caractères.')
        if password != confirm_password:
            errors.append('Les mots de passe ne correspondent pas.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
        else:
            user = User(
                username=username,
                email=email,
                full_name=full_name,
                organization=organization,
                role='analyst',
                is_active=True,
                is_verified=True
            )
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            login_user(user)
            flash('Compte créé avec succès! Bienvenue!', 'success')
            return redirect(url_for('dashboard.index'))
    
    return render_template('auth/register.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = request.form.get('full_name', '').strip()
        current_user.organization = request.form.get('organization', '').strip()
        
        new_password = request.form.get('new_password', '')
        if new_password:
            if len(new_password) < 8:
                flash('Le mot de passe doit contenir au moins 8 caractères.', 'error')
                return render_template('auth/profile.html')
            current_password = request.form.get('current_password', '')
            if not current_user.check_password(current_password):
                flash('Mot de passe actuel incorrect.', 'error')
                return render_template('auth/profile.html')
            current_user.set_password(new_password)
        
        db.session.commit()
        flash('Profil mis à jour avec succès!', 'success')
        return redirect(url_for('auth.profile'))
    
    return render_template('auth/profile.html')
