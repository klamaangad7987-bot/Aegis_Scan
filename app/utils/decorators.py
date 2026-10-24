from functools import wraps
from flask import abort, flash, redirect, url_for
from flask_login import current_user


def admin_required(f):
    """Décorateur : accès réservé aux administrateurs."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


def analyst_required(f):
    """Décorateur : accès réservé aux analystes et admins."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_analyst():
            abort(403)
        return f(*args, **kwargs)
    return decorated
