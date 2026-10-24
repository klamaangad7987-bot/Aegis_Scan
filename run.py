#!/usr/bin/env python3
import os
import sys
import click
from app import create_app, db

app = create_app(os.environ.get('FLASK_ENV', 'development'))

@app.shell_context_processor
def make_shell_context():
    from app.models.user import User
    from app.models.scan import Scan, Vulnerability, Report
    return {'db': db, 'User': User, 'Scan': Scan, 'Vulnerability': Vulnerability, 'Report': Report}

@app.cli.command('create-admin')
def create_admin():
    username = click.prompt('Username', default='admin')
    email = click.prompt('Email', default='admin@devsecops.local')
    password = click.prompt('Password', hide_input=True, confirmation_prompt=True)
    from app.models.user import User
    if User.query.filter_by(username=username).first():
        click.echo(f'Erreur: utilisateur existe deja.')
        return
    user = User(username=username, email=email, role='admin', is_active=True, is_verified=True)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    click.echo(f'Admin cree!')

if __name__ == '__main__':
    print("==========================================")
    print(" SecureAudit - http://127.0.0.1:5000")
    print("==========================================")
    sys.stdout.flush()
    app.run(debug=os.environ.get('FLASK_DEBUG')=='1', host='127.0.0.1', port=5000, use_reloader=False)
