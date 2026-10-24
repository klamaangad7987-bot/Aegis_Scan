import pytest
from app import create_app, db as _db
from app.models.user import User
from app.models.scan import Scan, Vulnerability


@pytest.fixture(scope='session')
def app():
    app = create_app('testing')
    with app.app_context():
        _db.create_all()
        yield app
        _db.drop_all()


@pytest.fixture(scope='function')
def db(app):
    with app.app_context():
        _db.create_all()
        yield _db
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def admin_user(db):
    user = User(
        username='testadmin',
        email='testadmin@test.com',
        role='admin',
        is_active=True,
        is_verified=True,
    )
    user.set_password('Admin@123!')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def analyst_user(db):
    user = User(
        username='testanalyst',
        email='testanalyst@test.com',
        role='analyst',
        is_active=True,
        is_verified=True,
    )
    user.set_password('Analyst@123!')
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def sample_scan(db, admin_user):
    scan = Scan(
        name='Test Scan SAST',
        scan_type='sast',
        target='app/test_target.py',
        status='completed',
        user_id=admin_user.id,
        risk_score=45.0,
    )
    db.session.add(scan)
    db.session.commit()

    vuln = Vulnerability(
        scan_id=scan.id,
        title='SQL Injection test',
        severity='high',
        category='SQL Injection',
        cwe_id='CWE-89',
        cvss_score=7.5,
        tool='bandit',
        status='open',
    )
    db.session.add(vuln)
    db.session.commit()
    scan.update_counts()
    db.session.commit()
    return scan
