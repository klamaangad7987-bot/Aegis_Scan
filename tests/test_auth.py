"""Tests du module authentification."""
import pytest


class TestLogin:

    def test_login_page_loads(self, client):
        res = client.get('/auth/login')
        assert res.status_code == 200
        assert b'SecureAudit' in res.data

    def test_login_success(self, client, admin_user):
        res = client.post('/auth/login', data={
            'username': 'testadmin',
            'password': 'Admin@123!',
            'csrf_token': 'test',
        }, follow_redirects=True)
        assert res.status_code == 200

    def test_login_wrong_password(self, client, admin_user):
        res = client.post('/auth/login', data={
            'username': 'testadmin',
            'password': 'wrong_password',
            'csrf_token': 'test',
        }, follow_redirects=True)
        assert res.status_code == 200

    def test_login_nonexistent_user(self, client):
        res = client.post('/auth/login', data={
            'username': 'nobody',
            'password': 'password',
            'csrf_token': 'test',
        }, follow_redirects=True)
        assert res.status_code == 200


class TestRegister:

    def test_register_page_loads(self, client):
        res = client.get('/auth/register')
        assert res.status_code == 200

    def test_register_success(self, client, db):
        res = client.post('/auth/register', data={
            'username': 'newuser',
            'email': 'newuser@test.com',
            'password': 'NewPass@123!',
            'confirm_password': 'NewPass@123!',
            'csrf_token': 'test',
        }, follow_redirects=True)
        assert res.status_code == 200

        from app.models.user import User
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'newuser@test.com'

    def test_register_duplicate_username(self, client, admin_user):
        res = client.post('/auth/register', data={
            'username': 'testadmin',
            'email': 'other@test.com',
            'password': 'Pass@123!',
            'confirm_password': 'Pass@123!',
            'csrf_token': 'test',
        }, follow_redirects=True)
        assert res.status_code == 200


class TestUserModel:

    def test_password_hashing(self, admin_user):
        assert admin_user.check_password('Admin@123!') is True
        assert admin_user.check_password('wrongpass') is False

    def test_admin_role(self, admin_user):
        assert admin_user.is_admin() is True
        assert admin_user.is_analyst() is True

    def test_analyst_role(self, analyst_user):
        assert analyst_user.is_admin() is False
        assert analyst_user.is_analyst() is True

    def test_user_to_dict(self, admin_user):
        d = admin_user.to_dict()
        assert d['username'] == 'testadmin'
        assert d['role'] == 'admin'
        assert 'password_hash' not in d
