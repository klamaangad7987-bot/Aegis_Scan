from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.scan import scan_bp
from app.routes.reports import reports_bp
from app.routes.api import api_bp

__all__ = ['auth_bp', 'dashboard_bp', 'scan_bp', 'reports_bp', 'api_bp']
