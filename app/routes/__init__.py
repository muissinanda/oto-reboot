"""
Routes package initialization for OTO REBOOT application.
Exports blueprints and provides a helper function to register all blueprints.
"""

from app.routes.dashboard import dashboard_bp
from app.routes.access_points import access_points_bp
from app.routes.controllers import controllers_bp
from app.routes.schedules import schedules_bp
from app.routes.logs import logs_bp


def register_routes(app):
    """
    Registers all blueprints with the Flask application instance.
    """
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(access_points_bp)
    app.register_blueprint(controllers_bp)
    app.register_blueprint(schedules_bp)
    app.register_blueprint(logs_bp)


__all__ = [
    'dashboard_bp',
    'access_points_bp',
    'controllers_bp',
    'schedules_bp',
    'logs_bp',
    'register_routes'
]
