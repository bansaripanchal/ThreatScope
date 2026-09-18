"""
ThreatScope V2 - Application Entrypoint & Factory
Initializes Flask app, configures blueprints, database schema, safe JSON providers, and error handlers.
"""

from flask import Flask, render_template
from flask.json.provider import DefaultJSONProvider
from markupsafe import Markup
from config import Config
from database.db import init_db
from routes.web_routes import web_bp
from routes.api_routes import api_bp
from services.json_util import normalize_for_json, safe_json_dumps

class SafeJSONProvider(DefaultJSONProvider):
    """Guarantees safe JSON serialization for all Flask API responses."""
    def default(self, obj):
        if type(obj).__name__ in ("Undefined", "StrictUndefined", "DebugUndefined"):
            return None
        return normalize_for_json(obj)

def safe_tojson_filter(val, **kwargs):
    """Safe Jinja tojson filter that never crashes on Undefined objects or dates."""
    normalized = normalize_for_json(val)
    return Markup(safe_json_dumps(normalized, **kwargs))

def create_app(config_class=Config) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Configure Safe JSON provider and safe Jinja filter
    app.json = SafeJSONProvider(app)
    app.jinja_env.filters["tojson"] = safe_tojson_filter

    # Initialize SQLite Database Tables
    with app.app_context():
        init_db()

    # Register Blueprints
    app.register_blueprint(web_bp)
    app.register_blueprint(api_bp)

    # Error Handlers
    @app.errorhandler(404)
    def not_found(e):
        return render_template("base.html", content="<div class='card' style='padding: 3rem; text-align: center;'><h2 style='margin-bottom: 0.5rem;'>404 - Not Found</h2><p style='color: var(--text-muted);'>The requested reconnaissance asset or view could not be located.</p><a href='/' class='btn btn-primary btn-sm' style='margin-top: 1rem;'>Return to Dashboard</a></div>"), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template("base.html", content="<div class='card' style='padding: 3rem; text-align: center;'><h2 style='margin-bottom: 0.5rem; color: var(--color-danger);'>500 - System Error</h2><p style='color: var(--text-muted);'>An internal error occurred during telemetry processing.</p><a href='/' class='btn btn-secondary btn-sm' style='margin-top: 1rem;'>Return to Dashboard</a></div>"), 500

    return app

if __name__ == "__main__":
    application = create_app()
    print(f"[*] ThreatScope V2 starting on http://127.0.0.1:5000 (Debug={Config.DEBUG})")
    application.run(host="0.0.0.0", port=5000, debug=Config.DEBUG, use_reloader=False)
