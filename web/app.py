#!/usr/bin/env python3
"""
app.py — Application principale Flask + Socket.IO.
Point d'entrée unique : initialise l'app, les extensions et enregistre les blueprints.
"""

import os
from flask import Flask
from flask_socketio import SocketIO
from flask_wtf.csrf import CSRFProtect
from flask import redirect, url_for

# Extensions partagées (importées dans les blueprints si besoin)
socketio = SocketIO()
csrf = CSRFProtect()


def create_app():
    app = Flask(__name__)

    # ------------------------------------------------------------------ #
    # Configuration#
    # ------------------------------------------------------------------ #
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "pfe-default-secret")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    # En production, passer à True (HTTPS uniquement)
    app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_ENV") == "production"

    # ------------------------------------------------------------------ #
    # Extensions   #
    # ------------------------------------------------------------------ #
    csrf.init_app(app)
    socketio.init_app(app, cors_allowed_origins="same-origin", namespace="/live")

    # ------------------------------------------------------------------ #
    # Blueprints   #
    # ------------------------------------------------------------------ #
    from web.auth import auth_bp
    from web.dashboard import dashboard_bp
    from web.api import api_bp
    from web.live import live_bp  # namespace Socket.IO

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(live_bp)

    @app.route('/')
    def index():
    # Redirige automatiquement n'importe qui arrivant sur http://192.168.1.100:2003/
    # vers http://192.168.1.100:2003/login
        return redirect(url_for('auth.login'))

    return app



if __name__ == "__main__":
    app = create_app()
    # debug=False en production
    socketio.run(app, host="0.0.0.0", port=2003, debug=True)
