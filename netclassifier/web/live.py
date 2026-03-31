#!/usr/bin/env python3
"""
web/live.py — Namespace Socket.IO "/live".
Émet les flux classifiés et les stats agrégées en temps réel.
Ce module est appelé par le moteur de classification (thread séparé)
via emit_flow() et emit_stats().
"""

from flask import Blueprint, session
from flask_socketio import Namespace, emit, disconnect
from app import socketio

live_bp = Blueprint("live", __name__)


class LiveNamespace(Namespace):
    """Namespace /live — connexions dashboard."""

    def on_connect(self):
        """Refuse la connexion si l'utilisateur n'est pas authentifié."""
        if "admin_user" not in session:
            disconnect()
            return False

    def on_disconnect(self):
        pass


socketio.on_namespace(LiveNamespace("/live"))


# ------------------------------------------------------------------ #
# Fonctions appelées depuis le moteur de classification               #
# ------------------------------------------------------------------ #

def emit_flow(flow_dict: dict):
    """Émet un nouveau flux vers tous les clients connectés sur /live."""
    socketio.emit("new_flow", flow_dict, namespace="/live")


def emit_stats(stats_dict: dict):
    """Émet les stats agrégées (toutes les N secondes)."""
    socketio.emit("stats_update", stats_dict, namespace="/live")
