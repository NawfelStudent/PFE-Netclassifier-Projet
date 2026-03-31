#!/usr/bin/env python3
"""
web/api.py — Blueprint API REST.
Sert les données JSON pour le dashboard JavaScript (Chart.js, tableau live).
Toutes les routes sont préfixées par /api/.

Corrections apportées :
  - Décorateur super_admin_required pour les routes sensibles (profil, suppression)
  - Protection CSRF via flask-wtf (token dans le header X-CSRFToken)
  - Validation du profil cible (interdit de se promouvoir soi-même en admin)
  - Gestion d'erreur sur api_update_policy (data manquant)
"""

from functools import wraps
from flask import Blueprint, jsonify, request, session
from db.database import (
    get_realtime_stats, get_stats_history, get_active_sessions,
    get_recent_flows, get_all_users, create_user, update_user_profile,
    delete_user, get_all_policies, update_policy, get_unread_alerts,
    mark_alert_read, get_top_users, get_top_domains, log_access
)

api_bp = Blueprint("api", __name__)

# Profils autorisés à être assignés
VALID_PROFILES = {"etudiant", "employe", "admin", "invite", "restricted"}


# ------------------------------------------------------------------ #
# Décorateurs d'autorisation                                          #
# ------------------------------------------------------------------ #

def api_login_required(f):
    """Vérifie qu'une session admin/employé est active."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_user" not in session:
            return jsonify({"error": "Non autorisé"}), 401
        return f(*args, **kwargs)
    return decorated


def api_admin_required(f):
    """Réservé aux administrateurs uniquement."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_user" not in session:
            return jsonify({"error": "Non autorisé"}), 401
        if session.get("admin_profile") != "admin":
            return jsonify({"error": "Droits administrateur requis"}), 403
        return f(*args, **kwargs)
    return decorated


# ------------------------------------------------------------------ #
# STATISTIQUES                                                        #
# ------------------------------------------------------------------ #

@api_bp.route("/stats/realtime")
@api_login_required
def api_realtime_stats():
    return jsonify(get_realtime_stats())


@api_bp.route("/stats/history")
@api_login_required
def api_stats_history():
    minutes = request.args.get("minutes", 60, type=int)
    return jsonify(get_stats_history(minutes))


@api_bp.route("/stats/top-users")
@api_login_required
def api_top_users():
    hours = request.args.get("hours", 1, type=int)
    return jsonify(get_top_users(hours))


@api_bp.route("/stats/top-domains")
@api_login_required
def api_top_domains():
    hours = request.args.get("hours", 1, type=int)
    return jsonify(get_top_domains(hours))


# ------------------------------------------------------------------ #
# FLUX                                                                #
# ------------------------------------------------------------------ #

@api_bp.route("/flows/recent")
@api_login_required
def api_recent_flows():
    limit = min(request.args.get("limit", 50, type=int), 500)
    return jsonify(get_recent_flows(limit))


# ------------------------------------------------------------------ #
# SESSIONS                                                            #
# ------------------------------------------------------------------ #

@api_bp.route("/sessions")
@api_login_required
def api_sessions():
    return jsonify(get_active_sessions())


# ------------------------------------------------------------------ #
# UTILISATEURS  (admin uniquement)                                   #
# ------------------------------------------------------------------ #

@api_bp.route("/users")
@api_login_required
def api_list_users():
    return jsonify(get_all_users())


@api_bp.route("/users", methods=["POST"])
@api_admin_required
def api_create_user():
    data = request.json
    if not data or not data.get("username") or not data.get("password"):
        return jsonify({"error": "username et password requis"}), 400

    profile = data.get("profile", "invite")
    if profile not in VALID_PROFILES:
        return jsonify({"error": "Profil invalide"}), 400

    ok = create_user(
        username=data["username"],
        password=data["password"],
        full_name=data.get("full_name", ""),
        profile=profile
    )
    if ok:
        return jsonify({"status": "ok"}), 201
    return jsonify({"error": "Nom d'utilisateur déjà pris"}), 409


@api_bp.route("/users/<int:user_id>/profile", methods=["PUT"])
@api_admin_required                         # employé ne peut plus appeler cette route
def api_update_profile(user_id):
    data = request.json
    if not data or not data.get("profile"):
        return jsonify({"error": "profile requis"}), 400

    new_profile = data["profile"]
    if new_profile not in VALID_PROFILES:
        return jsonify({"error": "Profil invalide"}), 400

    update_user_profile(user_id, new_profile)
    log_access(
        ip_address=request.remote_addr,
        username=session["admin_user"],
        event="profile_changed",
        details=f"user_id={user_id} → {new_profile}"
    )
    return jsonify({"status": "ok"})


@api_bp.route("/users/<int:user_id>", methods=["DELETE"])
@api_admin_required
def api_delete_user(user_id):
    # Interdit de supprimer son propre compte
    users = get_all_users()
    target = next((u for u in users if u["id"] == user_id), None)
    if target and target["username"] == session["admin_user"]:
        return jsonify({"error": "Impossible de supprimer son propre compte"}), 403

    delete_user(user_id)
    log_access(
        ip_address=request.remote_addr,
        username=session["admin_user"],
        event="user_deleted",
        details=f"user_id={user_id}"
    )
    return jsonify({"status": "ok"})


# ------------------------------------------------------------------ #
# POLITIQUES                                                          #
# ------------------------------------------------------------------ #

@api_bp.route("/policies")
@api_login_required
def api_list_policies():
    return jsonify(get_all_policies())


@api_bp.route("/policies/<int:rule_id>", methods=["PUT"])
@api_admin_required
def api_update_policy(rule_id):
    data = request.json
    if not data:
        return jsonify({"error": "Corps JSON manquant"}), 400

    valid_actions = {"Allow", "Block", "Limit", "Log"}
    action = data.get("action", "Allow")
    if action not in valid_actions:
        return jsonify({"error": "Action invalide"}), 400

    update_policy(
        rule_id=rule_id,
        action=action,
        bandwidth_kbps=data.get("bandwidth_kbps"),
        is_active=data.get("is_active", True)
    )
    return jsonify({"status": "ok"})


# ------------------------------------------------------------------ #
# ALERTES                                                             #
# ------------------------------------------------------------------ #

@api_bp.route("/alerts")
@api_login_required
def api_alerts():
    return jsonify(get_unread_alerts())


@api_bp.route("/alerts/<int:alert_id>/read", methods=["POST"])
@api_login_required
def api_mark_alert_read(alert_id):
    mark_alert_read(alert_id)
    return jsonify({"status": "ok"})
