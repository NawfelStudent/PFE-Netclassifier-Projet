#!/usr/bin/env python3
"""
web/dashboard.py — Blueprint des pages du dashboard.
Toutes les pages nécessitent une session admin/employé.

Corrections :
  - alert_count transmis à toutes les pages (plus uniquement /dashboard)
  - Pagination sur /logs (?page= et ?per_page=)
"""

from functools import wraps
from flask import Blueprint, render_template, session, redirect, url_for, request
from db.database import (
    get_all_users, get_active_sessions, get_all_policies,
    get_recent_flows, get_access_logs, get_unread_alerts,
)

dashboard_bp = Blueprint("dashboard", __name__)

PER_PAGE_DEFAULT = 100
PER_PAGE_MAX     = 500


# ------------------------------------------------------------------ #
# Décorateur  #
# ------------------------------------------------------------------ #

def admin_required(f):
    """Vérifie que l'utilisateur est admin ou employé."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "admin_user" not in session:
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated


def _base_ctx():
    """Contexte commun à toutes les pages (user, profile, alert_count)."""
    alerts = get_unread_alerts()
    return {
        "user":session["admin_user"],
        "profile":     session["admin_profile"],
        "fullname":    session.get("admin_fullname", ""),
        "alert_count": len(alerts),
    }


# ------------------------------------------------------------------ #
# Pages       #
# ------------------------------------------------------------------ #

@dashboard_bp.route("/dashboard")
@admin_required
def dashboard_page():
    return render_template("dashboard.html", **_base_ctx())


@dashboard_bp.route("/users")
@admin_required
def users_page():
    ctx = _base_ctx()
    ctx["users"]    = get_all_users()
    ctx["sessions"] = get_active_sessions()
    return render_template("users.html", **ctx)


@dashboard_bp.route("/policies")
@admin_required
def policies_page():
    policies = get_all_policies()
    grouped = {}
    for p in policies:
        grouped.setdefault(p["profile"], []).append(p)

    ctx = _base_ctx()
    ctx["grouped_policies"] = grouped
    return render_template("policies.html", **ctx)


@dashboard_bp.route("/logs")
@admin_required
def logs_page():
    per_page = min(request.args.get("per_page", PER_PAGE_DEFAULT, type=int), PER_PAGE_MAX)

    ctx = _base_ctx()
    ctx["flows"]       = get_recent_flows(limit=per_page)
    ctx["access_logs"] = get_access_logs(limit=per_page)
    ctx["per_page"]    = per_page
    return render_template("logs.html", **ctx)
