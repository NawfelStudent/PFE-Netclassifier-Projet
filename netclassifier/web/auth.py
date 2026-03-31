#!/usr/bin/env python3
"""
web/auth.py le Blueprint d'authentification.
Glere le portail captif (login/logout) et la gestion de session.
"""

from flask import (Blueprint, render_template, request, redirect,
                   url_for, session, flash)
from werkzeug.security import check_password_hash
from db.database import (
    get_user_by_username, create_session, delete_session, log_access
)

auth_bp = Blueprint("auth", __name__)

SESSION_DURATION_HOURS = 8


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    client_ip = request.remote_addr

    if request.method == "GET":
        return render_template("login.html",
                               client_ip=client_ip,
                               hours=SESSION_DURATION_HOURS)

    # --- POST : tentative de connexion ---
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Veuillez remplir tous les champs.", "error")
        return render_template("login.html", client_ip=client_ip,
                               hours=SESSION_DURATION_HOURS)

    user = get_user_by_username(username)

    if user and check_password_hash(user["password_hash"], password):
        # Connexion rleussie
        create_session(
            ip_address=client_ip,
            user_id=user["id"],
            username=username,
            profile=user["profile"],
            duration_hours=SESSION_DURATION_HOURS
        )

        # Si admin ou employle le accles au dashboard
        if user["profile"] in ("admin", "employe"):
            session["admin_user"] = username
            session["admin_profile"] = user["profile"]
            session["admin_fullname"] = user["full_name"]
            return redirect(url_for("dashboard.dashboard_page"))

        # Sinon, rediriger vers Internet
        return redirect("http://www.google.com")

    else:
        # lechec de connexion
        log_access(client_ip, username, "failed_login",
                   f"Tentative lechoulee depuis {client_ip}")
        flash("Nom d'utilisateur ou mot de passe incorrect.", "error")
        return render_template("login.html", client_ip=client_ip,
                               hours=SESSION_DURATION_HOURS)


@auth_bp.route("/logout")
def logout():
    client_ip = request.remote_addr
    delete_session(client_ip)
    session.clear()
    flash("Vous avez letle dleconnectle.", "info")
    return redirect(url_for("auth.login"))