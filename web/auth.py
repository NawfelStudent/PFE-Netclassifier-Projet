#!/usr/bin/env python3
"""
web/auth.py — Blueprint d'authentification.
Gère le portail captif (login/logout) et la gestion de session.
"""

from flask import (Blueprint, render_template, request, redirect,
   url_for, session, flash)
from werkzeug.security import check_password_hash
from db.database import (
    get_user_by_username, create_session, delete_session, log_access
)

import subprocess
import re

auth_bp = Blueprint("auth", __name__)

SESSION_DURATION_HOURS = 8

def get_mac_address(ip):
    """Cherche l'adresse MAC dans la table ARP du système"""
    try:
        # Optionnel : un ping rapide réveille la table ARP si elle est vide
        subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # On interroge le voisinage réseau
        res = subprocess.check_output(["ip", "neighbor", "show", ip], stderr=subprocess.STDOUT).decode()
        
        # Recherche de l'adresse MAC (ex: aa:bb:cc:dd:ee:ff)
        mac = re.search(r"lladdr\s+([0-9a-fA-F:]+)", res)
        
        if mac:
            return mac.group(1)
        return None
    except Exception as e:
        print(f"Erreur get_mac_address : {e}")
        return None

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
                                hours=SESSION_DURATION_HOURS,
                                )

    user = get_user_by_username(username)

    if user and check_password_hash(user["password_hash"], password):

        timeout_seconds = SESSION_DURATION_HOURS * 3600
        client_mac = get_mac_address(request.remote_addr)
        if not client_mac:
            flash("Erreur : Impossible d'identifier votre carte réseau (MAC).", "error")
            return redirect(url_for("auth.login"))
        
        # 2. AUTORISATION RÉSEAU (nftables)
        # On ajoute la MAC dans le set avec un timeout automatique
        
        try:
            subprocess.run([
                "sudo", "nft", "add", "element", "inet", "portail_captif", "mac_autorises",
                f"{{ {client_mac} timeout {timeout_seconds}s }}"
            ], check=True)
        except Exception as e:
            print(f"Erreur nftables : {e}")


        # 1. Créer la session en base de données
        create_session(
        ip_address=client_ip,
        user_id=user["id"],
        username=username,
        profile=user["profile"],
        duration_hours=SESSION_DURATION_HOURS
        )

        
        # 3. REDIRECTION SELON LE PROFIL
        if user["profile"] in ("admin"):
            session["admin_user"] = username
            session["admin_profile"] = user["profile"]
            session["admin_fullname"] = user["full_name"]
            return redirect(url_for("dashboard.dashboard_page"))
        # Sinon, rediriger vers Internet
        else:
            return redirect("http://www.google.com")
    
    else:
    # échec de connexion
        log_access(client_ip, username, "failed_login",
        f"Tentative  échouée depuis {client_ip}")
        flash("Nom d'utilisateur ou mot de passe incorrect.", "error")
        return render_template("login.html", client_ip=client_ip,
                                hours=SESSION_DURATION_HOURS)


@auth_bp.route("/logout")
def logout():
    client_ip = request.remote_addr
    client_mac = get_mac_address(client_ip)
    # Supprimer l'IP de nftables immédiatement au logout
    try:
        subprocess.run([
            "sudo", "nft", "delete", "element", "inet", "portail_captif", "mac_autorises", 
            f"{{ {client_mac} }}"
        ])
    except:
        pass
    delete_session(client_ip)
    session.clear()
    flash("Vous avez été déconnecté.", "info")
    return redirect(url_for("auth.login"))