#!/usr/bin/env python3
"""
db/database.py  Couche d'accès à la base de données SQLite.

Ce fichier est importé par TOUS les autres modules du projet :
  - web/auth.py      pour login/logout (users, active_sessions, access_log)
  - web/api.py       pour lecture des stats et flux (classified_flows, stats_per_minute)
  - core/pipeline.py pour sauvegarde des flux classifiés (classified_flows)
  - core/resolver.py pour lecture des sessions (active_sessions)
  - manage.py        pour initialisation (init_db)

Règle critique : chaque fonction ouvre et ferme sa propre connexion.
SQLite en mode WAL supporte 1 writer + N readers simultanés.
"""

import sqlite3
import time
import threading
from pathlib import Path
from datetime import datetime, timedelta
from contextlib import contextmanager

from werkzeug.security import generate_password_hash

# Chemin vers la BDD importé depuis config si disponible,
# sinon valeur par défaut
try:
    from config.settings import DB_PATH
except ImportError:
    DB_PATH = str(Path(__file__).parent / "netclassifier.db")

# Chemin vers le schéma SQL
SCHEMA_PATH = str(Path(__file__).parent / "schema.sql")


# =============================================================================
# CONNEXION
# =============================================================================

@contextmanager
def get_db():
    """
    Context manager pour obtenir une connexion SQLite.
    Ouvre la connexion, exécute le bloc, puis ferme automatiquement.

    Usage :
        with get_db() as conn:
            conn.execute("SELECT ...")

    Pourquoi un context manager ?
    - Garantit que la connexion est fermée même en cas d'erreur
    - Évite les fuites de connexion (important avec SQLite)
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row        # Accès par nom de colonne : row["username"]
    conn.execute("PRAGMA journal_mode=WAL")  # Lectures parallèles aux écritures
    conn.execute("PRAGMA foreign_keys=ON")   # Activer les clés étrangères
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db_simple():
    """
    Connexion simple (sans context manager).
    ATTENTION : l'appelant DOIT fermer la connexion lui-même.
    Utilisé uniquement par CaptivePortalResolver qui garde une connexion
    ouverte en cache pour la performance.
    """
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


# =============================================================================
# INITIALISATION
# Appelé par : manage.py init, web/app.py au démarrage
# =============================================================================

def init_db():
    """
    Crée toutes les tables et insère les données initiales.

    Usage :
        python3 -c "from db.database import init_db; init_db()"
    """
    # Créer le répertoire si nécessaire
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    with get_db() as conn:
        # Exécute le schéma SQL
        if Path(SCHEMA_PATH).exists():
            conn.executescript(Path(SCHEMA_PATH).read_text(encoding="utf-8"))
        else:
            print(f"ATTENTION : {SCHEMA_PATH} introuvable, création minimale")
            _create_minimal_schema(conn)

        # Insère les utilisateurs de test (avec vrais hash de mots de passe)
        _seed_test_users(conn)

    print(f"\u2705 Base de données initialisée : {DB_PATH}")


def _seed_test_users(conn):
    """
    Insère les 6 utilisateurs de test.
    Les mots de passe sont hashés avec werkzeug (même algo que Flask).
    """
    test_users = [
        ("ahmed",   "pass123", "Ahmed Benali",     "etudiant"),
        ("sara",    "pass123", "Sara Mansouri",     "etudiant"),
        ("prof1",   "pass123", "M. Dupont",         "employe"),
        ("admin",   "admin00", "Administrateur",    "admin"),
        ("guest01", "guest",   "Visiteur",          "invite"),
        ("labo",    "pass123", "Salle Labo",        "restricted"),
    ]
    for username, password, full_name, profile in test_users:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, full_name, profile) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), full_name, profile)
            )
        except sqlite3.IntegrityError:
            pass  # Utilisateur déjà existant, on ignore


def _create_minimal_schema(conn):
    """Schéma minimal si schema.sql est introuvable."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT DEFAULT '',
            profile TEXT NOT NULL DEFAULT 'invite',
            is_active BOOLEAN DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS active_sessions (
            ip_address TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            profile TEXT NOT NULL,
            mac_address TEXT DEFAULT '',
            login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        );
        CREATE TABLE IF NOT EXISTS classified_flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT, dst_ip TEXT,
            src_port INTEGER, dst_port INTEGER, protocol INTEGER,
            application_name TEXT DEFAULT 'Unknown',
            sni TEXT DEFAULT '',
            category TEXT NOT NULL,
            confidence REAL DEFAULT 0.0,
            action TEXT NOT NULL,
            action_detail TEXT DEFAULT '',
            username TEXT DEFAULT 'Inconnu',
            profile TEXT DEFAULT 'invite',
            bytes_total INTEGER DEFAULT 0,
            packets_total INTEGER DEFAULT 0,
            duration_ms INTEGER DEFAULT 0,
            bytes_per_second REAL DEFAULT 0.0,
            decision_latency_ms REAL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS stats_per_minute (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_flows INTEGER DEFAULT 0,
            total_bytes INTEGER DEFAULT 0,
            active_users INTEGER DEFAULT 0,
            cat_streaming INTEGER DEFAULT 0,
            cat_social INTEGER DEFAULT 0,
            cat_ads INTEGER DEFAULT 0,
            cat_download INTEGER DEFAULT 0,
            cat_web INTEGER DEFAULT 0,
            cat_suspect INTEGER DEFAULT 0,
            action_allow INTEGER DEFAULT 0,
            action_block INTEGER DEFAULT 0,
            action_limit INTEGER DEFAULT 0,
            avg_latency_ms REAL DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS access_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip_address TEXT DEFAULT '',
            username TEXT DEFAULT '',
            event TEXT NOT NULL,
            details TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            severity TEXT DEFAULT 'info',
            source TEXT DEFAULT '',
            title TEXT NOT NULL,
            message TEXT DEFAULT '',
            ip_address TEXT DEFAULT '',
            username TEXT DEFAULT '',
            is_read BOOLEAN DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS policy_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile TEXT NOT NULL,
            category TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'Allow',
            bandwidth_kbps INTEGER DEFAULT NULL,
            time_start TEXT DEFAULT NULL,
            time_end TEXT DEFAULT NULL,
            priority INTEGER DEFAULT 0,
            is_active BOOLEAN DEFAULT 1
        );
    """)


# =============================================================================
# UTILISATEURS
# Appelé par : web/auth.py (login), web/api.py (gestion users)
# =============================================================================

def get_user_by_username(username: str) -> dict | None:
    """
    Cherche un utilisateur par son nom.
    Retourné par le portail captif pour vérifier le login.

    Retourne : dict avec toutes les colonnes, ou None si introuvable.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()
        return dict(row) if row else None


def get_all_users() -> list[dict]:
    """
    Liste tous les utilisateurs.
    Utilisé par le dashboard (page Utilisateurs).
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, full_name, email, profile, is_active, created_at "
            "FROM users ORDER BY profile, username"
        ).fetchall()
        return [dict(r) for r in rows]


def create_user(username: str, password: str, full_name: str = "",
                profile: str = "invite") -> bool:
    """
    Crée un nouvel utilisateur.
    Appelé depuis le dashboard admin (API POST /api/users).
    Retourne True si crée, False si username déjà pris.
    """
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, full_name, profile) "
                "VALUES (?, ?, ?, ?)",
                (username, generate_password_hash(password), full_name, profile)
            )
            log_access("", username, "user_created",
                       f"Profil: {profile}", conn=conn)
        return True
    except sqlite3.IntegrityError:
        return False


def update_user_profile(user_id: int, new_profile: str) -> bool:
    """
    Change le profil d'un utilisateur.
    Met aussi jour la session active si elle existe.
    Appelé depuis le dashboard admin (API PUT /api/users/<id>/profile).
    """
    with get_db() as conn:
        conn.execute("UPDATE users SET profile = ? WHERE id = ?",
                     (new_profile, user_id))
        # Mettre jour la session active aussi
        conn.execute("UPDATE active_sessions SET profile = ? WHERE user_id = ?",
                     (new_profile, user_id))
        return conn.total_changes > 0


def delete_user(user_id: int):
    """Supprime un utilisateur (CASCADE supprime aussi sa session)."""
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))


# =============================================================================
# SESSIONS
# Appelé par : web/auth.py (login/logout), core/resolver.py (lookup)
# =============================================================================

def create_session(ip_address: str, user_id: int, username: str,
                   profile: str, duration_hours: int = 8,
                   mac_address: str = ""):
    """
    Crée une session active (appelé au login réussi).
    Si l'IP a déjà une session, elle est remplacée (INSERT OR REPLACE).
    """
    expires = datetime.now() + timedelta(hours=duration_hours)
    with get_db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO active_sessions "
            "(ip_address, user_id, username, profile, mac_address, "
            " login_time, expires_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ip_address, user_id, username, profile, mac_address,
             datetime.now(), expires)
        )
        log_access(ip_address, username, "login", f"Profil: {profile}", conn=conn)


def delete_session(ip_address: str):
    """
    Supprime une session (appelé au logout ou à l'expiration).
    """
    with get_db() as conn:
        # Récupère le username avant suppression (pour le log)
        row = conn.execute(
            "SELECT username FROM active_sessions WHERE ip_address = ?",
            (ip_address,)
        ).fetchone()
        conn.execute(
            "DELETE FROM active_sessions WHERE ip_address = ?",
            (ip_address,)
        )
        if row:
            log_access(ip_address, row["username"], "logout", conn=conn)


def get_active_sessions() -> list[dict]:
    """
    Retourne toutes les sessions actives (non expirées).
    Utilisé par le dashboard et l'API.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM active_sessions "
            "WHERE expires_at > datetime('now') "
            "ORDER BY login_time DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def get_all_sessions_as_cache() -> dict:
    """
    Retourne les sessions sous forme de dict {ip: (username, profile)}.
    Utilisé par CaptivePortalResolver pour charger le cache mémoire.
    Optimisé : une seule requête pour tout charger.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT ip_address, username, profile FROM active_sessions "
            "WHERE expires_at > datetime('now')"
        ).fetchall()
        return {
            row["ip_address"]: (row["username"], row["profile"])
            for row in rows
        }


def cleanup_expired_sessions() -> int:
    """
    Supprime les sessions expirées. Retourne le nombre supprimé.
    Appelé périodiquement par un thread de maintenance.
    """
    with get_db() as conn:
        # Logger les expirations avant suppression
        expired = conn.execute(
            "SELECT ip_address, username FROM active_sessions "
            "WHERE expires_at <= datetime('now')"
        ).fetchall()
        for row in expired:
            log_access(row["ip_address"], row["username"], "expired", conn=conn)

        conn.execute(
            "DELETE FROM active_sessions WHERE expires_at <= datetime('now')"
        )
        return len(expired)


# =============================================================================
# FLUX CLASSIFIÉS
# Appelé par : core/pipeline.py (critère), web/api.py (lecture)
# =============================================================================

def save_classified_flow(flow_data: dict):
    """
    Enregistre un flux classifié dans l'historique.
    Appelé par core/pipeline.py le chaque flux expiré par NFStream.

    flow_data doit contenir au minimum :
        src_ip, dst_ip, category, action
    """
    with get_db() as conn:
        conn.execute("""
            INSERT INTO classified_flows
            (src_ip, dst_ip, src_port, dst_port, protocol,
             application_name, sni, category, confidence, model_type,
             action, action_detail, username, profile,
             bytes_total, packets_total, duration_ms,
             bytes_per_second, decision_latency_ms)
            VALUES (?,?,?,?,?, ?,?,?,?,?, ?,?,?,?, ?,?,?,?,?)
        """, (
            flow_data.get("src_ip", ""),
            flow_data.get("dst_ip", ""),
            flow_data.get("src_port", 0),
            flow_data.get("dst_port", 0),
            flow_data.get("protocol", 6),
            flow_data.get("application_name", "Unknown"),
            flow_data.get("sni", flow_data.get("requested_server_name", "")),
            flow_data["category"],
            flow_data.get("confidence", 0.0),
            flow_data.get("model_type", "heuristic"),
            flow_data["action"],
            flow_data.get("action_detail", ""),
            flow_data.get("username", "Inconnu"),
            flow_data.get("profile", "invite"),
            flow_data.get("bytes_total", flow_data.get("bidirectional_bytes", 0)),
            flow_data.get("packets_total", flow_data.get("bidirectional_packets", 0)),
            flow_data.get("duration_ms", flow_data.get("bidirectional_duration_ms", 0)),
            flow_data.get("bytes_per_second", 0.0),
            flow_data.get("latency_ms", flow_data.get("decision_latency_ms", 0.0)),
        ))

        # Génère une alerte si flux suspect
        if flow_data["category"] == "Suspect":
            create_alert(
                severity="warning",
                source="classifier",
                title="Flux suspect détecté",
                message=(
                    f"{flow_data.get('src_ip')} \u2192 {flow_data.get('dst_ip')}:{flow_data.get('dst_port')} "
                    f"| App={flow_data.get('application_name')} "
                    f"| Confiance={flow_data.get('confidence', 0):.0%}"
                ),
                ip_address=flow_data.get("src_ip", ""),
                username=flow_data.get("username", ""),
                conn=conn,
            )


def get_recent_flows(limit: int = 50) -> list[dict]:
    """
    Retourne les derniers flux classifiés.
    Utilisé par le dashboard (tableau live) et l'API.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM classified_flows ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_realtime_stats() -> dict:
    """
    Retourne les statistiques de la dernière minute.
    Utilise la vue v_realtime_stats définie dans schema.sql.
    Appelé par l'API /api/stats/realtime.
    """
    with get_db() as conn:
        row = conn.execute("SELECT * FROM v_realtime_stats").fetchone()
        return dict(row) if row else {}


def get_top_users(hours: int = 1) -> list[dict]:
    """Top consommateurs de bande passante."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT username, profile, "
            "COUNT(*) AS flow_count, SUM(bytes_total) AS total_bytes, "
            "SUM(CASE WHEN action='Block' THEN 1 ELSE 0 END) AS blocked_flows "
            "FROM classified_flows "
            "WHERE timestamp > datetime('now', ?) "
            "GROUP BY username ORDER BY total_bytes DESC",
            (f"-{hours} hours",)
        ).fetchall()
        return [dict(r) for r in rows]


def get_top_domains(hours: int = 1, limit: int = 50) -> list[dict]:
    """Top domaines visités (par SNI)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT sni, category, COUNT(*) AS hit_count, "
            "SUM(bytes_total) AS total_bytes, "
            "COUNT(DISTINCT src_ip) AS unique_users "
            "FROM classified_flows "
            "WHERE timestamp > datetime('now', ?) AND sni != '' "
            "GROUP BY sni ORDER BY hit_count DESC LIMIT ?",
            (f"-{hours} hours", limit)
        ).fetchall()
        return [dict(r) for r in rows]


# =============================================================================
# STATISTIQUES AGRÉGÉES
# Appelé par : thread d'agrégation (core/pipeline.py), web/api.py
# =============================================================================

def aggregate_current_minute():
    """
    Calcule et sauvegarde les stats de la dernière minute.
    Appelé toutes les 60 secondes par un thread en arrière-plan.
    """
    with get_db() as conn:
        conn.execute("""
            INSERT INTO stats_per_minute
            (total_flows, total_bytes, total_packets, active_users,
             cat_streaming, cat_social, cat_ads, cat_download,
             cat_web, cat_suspect,
             action_allow, action_block, action_limit, action_log,
             avg_latency_ms, max_latency_ms)
            SELECT
                COUNT(*),
                COALESCE(SUM(bytes_total), 0),
                COALESCE(SUM(packets_total), 0),
                COUNT(DISTINCT src_ip),
                SUM(CASE WHEN category='Streaming'       THEN 1 ELSE 0 END),
                SUM(CASE WHEN category='R\u00e9seaux sociaux' THEN 1 ELSE 0 END),
                SUM(CASE WHEN category='Publicit\u00e9'       THEN 1 ELSE 0 END),
                SUM(CASE WHEN category='T\u00e9l\u00e9chargement'  THEN 1 ELSE 0 END),
                SUM(CASE WHEN category='Navigation web'  THEN 1 ELSE 0 END),
                SUM(CASE WHEN category='Suspect'         THEN 1 ELSE 0 END),
                SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END),
                SUM(CASE WHEN action='Block' THEN 1 ELSE 0 END),
                SUM(CASE WHEN action='Limit' THEN 1 ELSE 0 END),
                SUM(CASE WHEN action='Log'   THEN 1 ELSE 0 END),
                AVG(decision_latency_ms),
                MAX(decision_latency_ms)
            FROM classified_flows
            WHERE timestamp > datetime('now', '-1 minute')
        """)


def get_stats_history(minutes: int = 60) -> list[dict]:
    """
    Retourne les stats par minute pour le graphique timeline.
    Appelé par l'API /api/stats/history.
    """
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM stats_per_minute "
            "ORDER BY timestamp DESC LIMIT ?",
            (minutes,)
        ).fetchall()
        return [dict(r) for r in rows]


def run_aggregation_loop(interval: int = 60):
    """
    Boucle d'agrégation le lancer dans un thread daemon.
    Appelé par core/pipeline.py au démarrage :
        threading.Thread(target=run_aggregation_loop, daemon=True).start()
    """
    while True:
        time.sleep(interval)
        try:
            aggregate_current_minute()
        except Exception as e:
            print(f"Erreur agrégation stats : {e}")


# =============================================================================
# POLITIQUES
# Appelé par : core/policy_engine.py, web/api.py (gestion règles)
# =============================================================================

def get_policy(profile: str, category: str) -> dict | None:
    """
    Retourne la règle de politique applicable.
    Prend en compte les règles horaires (priorité plus élevée).

    Appelé par core/policy_engine.py pour chaque flux classifié.
    """
    now = datetime.now().strftime("%H:%M")

    with get_db() as conn:
        # Chercher d'abord une règle horaire active (priorité haute)
        row = conn.execute("""
            SELECT action, bandwidth_kbps, time_start, time_end
            FROM policy_rules
            WHERE profile = ? AND category = ? AND is_active = 1
              AND time_start IS NOT NULL AND time_end IS NOT NULL
              AND ? BETWEEN time_start AND time_end
            ORDER BY priority DESC
            LIMIT 1
        """, (profile, category, now)).fetchone()

        if row:
            return {
                "action": row["action"],
                "bandwidth_kbps": row["bandwidth_kbps"],
                "reason": f"Règle horaire {row['time_start']}-{row['time_end']}",
            }

        # Sinon, règle par défaut (sans horaire)
        row = conn.execute("""
            SELECT action, bandwidth_kbps
            FROM policy_rules
            WHERE profile = ? AND category = ? AND is_active = 1
              AND time_start IS NULL
            ORDER BY priority DESC
            LIMIT 1
        """, (profile, category)).fetchone()

        if row:
            return {
                "action": row["action"],
                "bandwidth_kbps": row["bandwidth_kbps"],
                "reason": f"Politique {profile}/{category}",
            }

        # Aucune règle trouvée : Allow par défaut
        return {"action": "Allow", "bandwidth_kbps": None, "reason": "Aucune règle"}


def get_all_policies() -> list[dict]:
    """Toutes les règles (pour la page Politiques du dashboard)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM policy_rules ORDER BY profile, priority DESC, category"
        ).fetchall()
        return [dict(r) for r in rows]


def update_policy(rule_id: int, action: str, bandwidth_kbps: int | None = None,
                  is_active: bool = True):
    """Modifier une règle existante depuis le dashboard."""
    with get_db() as conn:
        conn.execute(
            "UPDATE policy_rules SET action=?, bandwidth_kbps=?, is_active=?, "
            "updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (action, bandwidth_kbps, is_active, rule_id)
        )


# =============================================================================
# JOURNAL D'ACCÈS
# Appelé par : web/auth.py (login/logout), fonctions internes
# =============================================================================

def log_access(ip_address: str, username: str, event: str,
               details: str = "", conn=None):
    """
    Enregistre un événement dans le journal.
    Accepte une connexion existante (pour éviter d'en ouvrir une nouvelle
    dans une transaction d'erreur en cours).
    """
    if conn:
        conn.execute(
            "INSERT INTO access_log (ip_address, username, event, details) "
            "VALUES (?, ?, ?, ?)",
            (ip_address, username, event, details)
        )
    else:
        with get_db() as c:
            c.execute(
                "INSERT INTO access_log (ip_address, username, event, details) "
                "VALUES (?, ?, ?, ?)",
                (ip_address, username, event, details)
            )


def get_access_logs(limit: int = 200) -> list[dict]:
    """Retourne les derniers événements du journal."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM access_log ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


# =============================================================================
# ALERTES
# Appelé par : core/pipeline.py (flux suspects), web/api.py (lecture)
# =============================================================================

def create_alert(severity: str, source: str, title: str,
                 message: str = "", ip_address: str = "",
                 username: str = "", conn=None):
    """Crée une alerte dans la base."""
    sql = ("INSERT INTO alerts (severity, source, title, message, "
           "ip_address, username) VALUES (?, ?, ?, ?, ?, ?)")
    params = (severity, source, title, message, ip_address, username)

    if conn:
        conn.execute(sql, params)
    else:
        with get_db() as c:
            c.execute(sql, params)


def get_unread_alerts() -> list[dict]:
    """Alertes non lues (pour le bandeau du dashboard)."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM alerts WHERE is_read = 0 "
            "ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        return [dict(r) for r in rows]


def mark_alert_read(alert_id: int):
    """Marquer une alerte comme lue."""
    with get_db() as conn:
        conn.execute("UPDATE alerts SET is_read = 1 WHERE id = ?", (alert_id,))


# =============================================================================
# NETTOYAGE
# Appelé par : thread de maintenance (périodique)
# =============================================================================

def cleanup_old_data(flow_days: int = 7, stats_days: int = 30,
                     log_days: int = 90):
    """
    Supprime les données anciennes pour éviter que la BDD grossisse indéfiniment.
    Appelé une fois par jour par un thread de maintenance.

    Paramètres par défaut :
        - Flux classifiés : garder 7 jours
        - Stats par minute : garder 30 jours
        - Logs d'accès    : garder 90 jours
    """
    with get_db() as conn:
        conn.execute("DELETE FROM classified_flows WHERE timestamp < datetime('now', ?)",
                     (f"-{flow_days} days",))
        conn.execute("DELETE FROM stats_per_minute WHERE timestamp < datetime('now', ?)",
                     (f"-{stats_days} days",))
        conn.execute("DELETE FROM access_log WHERE timestamp < datetime('now', ?)",
                     (f"-{log_days} days",))

        # Nettoyer les sessions expirées
        cleanup_expired_sessions()

        # Résoudre les vieilles alertes
        conn.execute(
            "UPDATE alerts SET resolved_at = CURRENT_TIMESTAMP "
            "WHERE resolved_at IS NULL AND timestamp < datetime('now', '-1 day')"
        )

        # Compacter la base
        conn.execute("VACUUM")


def run_cleanup_loop(interval_hours: int = 24):
    """
    Boucle de nettoyage le lancer dans un thread daemon.
    Appelé par core/pipeline.py au démarrage :
        threading.Thread(target=run_cleanup_loop, daemon=True).start()
    """
    while True:
        time.sleep(interval_hours * 3600)
        try:
            cleanup_old_data()
            print(f"\u2705 Nettoyage BDD effectué")
        except Exception as e:
            print(f"Erreur nettoyage : {e}")


# =============================================================================
# TEST RAPIDE
# =============================================================================

if __name__ == "__main__":
    """Test rapide : initialiser la BDD et afficher les tables."""
    init_db()

    print("\n--- Utilisateurs ---")
    for u in get_all_users():
        print(f"  {u['username']:10s} | {u['profile']:12s} | {u['full_name']}")

    print("\n--- Politiques (étudiant) ---")
    for cat in ["Streaming", "R\u00e9seaux sociaux", "Publicit\u00e9",
                "T\u00e9l\u00e9chargement", "Navigation web", "Suspect"]:
        p = get_policy("etudiant", cat)
        print(f"  {cat:20s} \u2192 {p['action']:6s} | {p['reason']}")

    print(f"\n\u2705 Tout fonctionne. BDD : {DB_PATH}")