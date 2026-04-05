-- =============================================================================
-- db/schema.sql  Schéma complet de la base NetClassifier
-- =============================================================================
-- Exécuter une seule fois avec : sqlite3 db/netclassifier.db < db/schema.sql
-- Ou via Python : db.database.init_db()
-- =============================================================================

-- Active le mode WAL pour permettre les lectures parallèles aux écritures.
-- Critique car le classifieur écrit en continu pendant que le dashboard lit.
PRAGMA journal_mode = 'WAL';
PRAGMA foreign_keys = ON;


-- =============================================================================
-- TABLE 1 : users
-- Rôle : Annuaire des utilisateurs autorisés à se connecter au réseau.
-- Écrit par : Dashboard admin (création/modification de comptes)
-- Lu par    : Portail captif (vérification login/mot de passe)
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    UNIQUE NOT NULL,               -- Identifiant de connexion
    password_hash   TEXT    NOT NULL,                      -- Hash bcrypt/scrypt (jamais en clair)
    full_name       TEXT    DEFAULT '',                    -- Nom affiché ("Ahmed Benali")
    email           TEXT    DEFAULT '',                    -- Optionnel, pour notifications
    profile         TEXT    NOT NULL DEFAULT 'invite',     -- Profil de politique :
                                                            --   'etudiant', 'employe', 'admin',
                                                            --   'invite', 'restricted'
    is_active       BOOLEAN NOT NULL DEFAULT 1,            -- 0 = compte d'abandon sans le supprimer
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Contrainte : profil doit être un des 5 profils
    CHECK (profile IN ('etudiant', 'employe', 'admin', 'invite', 'restricted'))
);

-- Index pour recherche rapide au login
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);


-- =============================================================================
-- TABLE 2 : active_sessions
-- Rôle : Lie une IP à un utilisateur authentifié ("qui est connecté maintenant").
--        C'est LE pont entre le portail captif et le classifieur.
-- Écrit par : Portail captif (INSERT au login, DELETE au logout)
-- Lu par    : Classifieur via CaptivePortalResolver (IP à profil)
--             Dashboard (page "Utilisateurs connectés")
-- =============================================================================

CREATE TABLE IF NOT EXISTS active_sessions (
    ip_address      TEXT    PRIMARY KEY,                   -- Clé = IP du client (une seule session/IP)
    user_id         INTEGER NOT NULL,                      -- Référence vers users.id
    username        TEXT    NOT NULL,                      -- Normalisé pour éviter un JOIN à chaque flux
    profile         TEXT    NOT NULL,                      -- Profil de l'utilisateur
    mac_address     TEXT    DEFAULT '',                    -- Adresse MAC associée
    login_time      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- Heure de connexion
    expires_at      TIMESTAMP NOT NULL                     -- Expiration de la session
);

-- Le classifieur fait ce SELECT à chaque flux :
--   SELECT username, profile FROM active_sessions WHERE ip_address = '192.168.1.10'
-- L'index est automatique sur ip_address car c'est la PRIMARY KEY.


-- =============================================================================
-- TABLE 3 : classified_flows
-- Rôle : Historique de TOUS les flux classifiés par le système.
--        Chaque ligne = un flux réseau qui a traversé la passerelle.
-- Écrit par : Classifieur (INSERT à chaque flux expiré par NFStream)
-- Lu par    : Dashboard (tableau live, graphiques, KPI, page journal)
--             API REST (/api/flows/recent, /api/stats/realtime)
-- =============================================================================

CREATE TABLE IF NOT EXISTS classified_flows (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- Heure de capture
    src_ip          TEXT,                                  -- IP source
    dst_ip          TEXT,                                  -- IP destination
    src_port        INTEGER,                               -- Port source
    dst_port        INTEGER,                               -- Port destination
    protocol        INTEGER,                               -- Protocole (TCP/UDP)
    application_name TEXT DEFAULT 'Unknown',               -- Application détectée
    sni             TEXT DEFAULT '',                       -- Nom de domaine (SNI)
    category        TEXT NOT NULL,                         -- Catégorie (Streaming, Web...)
    confidence      REAL DEFAULT 0.0,                      -- Confiance du classifieur
    action          TEXT NOT NULL,                         -- Action (Allow, Block...)
    action_detail   TEXT DEFAULT '',                       -- Détails de l'action
    username        TEXT DEFAULT 'Inconnu',                -- Utilisateur associé
    profile         TEXT DEFAULT 'invite',                 -- Profil associé
    bytes_total     INTEGER DEFAULT 0,                     -- Total des octets
    packets_total   INTEGER DEFAULT 0,                     -- Total des paquets
    duration_ms     INTEGER DEFAULT 0,                     -- Durée en millisecondes
    bytes_per_second REAL DEFAULT 0.0,                     -- Débit moyen
    decision_latency_ms REAL DEFAULT 0.0                   -- Latence de décision
);

-- Index pour les requêtes fréquentes du dashboard
CREATE INDEX IF NOT EXISTS idx_flows_timestamp  ON classified_flows(timestamp);
CREATE INDEX IF NOT EXISTS idx_flows_category   ON classified_flows(category);
CREATE INDEX IF NOT EXISTS idx_flows_action     ON classified_flows(action);
CREATE INDEX IF NOT EXISTS idx_flows_username   ON classified_flows(username);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip     ON classified_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_sni        ON classified_flows(sni);

-- Index composite pour la requête la plus fréquente du dashboard :
-- "stats de la dernière minute groupées par catégorie"
CREATE INDEX IF NOT EXISTS idx_flows_ts_cat
    ON classified_flows(timestamp, category);

-- =============================================================================
-- TABLE 4 : stats_per_minute
-- Rôle : Statistiques pré-calculées (agrégées par minute).
--        Évite de scanner classified_flows à chaque rafraîchissement du dashboard.
-- Écrit par : Thread d'agrégation (toutes les 60 secondes)
-- Lu par    : Dashboard (graphique timeline "trafic sur la dernière heure")
-- =============================================================================

CREATE TABLE IF NOT EXISTS stats_per_minute (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- Minute de l'agrégation
    total_flows     INTEGER DEFAULT 0,                     -- Total des flux
    total_bytes     INTEGER DEFAULT 0,                     -- Total des octets
    active_users    INTEGER DEFAULT 0,                     -- Utilisateurs actifs
    cat_streaming   INTEGER DEFAULT 0,                     -- Flux Streaming
    cat_social      INTEGER DEFAULT 0,                     -- Flux Réseaux sociaux
    cat_ads         INTEGER DEFAULT 0,                     -- Flux Publicité
    cat_download    INTEGER DEFAULT 0,                     -- Flux Téléchargement
    cat_web         INTEGER DEFAULT 0,                     -- Flux Web
    cat_suspect     INTEGER DEFAULT 0,                     -- Flux suspects
    action_allow    INTEGER DEFAULT 0,                     -- Actions autorisées
    action_block    INTEGER DEFAULT 0,                     -- Actions bloquées
    action_limit    INTEGER DEFAULT 0,                     -- Actions limitées
    avg_latency_ms  REAL DEFAULT 0.0                       -- Latence moyenne
);

CREATE INDEX IF NOT EXISTS idx_stats_timestamp
    ON stats_per_minute(timestamp);

-- =============================================================================
-- TABLE 5 : access_log
-- Rôle : Journal de sécurité et d'audit.
--        Enregistre toutes les connexions, déconnexions, et tentatives échouées.
-- Écrit par : Portail captif (login, logout, échec, expiration)
-- Lu par    : Dashboard (page "Journal d'accès")
-- =============================================================================

CREATE TABLE IF NOT EXISTS access_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,   -- Heure de l'événement
    ip_address      TEXT DEFAULT '',                       -- IP associée
    username        TEXT DEFAULT '',                       -- Utilisateur associé
    event           TEXT NOT NULL,                         -- Type d'événement
    details         TEXT DEFAULT ''                        -- Détails supplémentaires
);

CREATE INDEX IF NOT EXISTS idx_access_timestamp ON access_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_access_username  ON access_log(username);
CREATE INDEX IF NOT EXISTS idx_access_event     ON access_log(event);

-- =============================================================================
-- TABLE 6 : policy_rules (optionnel à avantage : politiques en BDD au lieu de JSON)
-- Rôle : Stocke les règles de politique dynamiquement modifiables depuis le dashboard.
--        Alternative/complément au fichier config/policies.json.
-- Écrit par : Dashboard admin (page "Politiques")
-- Lu par    : Moteur de politique (policy_engine.py)
-- =============================================================================

CREATE TABLE IF NOT EXISTS policy_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile         TEXT NOT NULL,                         -- Profil utilisateur
    category        TEXT NOT NULL,                         -- Catégorie de flux
    action          TEXT NOT NULL DEFAULT 'Allow',         -- Action (Allow, Block...)
    bandwidth_kbps  INTEGER DEFAULT NULL,                  -- Limite de bande passante
    time_start      TEXT DEFAULT NULL,                     -- Début de la règle horaire
    time_end        TEXT DEFAULT NULL,                     -- Fin de la règle horaire
    priority        INTEGER DEFAULT 0,                     -- Plus haut = prioritaire
    is_active       BOOLEAN DEFAULT 1,                     -- Activer/désactiver sans supprimer
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    -- Une seule règle par combinaison profil + catégorie + horaire
    UNIQUE(profile, category, time_start, time_end),

    CHECK (action IN ('Allow', 'Block', 'Limit', 'Log')),
    CHECK (profile IN ('etudiant', 'employe', 'admin', 'invite', 'restricted'))
);

CREATE INDEX IF NOT EXISTS idx_policy_profile ON policy_rules(profile);

-- =============================================================================
-- TABLE 7 : alerts
-- Rôle : Alertes générées par le système (anomalies, seuils dépassés).
-- Écrit par : Classifieur (flux suspects), moniteur de performance (latence)
-- Lu par    : Dashboard (bandeau d'alertes, page notifications)
-- =============================================================================

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity        TEXT    NOT NULL DEFAULT 'info',        -- 'info', 'warning', 'critical'
    source          TEXT    DEFAULT '',                     -- 'classifier', 'policy', 'system'
    title           TEXT    NOT NULL,                       -- "Flux suspect détecté"
    message         TEXT    DEFAULT '',                     -- Détails de l'alerte
    ip_address      TEXT    DEFAULT '',                     -- IP associée
    username        TEXT    DEFAULT '',                     -- Utilisateur associé
    is_read         BOOLEAN DEFAULT 0,                      -- Marqué comme lu par l'admin
    resolved_at     TIMESTAMP DEFAULT NULL,                 -- Date de résolution

    CHECK (severity IN ('info', 'warning', 'critical'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity  ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_read      ON alerts(is_read);

-- =============================================================================
-- TABLE 8 : devices (optionnel à suivi des appareils sur le LAN)
-- Rôle : Inventaire des appareils détectés sur le réseau.
--        Utile pour le device_tracker.py et le dashboard.
-- Écrit par : device_tracker.py (scan ARP périodique)
-- Lu par    : Dashboard (page "Appareils connectés")
-- =============================================================================

CREATE TABLE IF NOT EXISTS devices (
    mac_address     TEXT    PRIMARY KEY,                    -- Adresse MAC unique de l'appareil
    last_ip         TEXT    DEFAULT '',                     -- Dernière IP vue
    hostname        TEXT    DEFAULT '',                     -- Nom d'hôte (si résolu)
    vendor          TEXT    DEFAULT '',                     -- Fabricant (déduit des 3 premiers octets MAC)
    first_seen      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,    -- Première détection
    last_seen       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,    -- Dernière détection
    assigned_user   TEXT    DEFAULT NULL,                   -- Utilisateur associé manuellement
    assigned_profile TEXT   DEFAULT NULL,                   -- Profil par défaut pour cet appareil
    is_known        BOOLEAN DEFAULT 0                       -- 0 = nouveau, 1 = reconnu par l'admin
);

CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(last_ip);

-- =============================================================================
-- DONNÉES INITIALES : Utilisateurs de test
-- Les 6 comptes couvrent les 5 profils du cahier des charges + 1 supplémentaire.
-- Mots de passe hashés avec werkzeug.security.generate_password_hash().
-- En production, exécuter via db/database.py init_db() qui hash correctement.
-- =============================================================================

-- NOTE : Les hash ci-dessous sont des placeholders.
-- Le vrai hashing se fait dans database.py avec generate_password_hash().
-- Ne PAS utiliser ce SQL directement pour créer les utilisateurs.
-- Utiliser : python3 -c "from db.database import init_db; init_db()"

/*
INSERT OR IGNORE INTO users (username, password_hash, full_name, profile) VALUES
    ('ahmed',   '<hash>', 'Ahmed Benali',    'etudiant'),
    ('sara',    '<hash>', 'Sara Mansouri',    'etudiant'),
    ('prof1',   '<hash>', 'M. Dupont',        'employe'),
    ('admin',   '<hash>', 'Administrateur',   'admin'),
    ('guest01', '<hash>', 'Visiteur',          'invite'),
    ('labo',    '<hash>', 'Salle Labo',        'restricted');
*/


-- =============================================================================
-- DONNÉES INITIALES : Politiques par défaut
-- =============================================================================

INSERT OR IGNORE INTO policy_rules (profile, category, action, bandwidth_kbps) VALUES
    -- Profil étudiant
    ('etudiant', 'Streaming',       'Limit', 500),
    ('etudiant', 'Réseaux sociaux', 'Allow', NULL),
    ('etudiant', 'Publicité',       'Block', NULL),
    ('etudiant', 'Téléchargement',  'Limit', 200),
    ('etudiant', 'Navigation web',  'Allow', NULL),
    ('etudiant', 'Suspect',         'Block', NULL),

    -- Profil employé
    ('employe', 'Streaming',       'Limit', 1000),
    ('employe', 'Réseaux sociaux', 'Limit', 500),
    ('employe', 'Publicité',       'Block', NULL),
    ('employe', 'Téléchargement',  'Allow', NULL),
    ('employe', 'Navigation web',  'Allow', NULL),
    ('employe', 'Suspect',         'Block', NULL),

    -- Profil admin (tout autorisé)
    ('admin', 'Streaming',       'Allow', NULL),
    ('admin', 'Réseaux sociaux', 'Allow', NULL),
    ('admin', 'Publicité',       'Allow', NULL),
    ('admin', 'Téléchargement',  'Allow', NULL),
    ('admin', 'Navigation web',  'Allow', NULL),
    ('admin', 'Suspect',         'Log',   NULL),

    -- Profil invité
    ('invite', 'Streaming',       'Block', NULL),
    ('invite', 'Réseaux sociaux', 'Limit', 200),
    ('invite', 'Publicité',       'Block', NULL),
    ('invite', 'Téléchargement',  'Block', NULL),
    ('invite', 'Navigation web',  'Allow', NULL),
    ('invite', 'Suspect',         'Block', NULL),

    -- Profil restreint
    ('restricted', 'Streaming',       'Block', NULL),
    ('restricted', 'Réseaux sociaux', 'Block', NULL),
    ('restricted', 'Publicité',       'Block', NULL),
    ('restricted', 'Téléchargement',  'Block', NULL),
    ('restricted', 'Navigation web',  'Allow', NULL),
    ('restricted', 'Suspect',         'Block', NULL);

-- Règle horaire : étudiants ne peuvent pas streamer pendant les cours
INSERT OR IGNORE INTO policy_rules (profile, category, action, time_start, time_end, priority) VALUES
    ('etudiant', 'Streaming', 'Block', '08:00', '17:00', 10);

-- =============================================================================
-- VUES : Requêtes pré-définies utilisées par le dashboard
-- =============================================================================

-- Vue : flux de la dernière minute (pour le tableau live)
CREATE VIEW IF NOT EXISTS v_recent_flows AS
    SELECT * FROM classified_flows
    WHERE timestamp > datetime('now', '-1 minute')
    ORDER BY timestamp DESC;

-- Vue : stats temps réel (pour les KPI cards)
CREATE VIEW IF NOT EXISTS v_realtime_stats AS
    SELECT
        COUNT(*)                                          AS total_flows,
        COALESCE(SUM(bytes_total), 0)                     AS total_bytes,
        COUNT(DISTINCT src_ip)                             AS active_ips,
        SUM(CASE WHEN category='Streaming'       THEN 1 ELSE 0 END) AS streaming,
        SUM(CASE WHEN category='Réseaux sociaux' THEN 1 ELSE 0 END) AS social,
        SUM(CASE WHEN category='Publicité'       THEN 1 ELSE 0 END) AS ads,
        SUM(CASE WHEN category='Téléchargement'  THEN 1 ELSE 0 END) AS download,
        SUM(CASE WHEN category='Navigation web'  THEN 1 ELSE 0 END) AS web,
        SUM(CASE WHEN category='Suspect'         THEN 1 ELSE 0 END) AS suspect,
        SUM(CASE WHEN action='Allow' THEN 1 ELSE 0 END)  AS allow_count,
        SUM(CASE WHEN action='Block' THEN 1 ELSE 0 END)  AS block_count,
        SUM(CASE WHEN action='Limit' THEN 1 ELSE 0 END)  AS limit_count,
        AVG(decision_latency_ms)                          AS avg_latency
    FROM classified_flows
    WHERE timestamp > datetime('now', '-1 minute');

-- Vue : top consommateurs de bande passante (dernière heure)
CREATE VIEW IF NOT EXISTS v_top_users AS
    SELECT
        username,
        profile,
        COUNT(*)            AS flow_count,
        SUM(bytes_total)    AS total_bytes,
        SUM(CASE WHEN action='Block' THEN 1 ELSE 0 END) AS blocked_flows
    FROM classified_flows
    WHERE timestamp > datetime('now', '-1 hour')
    GROUP BY username
    ORDER BY total_bytes DESC;

-- Vue : top domaines visités (dernière heure)
CREATE VIEW IF NOT EXISTS v_top_domains AS
    SELECT
        sni,
        category,
        COUNT(*)            AS hit_count,
        SUM(bytes_total)    AS total_bytes,
        COUNT(DISTINCT src_ip) AS unique_users
    FROM classified_flows
    WHERE timestamp > datetime('now', '-1 hour')
      AND sni != ''
    GROUP BY sni
    ORDER BY hit_count DESC
    LIMIT 50;

-- Vue : alertes non lues
CREATE VIEW IF NOT EXISTS v_unread_alerts AS
    SELECT * FROM alerts
    WHERE is_read = 0
    ORDER BY timestamp DESC;


-- =============================================================================
-- TRIGGERS : Maintenance automatique
-- =============================================================================

-- Trigger : mettre à jour updated_at quand un utilisateur est modifié
CREATE TRIGGER IF NOT EXISTS trg_users_updated
    AFTER UPDATE ON users
    FOR EACH ROW
    BEGIN
        UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
    END;

-- Trigger : logger automatiquement les changements de profil
CREATE TRIGGER IF NOT EXISTS trg_profile_change_log
    AFTER UPDATE OF profile ON users
    WHEN OLD.profile != NEW.profile
    BEGIN
        INSERT INTO access_log (username, event, details)
        VALUES (
            NEW.username,
            'profile_changed',
            'Profil changé de ' || OLD.profile || ' vers ' || NEW.profile
        );
    END;


-- =============================================================================
-- NETTOYAGE AUTOMATIQUE
-- Note : SQLite n'a pas de cron intégré. Le nettoyage est fait
-- périodiquement par database.py cleanup_old_data().
-- Ces requêtes sont préparées ici pour référence.
-- =============================================================================

/*
-- Supprimer les flux de plus de 7 jours
DELETE FROM classified_flows WHERE timestamp < datetime('now', '-7 days');

-- Supprimer les stats de plus de 30 jours
DELETE FROM stats_per_minute WHERE timestamp < datetime('now', '-30 days');

-- Supprimer les logs d'accès de plus de 90 jours
DELETE FROM access_log WHERE timestamp < datetime('now', '-90 days');

-- Supprimer les sessions expirées
DELETE FROM active_sessions WHERE expires_at < datetime('now');

-- Résoudre automatiquement les alertes de plus de 24h
UPDATE alerts SET resolved_at = CURRENT_TIMESTAMP
WHERE resolved_at IS NULL AND timestamp < datetime('now', '-1 day');

-- Compacter la base après nettoyage
VACUUM;
*/