#!/usr/bin/env python3
"""
real_time_classifier.py
─────────────────────────
Système de classification et contrôle du trafic réseau en temps réel.
Conforme au pipeline FlowFrontiers/ml-flow-class-tutorial, adapté pour
la capture live et l'application de politiques dynamiques.

Prérequis :
    pip install nfstream pandas scikit-learn joblib
    # Exécuter en root/sudo pour capturer sur l'interface réseau

Usage :
    sudo python3 real_time_classifier.py --interface eth0
    sudo python3 real_time_classifier.py --interface wlan0 --model mon_modele.joblib
"""

import argparse
import time
import logging
import json
import subprocess
import os
from datetime import datetime
from pathlib import Path

import pandas as pd
import numpy as np
from nfstream import NFStreamer

# ─── Logging ──────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("traffic_classifier")


# ══════════════════════════════════════════════════════════════════════
# 1. FEATURES — alignées sur le tutorial FlowFrontiers (notebook 01)
# ══════════════════════════════════════════════════════════════════════

# Features statistiques bidirectionnelles extraites par NFStream
# (identiques à celles du tutorial avec statistical_analysis=True)
STATISTICAL_FEATURES = [
    # --- Durée et volume (core features du tutorial) ---
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",

    # --- Statistiques de taille de paquets (statistical_analysis) ---
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_stddev_ps",
    "bidirectional_max_ps",
    "src2dst_min_ps",
    "src2dst_mean_ps",
    "src2dst_stddev_ps",
    "src2dst_max_ps",
    "dst2src_min_ps",
    "dst2src_mean_ps",
    "dst2src_stddev_ps",
    "dst2src_max_ps",

    # --- Inter-arrival time (statistical_analysis) ---
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_max_piat_ms",
    "src2dst_min_piat_ms",
    "src2dst_mean_piat_ms",
    "src2dst_stddev_piat_ms",
    "src2dst_max_piat_ms",
    "dst2src_min_piat_ms",
    "dst2src_mean_piat_ms",
    "dst2src_stddev_piat_ms",
    "dst2src_max_piat_ms",

    # --- Flags TCP (utiles pour détection anomalies) ---
    "bidirectional_syn_packets",
    "bidirectional_fin_packets",
    "bidirectional_rst_packets",
    "bidirectional_psh_packets",
]

# Features dérivées calculées manuellement (cahier des charges)
DERIVED_FEATURES = [
    "bytes_per_second",
    "packets_per_second",
    "bytes_ratio",       # ratio src2dst/dst2src bytes
    "packets_ratio",     # ratio src2dst/dst2src packets
]

ALL_FEATURES = STATISTICAL_FEATURES + DERIVED_FEATURES


# ══════════════════════════════════════════════════════════════════════
# 2. EXTRACTION DE FEATURES — depuis un objet NFlow
# ══════════════════════════════════════════════════════════════════════

def extract_features(flow) -> dict:
    """
    Extrait les features d'un objet NFlow NFStream.
    Aligné sur le pipeline du tutorial (statistical + SPLT features)
    avec ajout des features dérivées du cahier des charges.
    """
    feat = {}

    # Features statistiques natives NFStream
    for f in STATISTICAL_FEATURES:
        feat[f] = getattr(flow, f, 0)

    # Features dérivées (cahier des charges : débit, ratios)
    duration_s = max(feat["bidirectional_duration_ms"] / 1000.0, 0.001)
    feat["bytes_per_second"] = feat["bidirectional_bytes"] / duration_s
    feat["packets_per_second"] = feat["bidirectional_packets"] / duration_s

    dst_bytes = feat["dst2src_bytes"] if feat["dst2src_bytes"] > 0 else 1
    dst_pkts = feat["dst2src_packets"] if feat["dst2src_packets"] > 0 else 1
    feat["bytes_ratio"] = feat["src2dst_bytes"] / dst_bytes
    feat["packets_ratio"] = feat["src2dst_packets"] / dst_pkts

    return feat


def extract_metadata(flow) -> dict:
    """
    Extrait les métadonnées non-ML du flux (identifiants, DPI, SNI).
    Utilisées pour le logging, l'affichage et les règles basées sur domaine.
    """
    return {
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "application_name": getattr(flow, "application_name", "Unknown"),
        "application_category_name": getattr(flow, "application_category_name", "Unknown"),
        "requested_server_name": getattr(flow, "requested_server_name", ""),  # SNI
        "bidirectional_duration_ms": flow.bidirectional_duration_ms,
        "bidirectional_bytes": flow.bidirectional_bytes,
    }


# ══════════════════════════════════════════════════════════════════════
# 3. MOTEUR DE POLITIQUES — cahier des charges (couche décision)
# ══════════════════════════════════════════════════════════════════════

# Profils utilisateurs avec politiques par catégorie
DEFAULT_POLICIES = {
    "etudiant": {
        "Streaming":       {"action": "Limit", "bandwidth_kbps": 500},
        "Réseaux sociaux": {"action": "Allow"},
        "Publicité":       {"action": "Block"},
        "Téléchargement":  {"action": "Limit", "bandwidth_kbps": 200},
        "Navigation web":  {"action": "Allow"},
        "Suspect":         {"action": "Block"},
        "_default":        {"action": "Allow"},
    },
    "employe": {
        "Streaming":       {"action": "Limit", "bandwidth_kbps": 1000},
        "Réseaux sociaux": {"action": "Limit", "bandwidth_kbps": 500},
        "Publicité":       {"action": "Block"},
        "Téléchargement":  {"action": "Allow"},
        "Navigation web":  {"action": "Allow"},
        "Suspect":         {"action": "Block"},
        "_default":        {"action": "Allow"},
    },
    "admin": {
        "_default":        {"action": "Allow"},
    },
    "invite": {
        "Streaming":       {"action": "Block"},
        "Réseaux sociaux": {"action": "Limit", "bandwidth_kbps": 200},
        "Publicité":       {"action": "Block"},
        "Téléchargement":  {"action": "Block"},
        "Navigation web":  {"action": "Allow"},
        "Suspect":         {"action": "Block"},
        "_default":        {"action": "Log"},
    },
    "restricted": {
        "Navigation web":  {"action": "Allow"},
        "_default":        {"action": "Block"},
    },
}

# Règles horaires (optionnel)
TIME_RULES = {
    "etudiant": {
        "Streaming": {
            "blocked_hours": (8, 17),   # Bloqué pendant les heures de cours
        }
    }
}


def get_policy_decision(category: str, profile: str = "etudiant",
                        sni: str = "") -> dict:
    """
    Détermine l'action à appliquer sur un flux classifié.
    Basé sur : catégorie ML + profil utilisateur + horaire + domaine/SNI.
    """
    policies = DEFAULT_POLICIES.get(profile, DEFAULT_POLICIES["etudiant"])

    # 1. Vérifier règle horaire
    hour = datetime.now().hour
    time_rule = TIME_RULES.get(profile, {}).get(category, {})
    if "blocked_hours" in time_rule:
        start, end = time_rule["blocked_hours"]
        if start <= hour < end:
            return {"action": "Block", "reason": f"Horaire restreint ({start}h-{end}h)"}

    # 2. Règles spécifiques par domaine/SNI
    BLOCKED_DOMAINS = ["ads.", "tracker.", "analytics.", "doubleclick."]
    if sni and any(blocked in sni.lower() for blocked in BLOCKED_DOMAINS):
        return {"action": "Block", "reason": f"Domaine bloqué: {sni}"}

    # 3. Politique par catégorie
    policy = policies.get(category, policies.get("_default", {"action": "Allow"}))
    return {**policy, "reason": f"Politique {profile}/{category}"}


def enforce_action(decision: dict, flow_metadata: dict):
    """
    Applique la décision de politique.
    En prototype : log + (optionnel) iptables pour Block.
    """
    action = decision["action"]
    dst_ip = flow_metadata["dst_ip"]
    dst_port = flow_metadata["dst_port"]

    if action == "Block":
        log.warning(f" BLOCK  {dst_ip}:{dst_port} — {decision['reason']}")
        # Décommenter pour appliquer réellement via iptables :
        # subprocess.run(
        #     ["iptables", "-A", "OUTPUT", "-d", dst_ip,
        #      "--dport", str(dst_port), "-j", "DROP"],
        #     capture_output=True
        # )

    elif action == "Limit":
        bw = decision.get("bandwidth_kbps", 500)
        log.info(f"LIMIT  {dst_ip}:{dst_port} → {bw} kbps — {decision['reason']}")
        # Décommenter pour tc (traffic control) :
        # subprocess.run(["tc", "qdisc", "add", ...])  # traffic shaping

    elif action == "Log":
        log.info(f" LOG    {dst_ip}:{dst_port} — {decision['reason']}")

    else:  # Allow
        log.debug(f" ALLOW  {dst_ip}:{dst_port}")


# ══════════════════════════════════════════════════════════════════════
# 4. MODÈLE ML — chargement ou création d'un modèle de démonstration
# ══════════════════════════════════════════════════════════════════════

def load_or_create_model(model_path: str = None):
    """
    Charge un modèle pré-entraîné (.joblib) ou crée un modèle
    de démonstration basé sur des heuristiques.

    Pour entraîner un vrai modèle, utilisez les notebooks 02-05
    du tutorial FlowFrontiers, puis exportez avec :
        joblib.dump(trained_model, 'classifier.joblib')
    """
    if model_path and Path(model_path).exists():
        import joblib
        log.info(f"Chargement du modèle: {model_path}")
        model = joblib.load(model_path)
        return model, "ml"

    log.warning("Aucun modèle ML fourni — utilisation du classifieur heuristique de démonstration")
    return None, "heuristic"


def classify_heuristic(features: dict, metadata: dict) -> tuple:
    """
    Classifieur heuristique de démonstration.
    Remplacer par le vrai modèle ML (Random Forest, etc.).
    Retourne (catégorie, score_confiance).
    """
    app_name = metadata.get("application_name", "").lower()
    sni = metadata.get("requested_server_name", "").lower()
    dst_port = metadata.get("dst_port", 0)
    bps = features.get("bytes_per_second", 0)
    duration = features.get("bidirectional_duration_ms", 0)

    # Heuristiques basées sur nDPI + features statistiques
    streaming_keywords = ["youtube", "netflix", "twitch", "spotify", "video",
                         "stream", "tiktok", "deezer", "prime"]
    social_keywords = ["facebook", "instagram", "twitter", "whatsapp",
                      "telegram", "snapchat", "linkedin", "discord"]
    ad_keywords = ["ads", "ad.", "doubleclick", "adservice", "tracker",
                  "analytics", "pixel", "advertising"]

    combined = f"{app_name} {sni}"

    if any(kw in combined for kw in ad_keywords):
        return "Publicité", 0.85
    if any(kw in combined for kw in streaming_keywords):
        return "Streaming", 0.80
    if any(kw in combined for kw in social_keywords):
        return "Réseaux sociaux", 0.80

    # Patterns statistiques
    # Streaming : haut débit, longue durée
    if bps > 500_000 and duration > 10_000:
        return "Streaming", 0.65
    # Téléchargement : fort volume, asymétrique
    if (features.get("dst2src_bytes", 0) > 1_000_000
            and features.get("bytes_ratio", 1) < 0.1):
        return "Téléchargement", 0.60
    # Suspect : burst de SYN/RST, pattern atypique
    syn = features.get("bidirectional_syn_packets", 0)
    rst = features.get("bidirectional_rst_packets", 0)
    if syn > 5 or rst > 5:
        return "Suspect", 0.70

    # Ports HTTP/HTTPS → Navigation web
    if dst_port in (80, 443, 8080, 8443):
        return "Navigation web", 0.55

    return "Navigation web", 0.40


def classify_flow(features: dict, metadata: dict, model, model_type: str) -> tuple:
    """
    Point d'entrée de classification.
    Retourne (catégorie, score_confiance).
    """
    if model_type == "ml" and model is not None:
        # Modèle ML réel (Random Forest, SVM, etc.)
        feature_vector = pd.DataFrame([features])[ALL_FEATURES]
        feature_vector = feature_vector.fillna(0)

        prediction = model.predict(feature_vector)[0]
        confidence = max(model.predict_proba(feature_vector)[0])
        return prediction, confidence
    else:
        return classify_heuristic(features, metadata)


# ══════════════════════════════════════════════════════════════════════
# 5. BOUCLE PRINCIPALE — capture et classification temps réel
# ══════════════════════════════════════════════════════════════════════

def run_realtime_classifier(interface: str, model_path: str = None,
                            profile: str = "etudiant",
                            idle_timeout: int = 15,
                            active_timeout: int = 120):
    """
    Lance la capture et classification en temps réel.

    Paramètres NFStream alignés sur les recommandations du tutorial :
    - statistical_analysis=True : active les features stat (ps, piat)
    - n_dissections=20 : DPI pour labelling nDPI (SNI, app_name)
    - idle_timeout / active_timeout : expiration des flux
    """
    model, model_type = load_or_create_model(model_path)

    log.info(f"═══ Démarrage capture temps réel sur '{interface}' ═══")
    log.info(f"Profil actif : {profile}")
    log.info(f"Type classifieur : {model_type}")
    log.info(f"Timeouts : idle={idle_timeout}s, active={active_timeout}s")
    log.info("Ctrl+C pour arrêter\n")

    # ── NFStreamer en mode live ──
    # Même configuration que le tutorial, mais source = interface live
    streamer = NFStreamer(
        source=interface,                  # Interface live (au lieu de PCAP)
        n_meters=1,                        # Mono-thread pour stabilité prototype
        n_dissections=20,                  # DPI nDPI activé (SNI, app detection)
        statistical_analysis=True,         # Features statistiques (comme le tutorial)
        idle_timeout=idle_timeout,          # Expiration flux inactif (sec)
        active_timeout=active_timeout,      # Expiration flux actif (sec)
    )

    # Compteurs pour statistiques
    stats = {
        "total_flows": 0,
        "categories": {},
        "actions": {"Allow": 0, "Block": 0, "Limit": 0, "Log": 0},
        "start_time": time.time(),
    }

    try:
        # Itération flow-by-flow (méthode temps réel du tutorial)
        for flow in streamer:
            t_start = time.time()

            # 1. Extraction features (couche feature engineering)
            features = extract_features(flow)
            metadata = extract_metadata(flow)

            # 2. Classification ML (couche IA)
            category, confidence = classify_flow(
                features, metadata, model, model_type
            )

            # 3. Décision politique (couche décision)
            sni = metadata.get("requested_server_name", "")
            decision = get_policy_decision(category, profile, sni)

            # 4. Application de la politique (couche enforcement)
            enforce_action(decision, metadata)

            # 5. Mesure latence de décision
            latency_ms = (time.time() - t_start) * 1000

            # 6. Log détaillé
            stats["total_flows"] += 1
            stats["categories"][category] = stats["categories"].get(category, 0) + 1
            stats["actions"][decision["action"]] = stats["actions"].get(decision["action"], 0) + 1

            # Affichage console
            app_label = metadata["application_name"]
            sni_label = f" [{sni}]" if sni else ""
            log.info(
                f"Flow #{stats['total_flows']:>5d} | "
                f"{metadata['src_ip']}:{metadata['src_port']} → "
                f"{metadata['dst_ip']}:{metadata['dst_port']} | "
                f"App={app_label}{sni_label} | "
                f"Cat={category} ({confidence:.0%}) | "
                f"Action={decision['action']} | "
                f"Latence={latency_ms:.1f}ms"
            )

            # Alerte si latence > seuil cahier des charges
            if latency_ms > 200:
                log.warning(f"⚠ Latence décision {latency_ms:.1f}ms > 200ms !")

    except KeyboardInterrupt:
        log.info("\n═══ Arrêt demandé ═══")

    # ── Statistiques finales ──
    elapsed = time.time() - stats["start_time"]
    log.info(f"\n{'═'*60}")
    log.info(f"Durée session       : {elapsed:.0f}s")
    log.info(f"Flux traités        : {stats['total_flows']}")
    log.info(f"Flux/seconde        : {stats['total_flows']/max(elapsed,1):.1f}")
    log.info(f"Catégories          : {json.dumps(stats['categories'], indent=2, ensure_ascii=False)}")
    log.info(f"Actions appliquées  : {json.dumps(stats['actions'], indent=2)}")
    log.info(f"{'═'*60}")


# ══════════════════════════════════════════════════════════════════════
# 6. POINT D'ENTRÉE
# ══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Classification et contrôle du trafic réseau en temps réel"
    )
    parser.add_argument(
        "--interface", "-i", default="br0",
        help="Interface réseau à capturer (défaut: eth0)"
    )
    parser.add_argument(
        "--model", "-m", default=None,
        help="Chemin vers le modèle ML (.joblib) — si absent, mode heuristique"
    )
    parser.add_argument(
        "--profile", "-p", default="etudiant",
        choices=["etudiant", "employe", "admin", "invite", "restricted"],
        help="Profil utilisateur pour les politiques (défaut: etudiant)"
    )
    parser.add_argument(
        "--idle-timeout", type=int, default=15,
        help="Idle timeout en secondes (défaut: 15)"
    )
    parser.add_argument(
        "--active-timeout", type=int, default=120,
        help="Active timeout en secondes (défaut: 120)"
    )
    args = parser.parse_args()

    run_realtime_classifier(
        interface=args.interface,
        model_path=args.model,
        profile=args.profile,
        idle_timeout=args.idle_timeout,
        active_timeout=args.active_timeout,
    )

    """
    Pour connecter votre modèle ML entraîné (après les notebooks 02-05 du tutorial) :

    # Dans le notebook d'entraînement, après le fit :
    import joblib
    joblib.dump(trained_rf_model, "classifier.joblib")

    # Puis lancer :
    # sudo python3 real_time_classifier.py -i eth0 -m classifier.joblib -p etudiant
# """