# Paramètres système
# config/settings.py
import os
from dotenv import load_dotenv

load_dotenv()  # Charge .env

# Réseau
CAPTURE_INTERFACE = os.getenv("INTERFACE", "br0")
LAN_SUBNET = "192.168.1.0/24"
GATEWAY_IP = "192.168.1.1"

# Base de données
DB_PATH = os.getenv("DB_PATH", "/opt/netclassifier/db/netclassifier.db")

# Web
WEB_PORT = int(os.getenv("WEB_PORT", 2003))
SECRET_KEY = os.getenv("SECRET_KEY", "pfe_default_secret")

# ML
MODEL_PATH = "ml/models/classifier.joblib"
SCALER_PATH = "ml/models/scaler.joblib"
LABEL_ENCODER_PATH = "ml/models/label_encoder.joblib"

# NFStream
IDLE_TIMEOUT = 15       # secondes
ACTIVE_TIMEOUT = 120    # secondes
N_DISSECTIONS = 20      # profondeur DPI nDPI

# Performance
MAX_DECISION_LATENCY_MS = 200   # Seuil d'alerte
RESOLVER_CACHE_TTL = 30         # Rafraîchissement cache sessions
STATS_PUSH_INTERVAL = 5         # Push stats vers dashboard (secondes)
