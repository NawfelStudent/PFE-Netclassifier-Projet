# Script principal pour démarrer, arrêter ou initialiser le projet

# manage.py
import sys
import subprocess

def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"
    
    if cmd == "init":
# Créer la BDD + utilisateurs de test
from db.database import init_db
init_db()
print("Base de données initialisée")

    elif cmd == "start-web":
subprocess.run(["python3", "-m", "web.app"])

    elif cmd == "start-capture":
subprocess.run(["sudo", "python3", "-m", "core.pipeline"])

    elif cmd == "train":
subprocess.run(["python3", "-m", "ml.train_model"])

    elif cmd == "setup-network":
subprocess.run(["sudo", "bash", "services/setup_network.sh"])

    else:
print("Usage: python manage.py [init|start-web|start-capture|train|setup-network]")

if __name__ == "__main__":
    main()