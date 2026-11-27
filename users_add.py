"""Ajoute (ou met à jour) un utilisateur dans users.json avec un mot de passe HACHÉ.

Usage, depuis la racine du projet (à côté de server.py) :
    python add_user.py
"""
import json
from getpass import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash

USERS_FILE = Path(__file__).resolve().parent / "users.json"
ROLES = ["employee", "manager", "security_officer", "dlp_admin"]


def load_users():
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text(encoding="utf-8-sig"))
    return {}


def main():
    users = load_users()

    while True:
        name = input("\nNom d'utilisateur (vide pour terminer) : ").strip()
        if not name:
            break

        role = input(f"Rôle {ROLES} [employee] : ").strip() or "employee"
        if role not in ROLES:
            print("Rôle invalide, recommencez.")
            continue

        password = getpass("Mot de passe (masqué) : ")
        if len(password) < 8:
            print("8 caractères minimum, recommencez.")
            continue
        if password != getpass("Confirmez le mot de passe : "):
            print("Les mots de passe ne correspondent pas, recommencez.")
            continue

        users[name] = {
            "password_hash": generate_password_hash(password),
            "role": role,
        }
        print(f"[+] {name} ({role}) ajouté.")

    USERS_FILE.write_text(
        json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"\n{len(users)} utilisateur(s) enregistré(s) dans {USERS_FILE.name}")


if __name__ == "__main__":
    main()