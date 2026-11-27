"""Prépare l'environnement local : users.json et dataset.csv.

Usage (depuis la racine du projet, venv activé) :
    python setup_local.py
"""
import json
from getpass import getpass
from pathlib import Path

import numpy as np
import pandas as pd
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
USERS_FILE = BASE_DIR / "users.json"
DATASET_FILE = BASE_DIR / "dataset.csv"

ROLES = ["employee", "manager", "security_officer", "dlp_admin"]


def create_users():
    if USERS_FILE.exists():
        print(f"[=] {USERS_FILE.name} existe déjà, conservé.")
        return

    users = {}
    print("Création des comptes (laissez le nom vide pour terminer).")
    while True:
        name = input("Nom d'utilisateur : ").strip()
        if not name:
            break
        role = input(f"Rôle {ROLES} [employee] : ").strip() or "employee"
        if role not in ROLES:
            print("Rôle invalide, recommencez.")
            continue
        password = getpass("Mot de passe : ")
        if len(password) < 8:
            print("8 caractères minimum, recommencez.")
            continue
        users[name] = {
            "password_hash": generate_password_hash(password),
            "role": role,
        }

    if not users:
        print("[!] Aucun compte créé.")
        return

    USERS_FILE.write_text(
        json.dumps(users, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    print(f"[+] {USERS_FILE.name} créé ({len(users)} compte(s)).")


def create_dataset():
    if DATASET_FILE.exists():
        print(f"[=] {DATASET_FILE.name} existe déjà, conservé.")
        return

    rng = np.random.default_rng(42)
    n = 500
    pd.DataFrame({
        "file_size": rng.lognormal(11, 1.0, n).astype(int),
        "external": rng.integers(0, 2, n),
        "transfer_frequency": rng.integers(1, 6, n),
        "sensitivity": rng.integers(1, 5, n),
    }).to_csv(DATASET_FILE, index=False)
    print(f"[+] {DATASET_FILE.name} créé (jeu synthétique de démonstration).")


if __name__ == "__main__":
    create_users()
    create_dataset()