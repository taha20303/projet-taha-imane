"""Génère les fichiers de démonstration dans le dossier demo_files/.
Toutes les données sont FICTIVES (numéros de test publics).

Usage (racine du projet, venv activé) :
    python make_demo_files.py
"""
from pathlib import Path

from docx import Document
from openpyxl import Workbook

OUT = Path(__file__).resolve().parent / "demo_files"
OUT.mkdir(exist_ok=True)


def write(name, text):
    (OUT / name).write_text(text, encoding="utf-8")


# 1. Public : aucune donnée sensible
write("01_public_annonce.txt", (
    "COMMUNIQUE\n"
    "Notre entreprise ouvre ses portes au public le samedi 5 décembre.\n"
    "Entrée libre, visite des locaux et présentation des services.\n"
))

# 2. Interne : note de service sans donnée personnelle
doc = Document()
doc.add_heading("Note de service interne", level=1)
doc.add_paragraph(
    "Réunion d'équipe mardi à 10h en salle B. "
    "Merci de préparer le point d'avancement du projet. "
    "Ce document est réservé au personnel de l'entreprise."
)
doc.save(OUT / "02_note_interne.docx")

# 3. Confidentiel : données personnelles de clients
wb = Workbook()
ws = wb.active
ws.title = "Clients"
ws.append(["Nom", "Email", "Téléphone", "IBAN", "Carte bancaire"])
ws.append(["Sara Alaoui", "sara.alaoui@example.com", "+212 6 12 34 56 78",
           "FR76 3000 6000 0112 3456 7890 189", "4111 1111 1111 1111"])
ws.append(["Youssef Bennani", "y.bennani@example.com", "+212 6 61 22 33 44",
           "FR76 3000 6000 0112 3456 7890 189", "5555 5555 5555 4444"])
ws.append(["Imane Idrissi", "imane.idrissi@example.com", "+212 6 70 11 22 33",
           "FR76 3000 6000 0112 3456 7890 189", "4111 1111 1111 1111"])
wb.save(OUT / "03_clients_confidentiel.xlsx")

# 4. Très confidentiel : identifiants, cartes, CIN
write("04_tres_confidentiel.txt", (
    "ACCES SERVEUR PRODUCTION\n"
    "login: admin\n"
    "password: P@ssw0rd-Production-2026\n"
    "api_key: sk_live_51H8xExampleKey1234567890\n\n"
    "Carte bancaire entreprise : 4111 1111 1111 1111  CVV 123\n"
    "IBAN : FR76 3000 6000 0112 3456 7890 189\n"
    "CIN du directeur : AB123456\n"
    "Email : directeur@example.com  Tel : +212 6 12 34 56 78\n"
))

# 5. Gros fichier (~6 Mo) contenant des données sensibles : test ML / anomalie
line = "Rapport d'activité trimestriel - ligne de remplissage sans intérêt.\n"
with open(OUT / "05_gros_fichier_sensible.txt", "w", encoding="utf-8") as f:
    f.write("Carte bancaire : 4111 1111 1111 1111\n")
    f.write("password: Secret-Admin-2026\n")
    target = 6 * 1024 * 1024
    written = 0
    while written < target:
        f.write(line)
        written += len(line)

# 6. Faux PDF : contenu invalide -> doit être bloqué (fail-closed) et journalisé
(OUT / "06_pdf_corrompu.pdf").write_bytes(b"ceci n'est pas un vrai pdf")

# 7. Extension interdite -> refusé dès le départ
(OUT / "07_programme.exe").write_bytes(b"MZ-faux-executable")

print(f"Fichiers de démonstration créés dans : {OUT}")
for p in sorted(OUT.iterdir()):
    print(f"  - {p.name:35s} {p.stat().st_size:>10,d} octets")