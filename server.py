import json
import os
from functools import wraps
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv
from flask import (
    Flask, request, redirect, url_for, session,
    render_template_string, flash
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

from inspection.inspection_service import inspect_file
from classification.classifier import classify_document

from policy_engine.decision_engine import make_access_decision
from dlp_engine.decision_engine import make_dlp_decision

from transfer_security.database import (
    init_db,
    save_transfer,
    count_recent_user_transfers,
    get_recent_transfers
)
from transfer_security.monitoring import collect_transfer_metadata
from transfer_security.risk_scoring import calculate_risk, get_risk_level

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
PENDING_DIR = UPLOAD_DIR / "pending"
ALLOWED_DIR = UPLOAD_DIR / "allowed"
USERS_FILE = BASE_DIR / "users.json"

PENDING_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_DIR.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "txt"}
VALID_DESTINATIONS = {"internal", "external", "usb"}
VALID_OPERATIONS = {"copy", "email", "share", "upload"}
VALID_ROLES = {"employee", "manager", "security_officer", "dlp_admin"}

# --- Configuration : la clé secrète est OBLIGATOIRE -------------------------
secret_key = os.getenv("FLASK_SECRET_KEY")
if not secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY est absente. Ajoutez-la dans .env "
        "(ex. python -c \"import secrets; print(secrets.token_hex(32))\")."
    )

app = Flask(__name__)
app.secret_key = secret_key
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

csrf = CSRFProtect(app)  # protège tous les POST


# --- Utilisateurs / authentification ---------------------------------------
def load_users():
    """users.json : {"alice": {"password_hash": "...", "role": "manager"}}
    Générez un hash avec :
    python -c "from werkzeug.security import generate_password_hash as g; print(g('motdepasse'))"
    """
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


# --- Fonctions utilitaires --------------------------------------------------
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


def get_classification(findings):
    result = classify_document(findings)

    if isinstance(result, str):
        return result.upper()

    if isinstance(result, dict):
        value = result.get("classification") or result.get("level")
        if value:
            return str(value).upper()

    raise ValueError("Classification invalide.")


def inspect_and_classify(file_path):
    inspection = inspect_file(str(file_path))

    if not isinstance(inspection, dict):
        raise ValueError("Résultat d'inspection invalide.")

    if inspection.get("status") != "success":
        raise ValueError(
            inspection.get("reason")
            or inspection.get("error")
            or "L'inspection du fichier a échoué."
        )

    classification = get_classification(inspection.get("findings", []))
    return inspection, classification


# --- ML : chargé une seule fois, au démarrage -------------------------------
_ml = {"detect": None}


def init_ml():
    try:
        from transfer_security.ML import (
            DATASET_PATH, MODEL_PATH, train_model, detect_anomaly
        )
        if not MODEL_PATH.exists():
            if not DATASET_PATH.exists():
                app.logger.warning("Dataset ML absent : analyse désactivée.")
                return
            train_model()
        _ml["detect"] = detect_anomaly
    except Exception:
        app.logger.exception("Initialisation ML impossible.")


def analyze_with_ml(transfer):
    """Retourne True / False, ou None si le ML est indisponible."""
    if _ml["detect"] is None:
        return None
    try:
        return bool(_ml["detect"](transfer))
    except Exception:
        app.logger.exception("Analyse ML en échec.")
        return None


def log_blocked(username, filename, destination, reason, file_size=0):
    """Journalise un échec de traitement (fail-closed)."""
    try:
        save_transfer({
            "username": username,
            "filename": filename,
            "destination": destination,
            "file_size": file_size,
            "sensitivity": "UNKNOWN",
            "decision": "BLOCK",
            "decision_reason": reason,
            "risk_score": 100,
            "risk_level": "HIGH",
            "anomaly": None,
        })
    except Exception:
        app.logger.exception("Impossible de journaliser le blocage.")


# --- Pages ------------------------------------------------------------------
STYLE = """
body { font-family: Arial, sans-serif; background: #f3f6fb; color: #172033; margin: 0; }
header { background: #142b4a; color: white; padding: 24px 7%;
         display: flex; justify-content: space-between; align-items: center; }
header h1 { margin: 0; }
header form { margin: 0; }
header button { margin: 0; background: #2c4a73; }
main { max-width: 1100px; margin: 30px auto; padding: 0 18px; }
.panel { background: white; padding: 24px; margin-bottom: 24px;
         border-radius: 10px; box-shadow: 0 2px 10px #0000000c; }
label { display: block; margin-top: 14px; font-weight: bold; }
input, select { width: 100%; padding: 11px; margin-top: 7px;
                border: 1px solid #ccd4df; border-radius: 6px; box-sizing: border-box; }
button { margin-top: 20px; padding: 12px 20px; background: #087eaa; color: white;
         border: 0; border-radius: 6px; cursor: pointer; font-weight: bold; }
button:hover { background: #066487; }
.message { background: #e8f1fb; border-left: 4px solid #087eaa;
           padding: 12px; margin-bottom: 12px; border-radius: 4px; }
.message.success { background: #e9f7ee; border-left-color: #2e9e5b; }
.message.warning { background: #fff6e0; border-left-color: #d99a16; }
.message.error { background: #fdeaea; border-left-color: #c93636; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e5e9ef; }
th { background: #f1f5f9; }
.muted { color: #68758a; font-size: 13px; }
"""

FLASH_BLOCK = """
{% for category, message in get_flashed_messages(with_categories=true) %}
    <div class="message {{ category }}">{{ message }}</div>
{% endfor %}
"""

PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Enterprise DLP Platform</title>
    <style>""" + STYLE + """</style>
</head>
<body>
<header>
    <div>
        <h1>Enterprise DLP Platform</h1>
        <p>Connecté : {{ session['user'] }} ({{ session['role'] }})</p>
    </div>
    <form method="POST" action="{{ url_for('logout') }}">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <button type="submit">Déconnexion</button>
    </form>
</header>

<main>
""" + FLASH_BLOCK + """
    {% if database_error %}
        <div class="message error">Base de données indisponible.</div>
    {% endif %}

    <section class="panel">
        <h2>Analyser un fichier</h2>
        <p class="muted">La classification est déterminée automatiquement à partir du contenu.</p>

        <form method="POST" action="{{ url_for('upload') }}" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">

            <label>Destination</label>
            <select name="destination" required>
                <option value="internal">Interne</option>
                <option value="external">Externe</option>
                <option value="usb">USB</option>
            </select>

            <label>Opération</label>
            <select name="operation" required>
                <option value="copy">Copy</option>
                <option value="email">Email</option>
                <option value="share">Share</option>
                <option value="upload">Upload</option>
            </select>

            <label>Fichier</label>
            <input type="file" name="file" required>

            <button type="submit">Analyser et contrôler</button>
        </form>
    </section>

    <section class="panel">
        <h2>Historique des transferts</h2>
        {% if transfers %}
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Utilisateur</th><th>Fichier</th><th>Destination</th>
                        <th>Classification</th><th>Décision</th><th>Risque</th><th>Anomalie</th>
                    </tr>
                </thead>
                <tbody>
                    {% for item in transfers %}
                    <tr>
                        <td>{{ item.username }}</td>
                        <td>{{ item.filename }}</td>
                        <td>{{ item.destination }}</td>
                        <td>{{ item.sensitivity }}</td>
                        <td>{{ item.decision }}</td>
                        <td>{{ item.risk_level }}</td>
                        <td>{{ 'N/D' if item.anomaly is none else ('Oui' if item.anomaly else 'Non') }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
            <p class="muted">Aucun transfert enregistré pour le moment.</p>
        {% endif %}
    </section>
</main>
</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Connexion - DLP</title>
    <style>""" + STYLE + """</style>
</head>
<body>
<main style="max-width:420px">
""" + FLASH_BLOCK + """
    <section class="panel">
        <h2>Connexion</h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
            <label>Nom d'utilisateur</label>
            <input type="text" name="username" required autofocus>
            <label>Mot de passe</label>
            <input type="password" name="password" required>
            <button type="submit">Se connecter</button>
        </form>
    </section>
</main>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = load_users().get(username)

        if (
            user
            and user.get("role") in VALID_ROLES
            and check_password_hash(user["password_hash"], password)
        ):
            session.clear()
            session["user"] = username
            session["role"] = user["role"]
            return redirect(url_for("index"))

        flash("Identifiants incorrects.", "error")

    return render_template_string(LOGIN_PAGE)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET"])
@login_required
def index():
    try:
        transfers = get_recent_transfers()
        database_error = False
    except Exception:
        app.logger.exception("Lecture de l'historique impossible.")
        transfers = []
        database_error = True

    return render_template_string(
        PAGE, transfers=transfers, database_error=database_error
    )


@app.route("/upload", methods=["POST"])
@login_required
def upload():
    temporary_path = None
    accepted_path = None

    # Identité et rôle viennent de la session, jamais du formulaire.
    username = session["user"]
    role = session["role"]

    uploaded_file = request.files.get("file")
    destination = request.form.get("destination", "").strip().lower()
    operation = request.form.get("operation", "").strip().lower()

    # Validation par liste blanche
    if not uploaded_file or not uploaded_file.filename:
        flash("Veuillez sélectionner un fichier.", "error")
        return redirect(url_for("index"))

    if destination not in VALID_DESTINATIONS or operation not in VALID_OPERATIONS:
        flash("Destination ou opération invalide.", "error")
        return redirect(url_for("index"))

    if not allowed_file(uploaded_file.filename):
        flash("Format non pris en charge. Utilisez PDF, DOCX, XLSX ou TXT.", "error")
        return redirect(url_for("index"))

    original_name = secure_filename(uploaded_file.filename) or "fichier"
    unique_name = f"{uuid4().hex}_{original_name}"
    temporary_path = PENDING_DIR / unique_name
    file_size = 0

    try:
        uploaded_file.save(temporary_path)
        file_size = temporary_path.stat().st_size  # taille fiable

        # 1. Inspection + classification
        _, classification = inspect_and_classify(temporary_path)

        # 2. RBAC
        access_action = "read" if destination == "internal" else "share"
        access_result = make_access_decision(
            user_role=role,
            classification=classification,
            action=access_action
        )
        access_decision = access_result.get("decision", "DENY").upper()

        # 3. DLP
        dlp_result = make_dlp_decision(
            classification=classification,
            operation=operation,
            destination=destination
        )
        dlp_decision = dlp_result.get("decision", "BLOCK").upper()
        if dlp_decision not in {"ALLOW", "WARN", "BLOCK"}:
            dlp_decision = "BLOCK"

        # 4. Métadonnées et risque
        metadata = collect_transfer_metadata(
            uploaded_file, username, destination, classification,
            file_size=file_size
        )
        metadata["transfer_frequency"] = count_recent_user_transfers(username) + 1

        risk_score = calculate_risk(metadata)
        risk_level = get_risk_level(risk_score)

        # 5. ML (None si indisponible)
        anomaly = analyze_with_ml(metadata)

        # 6. Décision finale
        if access_decision != "ALLOW" or dlp_decision == "BLOCK":
            final_decision = "BLOCK"
        elif dlp_decision == "WARN":
            final_decision = "WARN"
        else:
            final_decision = "ALLOW"

        decision_reason = " | ".join([
            f"RBAC : {access_result.get('reason', 'Aucune raison fournie')}",
            f"DLP : {dlp_result.get('reason', 'Aucune raison fournie')}",
        ])

        # 7. Journalisation
        save_transfer({
            "username": username,
            "filename": original_name,
            "destination": destination,
            "file_size": file_size,
            "sensitivity": classification,
            "decision": final_decision,
            "decision_reason": decision_reason,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "anomaly": anomaly,
        })

        # 8. Conservation du fichier
        if final_decision in {"ALLOW", "WARN"}:
            accepted_path = ALLOWED_DIR / unique_name
            temporary_path.replace(accepted_path)
            temporary_path = None
        else:
            temporary_path.unlink(missing_ok=True)
            temporary_path = None

        ml_label = (
            "Indisponible" if anomaly is None
            else ("Détectée" if anomaly else "Non détectée")
        )
        message = (
            f"Décision : {final_decision} | Classification : {classification} | "
            f"Risque : {risk_level} ({risk_score}/100) | Anomalie ML : {ml_label}"
            f" — {decision_reason}"
        )
        category = {"BLOCK": "error", "WARN": "warning"}.get(final_decision, "success")
        flash(message, category)

    except Exception as error:
        app.logger.exception("Erreur pendant le traitement du transfert.")

        if temporary_path and temporary_path.exists():
            temporary_path.unlink(missing_ok=True)
        if accepted_path and accepted_path.exists():
            accepted_path.unlink(missing_ok=True)

        # Fail-closed : un fichier non analysable est bloqué ET journalisé.
        log_blocked(
            username, original_name, destination,
            f"Traitement échoué : {type(error).__name__}", file_size
        )
        flash(
            "Le fichier n'a pas pu être analysé et a été bloqué par sécurité.",
            "error"
        )

    return redirect(url_for("index"))


# --- Démarrage (exécuté aussi avec flask run / gunicorn) --------------------
try:
    init_db()
except Exception:
    app.logger.exception("PostgreSQL indisponible à l'initialisation.")

init_ml()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)