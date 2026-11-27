import threading
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "dataset.csv"
MODEL_PATH = BASE_DIR / "isolation_forest.joblib"

FEATURES = [
    "file_size",
    "external",
    "transfer_frequency",
    "sensitivity"
]

SENSITIVITY_VALUES = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "HIGHLY_CONFIDENTIAL": 4
}

# Destinations considérées comme "externes" pour le modèle.
# Ajoutez "usb" ici si le dataset suit la même convention (puis réentraînez).
EXTERNAL_DESTINATIONS = {"external"}

_model = None
_lock = threading.Lock()


def _prepare(data):
    """Même transformation à l'entraînement et à la détection.
    file_size varie sur plusieurs ordres de grandeur : on passe en log."""
    prepared = data[FEATURES].astype(float).copy()
    prepared["file_size"] = np.log1p(prepared["file_size"].clip(lower=0))
    return prepared


def train_model():
    global _model

    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset introuvable : {DATASET_PATH}"
        )

    data = pd.read_csv(DATASET_PATH)

    missing = set(FEATURES) - set(data.columns)
    if missing:
        raise ValueError(
            f"Colonnes manquantes dans le dataset : {missing}"
        )

    model = make_pipeline(
        StandardScaler(),
        IsolationForest(
            contamination=0.08,
            random_state=42
        )
    )

    model.fit(_prepare(data))
    joblib.dump(model, MODEL_PATH)

    with _lock:
        _model = model

    print("Modèle entraîné avec succès !")
    return model


def load_model():
    """Charge le modèle une seule fois puis le garde en mémoire."""
    global _model

    if _model is None:
        with _lock:
            if _model is None:
                if not MODEL_PATH.exists():
                    raise FileNotFoundError(
                        "Modèle ML introuvable. Entraînez-le d'abord."
                    )
                _model = joblib.load(MODEL_PATH)

    return _model


def detect_anomaly(transfer):
    """Retourne True si le transfert est jugé anormal, sinon False."""
    model = load_model()

    sensitivity = str(transfer["sensitivity"]).upper()

    if sensitivity not in SENSITIVITY_VALUES:
        raise ValueError(f"Classification inconnue : {sensitivity}")

    features = pd.DataFrame([{
        "file_size": transfer["file_size"],
        "external": int(
            str(transfer["destination"]).lower() in EXTERNAL_DESTINATIONS
        ),
        "transfer_frequency": transfer.get("transfer_frequency", 1),
        "sensitivity": SENSITIVITY_VALUES[sensitivity]
    }])

    prediction = model.predict(_prepare(features))

    return bool(prediction[0] == -1)


if __name__ == "__main__":
    train_model()