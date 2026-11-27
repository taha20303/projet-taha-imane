
def calculate_risk(transfer):
    score = 0

    # 1. Sensibilité des données
    sensitivity_points = {
        "PUBLIC": 5,
        "INTERNAL": 10,
        "CONFIDENTIAL": 25,
        "HIGHLY_CONFIDENTIAL": 40,
    }

    sensitivity = transfer["sensitivity"].upper()
    score += sensitivity_points.get(sensitivity, 40)

    # 2. Destination externe
    if transfer["destination"].lower() == "external":
        score += 30

    # 3. Taille du fichier
    if transfer["file_size"] > 5 * 1024 * 1024:
        score += 15
    elif transfer["file_size"] > 1024 * 1024:
        score += 8

    # 4. Fréquence des transferts
    frequency = transfer.get("transfer_frequency", 0)

    if frequency >= 10:
        score += 15
    elif frequency >= 5:
        score += 8

    return min(score, 100)


def get_risk_level(score):
    if score >= 70:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"

    return "LOW"
