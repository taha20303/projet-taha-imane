
CLASSIFICATION_LEVELS = {
    "PUBLIC": 1,
    "INTERNAL": 2,
    "CONFIDENTIAL": 3,
    "HIGHLY_CONFIDENTIAL": 4
}

# Minimum classification required for each sensitive data type.
SENSITIVE_DATA_RULES = {
    "EMAIL": "CONFIDENTIAL",
    "MOROCCAN_PHONE": "CONFIDENTIAL",
    "MOROCCAN_CIN": "CONFIDENTIAL",
    "CREDIT_CARD": "HIGHLY_CONFIDENTIAL",
    "IBAN": "HIGHLY_CONFIDENTIAL"
}

DEFAULT_CLASSIFICATION = "INTERNAL"


def get_classification_level(level: str) -> int:
    """Return the numerical priority of a classification level."""

    normalized = level.upper()

    if normalized not in CLASSIFICATION_LEVELS:
        raise ValueError(f"Unknown classification level: {level}")

    return CLASSIFICATION_LEVELS[normalized]


def get_required_classification(data_type: str) -> str:
    """Return the minimum classification required for a data type."""

    normalized = data_type.upper()

    if normalized not in SENSITIVE_DATA_RULES:
        raise ValueError(f"Unknown sensitive data type: {data_type}")

    return SENSITIVE_DATA_RULES[normalized]
