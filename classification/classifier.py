
from classification.rules import (
    CLASSIFICATION_LEVELS,
    SENSITIVE_DATA_RULES,
    DEFAULT_CLASSIFICATION,
    get_classification_level
)


def classify_document(findings: list[dict]) -> dict:
    """
    Classify a document according to its detected sensitive data.

    The highest required classification determines
    the final document classification.
    """

    if not isinstance(findings, list):
        raise TypeError("Findings must be a list")

    detected_types = set()
    required_levels = [DEFAULT_CLASSIFICATION]

    for finding in findings:

        if not isinstance(finding, dict):
            raise ValueError("Each finding must be a dictionary")

        data_type = finding.get("type")

        if not isinstance(data_type, str):
            raise ValueError("Each finding must contain a valid type")

        normalized_type = data_type.upper()

        if normalized_type not in SENSITIVE_DATA_RULES:
            raise ValueError(
                f"Unknown sensitive data type: {data_type}"
            )

        detected_types.add(normalized_type)
        required_levels.append(
            SENSITIVE_DATA_RULES[normalized_type]
        )

    final_level = max(
        required_levels,
        key=get_classification_level
    )

    return {
        "classification": final_level,
        "classification_score": CLASSIFICATION_LEVELS[final_level],
        "detected_types": sorted(detected_types),
        "sensitive_data_count": len(findings)
    }
