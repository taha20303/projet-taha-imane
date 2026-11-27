
from classification.rules import (
    CLASSIFICATION_LEVELS,
    get_classification_level
)

from policy_engine.rbac import get_role_permissions


def evaluate_policy(
    role: str,
    classification: str,
    action: str
) -> dict:
    """
    Evaluate an access request according to the user's
    role, permissions and data classification.
    """

    if not isinstance(action, str) or not action.strip():
        raise ValueError("Action must be a non-empty string")

    normalized_action = action.lower()
    normalized_classification = classification.upper()

    if normalized_classification not in CLASSIFICATION_LEVELS:
        raise ValueError(
            f"Unknown classification: {classification}"
        )

    user = get_role_permissions(role)

    user_clearance = get_classification_level(user["clearance"])
    data_level = get_classification_level(normalized_classification)

    if normalized_action not in user["permissions"]:
        return {
            "allowed": False,
            "reason": "Action not permitted for this role"
        }

    if data_level > user_clearance:
        return {
            "allowed": False,
            "reason": "Insufficient security clearance"
        }

    return {
        "allowed": True,
        "reason": "Access granted"
    }
