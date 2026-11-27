
CLASSIFICATIONS = {
    "PUBLIC",
    "INTERNAL",
    "CONFIDENTIAL",
    "HIGHLY_CONFIDENTIAL"
}

OPERATIONS = {
    "read",
    "edit",
    "copy",
    "email",
    "share",
    "upload"
}

DESTINATIONS = {
    "internal",
    "external",
    "usb"
}


def evaluate_dlp_rule(classification, operation, destination):
    if not all(isinstance(value, str) for value in (
        classification, operation, destination
    )):
        raise TypeError("All parameters must be strings")

    classification = classification.strip().upper()
    operation = operation.strip().lower()
    destination = destination.strip().lower()

    if classification not in CLASSIFICATIONS:
        raise ValueError("Unknown classification")

    if operation not in OPERATIONS:
        raise ValueError("Unsupported operation")

    if destination not in DESTINATIONS:
        raise ValueError("Unknown destination")

    # Reading and editing are handled by the RBAC module.
    if operation in {"read", "edit"}:
        return {
            "decision": "ALLOW",
            "reason": "No data transfer detected"
        }

    # Public data can be transferred freely.
    if classification == "PUBLIC":
        return {
            "decision": "ALLOW",
            "reason": "Public data transfer is permitted"
        }

    # Transfers to internal destinations are permitted.
    if destination == "internal":
        return {
            "decision": "ALLOW",
            "reason": "Transfer remains within the organization"
        }

    # Internal data transferred outside the organization.
    if classification == "INTERNAL":
        return {
            "decision": "WARN",
            "reason": "Internal data is being transferred outside the organization"
        }

    # Sensitive data must not leave the organization.
    if classification in {"CONFIDENTIAL", "HIGHLY_CONFIDENTIAL"}:
        return {
            "decision": "BLOCK",
            "reason": "Sensitive data transfer to an external destination is prohibited"
        }
