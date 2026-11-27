
ROLES = {
    "employee": {
        "clearance": "INTERNAL",
        "permissions": ["read"]
    },

    "manager": {
        "clearance": "CONFIDENTIAL",
        "permissions": ["read", "share"]
    },

    "security_officer": {
        "clearance": "HIGHLY_CONFIDENTIAL",
        "permissions": ["read", "share", "export"]
    },

    "dlp_admin": {
        "clearance": "HIGHLY_CONFIDENTIAL",
        "permissions": ["read", "share", "export", "delete", "manage_policies"]
    }
}


def get_role_permissions(role: str) -> dict:
    """Retrieve permissions associated with a user role."""

    normalized_role = role.lower()

    if normalized_role not in ROLES:
        raise ValueError(f"Unknown role: {role}")

    return ROLES[normalized_role].copy()
