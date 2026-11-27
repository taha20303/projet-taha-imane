
import pytest

from policy_engine.rbac import get_role_permissions
from policy_engine.policies import evaluate_policy
from policy_engine.decision_engine import make_access_decision


def test_employee_can_read_internal():
    result = make_access_decision(
        "employee", "INTERNAL", "read"
    )
    assert result["decision"] == "ALLOW"


def test_employee_cannot_read_confidential():
    result = make_access_decision(
        "employee", "CONFIDENTIAL", "read"
    )
    assert result["decision"] == "DENY"


def test_manager_can_read_confidential():
    result = make_access_decision(
        "manager", "CONFIDENTIAL", "read"
    )
    assert result["decision"] == "ALLOW"


def test_manager_cannot_read_highly_confidential():
    result = make_access_decision(
        "manager", "HIGHLY_CONFIDENTIAL", "read"
    )
    assert result["decision"] == "DENY"


def test_security_officer_can_read_highly_confidential():
    result = make_access_decision(
        "security_officer", "HIGHLY_CONFIDENTIAL", "read"
    )
    assert result["decision"] == "ALLOW"


def test_employee_cannot_export():
    result = make_access_decision(
        "employee", "INTERNAL", "export"
    )
    assert result["decision"] == "DENY"


def test_admin_can_manage_policies():
    result = make_access_decision(
        "dlp_admin", "INTERNAL", "manage_policies"
    )
    assert result["decision"] == "ALLOW"


def test_unknown_role_is_denied():
    result = make_access_decision(
        "unknown_role", "INTERNAL", "read"
    )
    assert result["decision"] == "DENY"


def test_unknown_classification_is_denied():
    result = make_access_decision(
        "employee", "TOP_SECRET", "read"
    )
    assert result["decision"] == "DENY"


def test_invalid_action_is_denied():
    result = make_access_decision(
        "employee", "INTERNAL", ""
    )
    assert result["decision"] == "DENY"


def test_role_permissions():
    permissions = get_role_permissions("employee")

    assert permissions["clearance"] == "INTERNAL"
    assert "read" in permissions["permissions"]
    assert "export" not in permissions["permissions"]
