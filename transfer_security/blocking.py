
from policy_engine.decision_engine import make_access_decision


def evaluate_policy(transfer):
    role = transfer.get("user_role", "employee")
    classification = transfer["sensitivity"]

    action = (
        "share"
        if transfer["destination"].lower() == "external"
        else "read"
    )

    result = make_access_decision(
        user_role=role,
        classification=classification,
        action=action
    )

    decision = result.get("decision", "DENY").upper()
    reason = result.get("reason", "Policy Engine")

    if decision == "ALLOW":
        return "ALLOW", reason

    return "BLOCK", reason
