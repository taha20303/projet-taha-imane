
from policy_engine.policies import evaluate_policy


def make_access_decision(
    user_role: str,
    classification: str,
    action: str
) -> dict:
    """
    Make a final access control decision.
    """

    try:
        policy_result = evaluate_policy(
            role=user_role,
            classification=classification,
            action=action
        )

        return {
            "decision": "ALLOW" if policy_result["allowed"] else "DENY",
            "role": user_role,
            "classification": classification,
            "action": action,
            "reason": policy_result["reason"]
        }

    except (ValueError, TypeError) as error:
        return {
            "decision": "DENY",
            "role": user_role,
            "classification": classification,
            "action": action,
            "reason": str(error)
        }
