
from dlp_engine.rules import evaluate_dlp_rule


def make_dlp_decision(classification, operation, destination):
    try:
        result = evaluate_dlp_rule(
            classification,
            operation,
            destination
        )

        return {
            "classification": classification,
            "operation": operation,
            "destination": destination,
            "decision": result["decision"],
            "reason": result["reason"]
        }

    except (ValueError, TypeError) as error:
        return {
            "classification": classification,
            "operation": operation,
            "destination": destination,
            "decision": "DENY",
            "reason": str(error)
        }
