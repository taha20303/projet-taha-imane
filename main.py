
import argparse
from pathlib import Path

from inspection.inspection_service import inspect_file
from classification.classifier import classify_document
from policy_engine.decision_engine import make_access_decision
from dlp_engine.decision_engine import make_dlp_decision
from container_inspection.zip_inspector import inspect_zip


def analyze_file(file_path):
    inspection = inspect_file(file_path)

    if inspection["status"] != "success":
        return {
            "status": "error",
            "file": Path(file_path).name,
            "reason": inspection.get("error", "Inspection failed")
        }

    classification = classify_document(inspection["findings"])

    return {
        "status": "success",
        "file": Path(file_path).name,
        "classification": classification["classification"],
        "sensitive_data_count": classification["sensitive_data_count"],
        "detected_types": classification["detected_types"]
    }


def process_file(file_path, role, access_action, dlp_operation, destination):
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    if path.suffix.lower() == ".zip":
        analysis = inspect_zip(path)

        documents = [
            item for item in analysis["results"]
            if item["status"] == "success"
        ]

    else:
        analysis = None
        result = analyze_file(path)

        documents = [result] if result["status"] == "success" else []

    results = []

    for document in documents:
        classification = document["classification"]

        access = make_access_decision(
            role,
            classification,
            access_action
        )

        dlp = make_dlp_decision(
            classification,
            dlp_operation,
            destination
        )

        results.append({
            "file": document["file"],
            "classification": classification,
            "sensitive_data_count": document["sensitive_data_count"],
            "detected_types": document["detected_types"],
            "access_decision": access["decision"],
            "access_reason": access["reason"],
            "dlp_decision": dlp["decision"],
            "dlp_reason": dlp["reason"]
        })

    return {
        "source": path.name,
        "type": "ZIP archive" if path.suffix.lower() == ".zip" else "Individual file",
        "role": role,
        "access_action": access_action,
        "dlp_operation": dlp_operation,
        "destination": destination,
        "results": results,
        "skipped_or_failed": (
            [item for item in analysis["results"]
             if item["status"] != "success"]
            if analysis else
            ([result] if result["status"] == "error" else [])
        )
    }


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Data Loss Prevention Platform"
    )

    parser.add_argument("file", help="Path to a file or ZIP archive")
    parser.add_argument("--role", default="employee")
    parser.add_argument("--access-action", default="read")
    parser.add_argument("--dlp-operation", default="copy")
    parser.add_argument("--destination", default="external")

    args = parser.parse_args()

    try:
        report = process_file(
            args.file,
            args.role,
            args.access_action,
            args.dlp_operation,
            args.destination
        )

        print("\n========== ENTERPRISE DLP REPORT ==========")
        print(f"Source: {report['source']}")
        print(f"Type: {report['type']}")
        print(f"User role: {report['role']}")
        print(f"Access action: {report['access_action']}")
        print(f"DLP operation: {report['dlp_operation']}")
        print(f"Destination: {report['destination']}")

        for item in report["results"]:
            print("\n-------------------------------------------")
            for key, value in item.items():
                print(f"{key}: {value}")

        for item in report["skipped_or_failed"]:
            print("\n[SKIPPED / FAILED]")
            print(item)

        print("\n===========================================")

    except (ValueError, FileNotFoundError, OSError) as error:
        print(f"\nERROR: {error}")


if __name__ == "__main__":
    main()
