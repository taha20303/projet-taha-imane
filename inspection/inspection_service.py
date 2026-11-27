
from pathlib import Path

from inspection.file_scanner import scan_directory, get_file_info
from inspection.content_extractor import extract_text
from inspection.sensitive_detector import detect_sensitive_data


def inspect_file(file_path: str | Path) -> dict:
    """
    Inspect one file:
    metadata -> text extraction -> sensitive data detection.
    """

    path = Path(file_path)

    result = {
        "file": str(path),
        "status": "success",
        "metadata": None,
        "findings": [],
        "error": None
    }

    try:
        result["metadata"] = get_file_info(path)

        content = extract_text(path)

        result["findings"] = detect_sensitive_data(content)

    except Exception as error:
        result["status"] = "error"
        result["error"] = str(error)

    return result


def inspect_directory(directory: str | Path) -> dict:
    """
    Inspect all supported files in a directory.
    """

    files = scan_directory(directory)

    results = [
        inspect_file(file_path)
        for file_path in files
    ]

    successful = [
        result for result in results
        if result["status"] == "success"
    ]

    failed = [
        result for result in results
        if result["status"] == "error"
    ]

    total_findings = sum(
        len(result["findings"])
        for result in successful
    )

    return {
        "directory": str(directory),
        "total_files": len(files),
        "successful_files": len(successful),
        "failed_files": len(failed),
        "total_findings": total_findings,
        "results": results
    }
