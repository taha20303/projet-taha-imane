
import zipfile
import tempfile
from pathlib import Path

from inspection.inspection_service import inspect_file
from classification.classifier import classify_document


MAX_FILES = 100
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB par fichier
MAX_TOTAL_SIZE = 20 * 1024 * 1024  # 20 MB par archive


def inspect_zip(zip_path):
    zip_path = Path(zip_path)

    if not zip_path.exists() or not zip_path.is_file():
        raise FileNotFoundError(f"Archive not found: {zip_path}")

    if not zipfile.is_zipfile(zip_path):
        raise ValueError("The provided file is not a valid ZIP archive")

    results = []

    try:
        with zipfile.ZipFile(zip_path, "r") as archive:

            members = [
                item for item in archive.infolist()
                if not item.is_dir()
            ]

            if len(members) > MAX_FILES:
                raise ValueError("Archive contains too many files")

            total_size = sum(item.file_size for item in members)

            if total_size > MAX_TOTAL_SIZE:
                raise ValueError("Archive exceeds the maximum allowed size")

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_root = Path(temp_dir).resolve()

                for member in members:

                    file_name = Path(member.filename).name

                    if not file_name:
                        continue

                    if member.file_size > MAX_FILE_SIZE:
                        results.append({
                            "file": member.filename,
                            "status": "skipped",
                            "reason": "File exceeds the maximum allowed size"
                        })
                        continue

                    if member.flag_bits & 0x1:
                        results.append({
                            "file": member.filename,
                            "status": "skipped",
                            "reason": "Encrypted files are not supported"
                        })
                        continue

                    destination = temp_root / file_name

                    try:
                        with archive.open(member) as source:
                            with destination.open("wb") as target:
                                target.write(source.read(MAX_FILE_SIZE + 1))

                        if destination.stat().st_size > MAX_FILE_SIZE:
                            results.append({
                                "file": member.filename,
                                "status": "skipped",
                                "reason": "File exceeds the maximum allowed size"
                            })
                            destination.unlink(missing_ok=True)
                            continue

                        inspection = inspect_file(destination)

                        if inspection["status"] != "success":
                            results.append({
                                "file": member.filename,
                                "status": "error",
                                "reason": inspection.get("error", "Inspection failed")
                            })
                            continue

                        classification = classify_document(
                            inspection["findings"]
                        )

                        results.append({
                            "file": member.filename,
                            "status": "success",
                            "sensitive_data_count": classification["sensitive_data_count"],
                            "detected_types": classification["detected_types"],
                            "classification": classification["classification"]
                        })

                    except Exception as error:
                        results.append({
                            "file": member.filename,
                            "status": "error",
                            "reason": str(error)
                        })

    except zipfile.BadZipFile:
        raise ValueError("The ZIP archive is corrupted")

    return {
        "archive": zip_path.name,
        "total_files": len(members),
        "inspected_files": sum(
            1 for item in results if item["status"] == "success"
        ),
        "results": results
    }
