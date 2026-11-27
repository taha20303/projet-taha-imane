
import stat
import zipfile
import tempfile

from pathlib import Path, PurePosixPath

from inspection.inspection_service import inspect_file
from classification.classifier import classify_document


MAX_FILES = 100
MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_TOTAL_SIZE = 20 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200


def inspect_zip(zip_path):
    zip_path = Path(zip_path)

    if not zip_path.exists() or not zip_path.is_file():
        raise FileNotFoundError(f"Archive not found: {zip_path}")

    if not zipfile.is_zipfile(zip_path):
        raise ValueError("Invalid ZIP archive")

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
                raise ValueError("Archive exceeds maximum total size")

            with tempfile.TemporaryDirectory() as temp_dir:
                temp_root = Path(temp_dir)

                for index, member in enumerate(members):
                    original_name = member.filename
                    safe_name = PurePosixPath(
                        original_name.replace("\\", "/")
                    ).name

                    if not safe_name or safe_name in {".", ".."}:
                        results.append({
                            "file": original_name,
                            "status": "skipped",
                            "reason": "Invalid file name"
                        })
                        continue

                    if member.file_size > MAX_FILE_SIZE:
                        results.append({
                            "file": original_name,
                            "status": "skipped",
                            "reason": "File exceeds maximum size"
                        })
                        continue

                    if member.flag_bits & 0x1:
                        results.append({
                            "file": original_name,
                            "status": "skipped",
                            "reason": "Encrypted file"
                        })
                        continue

                    unix_mode = member.external_attr >> 16
                    if stat.S_ISLNK(unix_mode):
                        results.append({
                            "file": original_name,
                            "status": "skipped",
                            "reason": "Symbolic links are not supported"
                        })
                        continue

                    if member.file_size > 0:
                        if member.compress_size == 0:
                            results.append({
                                "file": original_name,
                                "status": "skipped",
                                "reason": "Suspicious compression ratio"
                            })
                            continue

                        ratio = member.file_size / member.compress_size

                        if ratio > MAX_COMPRESSION_RATIO:
                            results.append({
                                "file": original_name,
                                "status": "skipped",
                                "reason": "Suspicious compression ratio"
                            })
                            continue

                    # Unique name prevents collisions between archive entries.
                    destination = temp_root / f"{index}_{safe_name}"

                    try:
                        written = 0

                        with archive.open(member, "r") as source:
                            with destination.open("wb") as target:
                                while True:
                                    chunk = source.read(64 * 1024)

                                    if not chunk:
                                        break

                                    written += len(chunk)

                                    if written > MAX_FILE_SIZE:
                                        raise ValueError(
                                            "Decompressed file exceeds maximum size"
                                        )

                                    target.write(chunk)

                        inspection = inspect_file(destination)

                        if inspection["status"] != "success":
                            results.append({
                                "file": original_name,
                                "status": "error",
                                "reason": inspection.get(
                                    "error", "Inspection failed"
                                )
                            })
                            continue

                        classification = classify_document(
                            inspection["findings"]
                        )

                        results.append({
                            "file": original_name,
                            "status": "success",
                            "sensitive_data_count": classification[
                                "sensitive_data_count"
                            ],
                            "detected_types": classification["detected_types"],
                            "classification": classification["classification"]
                        })

                    except Exception as error:
                        results.append({
                            "file": original_name,
                            "status": "error",
                            "reason": str(error)
                        })

    except zipfile.BadZipFile:
        raise ValueError("The ZIP archive is corrupted")

    return {
        "archive": zip_path.name,
        "total_files": len(members),
        "inspected_files": sum(
            item["status"] == "success" for item in results
        ),
        "results": results
    }
