
from pathlib import Path

from inspection.content_extractor import SUPPORTED_FORMATS


def scan_directory(directory: str | Path) -> list[Path]:
    """
    Recursively scan a directory and return supported files.

    Supported formats: TXT, PDF, DOCX and XLSX.
    """

    root = Path(directory)

    if not root.exists():
        raise FileNotFoundError(
            f"Directory not found: {root}"
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Not a directory: {root}"
        )

    supported_files = []

    for file_path in root.rglob("*"):

        if not file_path.is_file():
            continue

        if file_path.suffix.lower() in SUPPORTED_FORMATS:
            supported_files.append(file_path)

    return sorted(supported_files, key=lambda path: str(path).lower())


def get_file_info(file_path: str | Path) -> dict:
    """
    Return basic metadata about a file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular file: {path}"
        )

    return {
        "name": path.name,
        "extension": path.suffix.lower(),
        "size_bytes": path.stat().st_size,
        "path": str(path.resolve()),
        "supported": path.suffix.lower() in SUPPORTED_FORMATS
    }
