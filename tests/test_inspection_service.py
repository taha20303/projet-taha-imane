
from inspection.inspection_service import (
    inspect_file,
    inspect_directory
)


def test_inspect_file(tmp_path):
    file = tmp_path / "document.txt"

    file.write_text(
        "Contact: imane@example.com",
        encoding="utf-8"
    )

    result = inspect_file(file)

    assert result["status"] == "success"
    assert result["metadata"]["name"] == "document.txt"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["type"] == "EMAIL"


def test_inspect_directory(tmp_path):
    (tmp_path / "file1.txt").write_text(
        "Contact: imane@example.com",
        encoding="utf-8"
    )

    (tmp_path / "file2.txt").write_text(
        "Document public sans données sensibles.",
        encoding="utf-8"
    )

    result = inspect_directory(tmp_path)

    assert result["total_files"] == 2
    assert result["successful_files"] == 2
    assert result["failed_files"] == 0
    assert result["total_findings"] == 1


def test_inspect_empty_directory(tmp_path):
    result = inspect_directory(tmp_path)

    assert result["total_files"] == 0
    assert result["total_findings"] == 0
