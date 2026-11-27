
import pytest

from inspection.file_scanner import (
    scan_directory,
    get_file_info
)


def test_scan_supported_files(tmp_path):
    (tmp_path / "file.txt").write_text("Hello")
    (tmp_path / "file.pdf").write_bytes(b"PDF")
    (tmp_path / "file.csv").write_text("A,B")

    files = scan_directory(tmp_path)

    names = [file.name for file in files]

    assert "file.txt" in names
    assert "file.pdf" in names
    assert "file.csv" not in names


def test_scan_subdirectories(tmp_path):
    subfolder = tmp_path / "subfolder"
    subfolder.mkdir()

    (subfolder / "document.docx").write_bytes(b"test")

    files = scan_directory(tmp_path)

    assert len(files) == 1
    assert files[0].name == "document.docx"


def test_scan_empty_directory(tmp_path):
    assert scan_directory(tmp_path) == []


def test_missing_directory():
    with pytest.raises(FileNotFoundError):
        scan_directory("inexistant_directory")


def test_get_file_info(tmp_path):
    file = tmp_path / "document.txt"
    file.write_text("Hello DLP")

    info = get_file_info(file)

    assert info["name"] == "document.txt"
    assert info["extension"] == ".txt"
    assert info["size_bytes"] > 0
    assert info["supported"] is True


def test_get_file_info_unsupported(tmp_path):
    file = tmp_path / "document.csv"
    file.write_text("Hello")

    info = get_file_info(file)

    assert info["supported"] is False
