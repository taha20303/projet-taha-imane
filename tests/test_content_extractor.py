
from pathlib import Path

import pytest
from docx import Document
from openpyxl import Workbook
from reportlab.pdfgen import canvas

from inspection.content_extractor import (
    extract_text,
    ExtractionError
)


@pytest.fixture
def test_files(tmp_path):
    files = {}

    # TXT
    txt = tmp_path / "test.txt"
    txt.write_text("Test DLP TXT", encoding="utf-8")
    files["txt"] = txt

    # DOCX
    docx = tmp_path / "test.docx"
    document = Document()
    document.add_paragraph("Test DLP DOCX")
    document.save(docx)
    files["docx"] = docx

    # XLSX
    xlsx = tmp_path / "test.xlsx"
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.append(["Test DLP XLSX"])
    workbook.save(xlsx)
    workbook.close()
    files["xlsx"] = xlsx

    # PDF
    pdf = tmp_path / "test.pdf"
    document_pdf = canvas.Canvas(str(pdf))
    document_pdf.drawString(100, 750, "Test DLP PDF")
    document_pdf.save()
    files["pdf"] = pdf

    return files


def test_extract_txt(test_files):
    assert extract_text(test_files["txt"]) == "Test DLP TXT"


def test_extract_docx(test_files):
    assert extract_text(test_files["docx"]) == "Test DLP DOCX"


def test_extract_xlsx(test_files):
    assert "Test DLP XLSX" in extract_text(test_files["xlsx"])


def test_extract_pdf(test_files):
    assert "Test DLP PDF" in extract_text(test_files["pdf"])


def test_missing_file():
    with pytest.raises(FileNotFoundError):
        extract_text("inexistant.txt")


def test_unsupported_format(tmp_path):
    file = tmp_path / "test.csv"
    file.write_text("Test", encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported file format"):
        extract_text(file)


def test_directory_instead_of_file(tmp_path):
    with pytest.raises(ValueError, match="Not a regular file"):
        extract_text(tmp_path)
