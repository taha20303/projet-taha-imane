
from pathlib import Path

from pypdf import PdfReader
from docx import Document
from openpyxl import load_workbook


class ExtractionError(Exception):
    """Raised when text extraction fails."""


SUPPORTED_FORMATS = {".txt", ".pdf", ".docx", ".xlsx"}


def extract_text(file_path: str | Path) -> str:
    """
    Extract text from a supported file.

    Supported formats: TXT, PDF, DOCX and XLSX.
    Returns the extracted text as a string.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    extension = path.suffix.lower()

    if extension not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported file format: {extension}")

    try:
        if extension == ".txt":
            return _extract_txt(path)

        if extension == ".pdf":
            return _extract_pdf(path)

        if extension == ".docx":
            return _extract_docx(path)

        if extension == ".xlsx":
            return _extract_xlsx(path)

    except (FileNotFoundError, PermissionError, ValueError):
        raise
    except Exception as error:
        raise ExtractionError(
            f"Could not extract content from {path.name}: {error}"
        ) from error


def _extract_txt(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        return path.read_text(encoding="cp1252")


def _extract_pdf(path: Path) -> str:
    reader = PdfReader(str(path))

    extracted_pages = []

    for page in reader.pages:
        extracted_pages.append(page.extract_text() or "")

    return "\n".join(extracted_pages)


def _extract_docx(path: Path) -> str:
    document = Document(str(path))

    paragraphs = [
        paragraph.text
        for paragraph in document.paragraphs
        if paragraph.text.strip()
    ]

    return "\n".join(paragraphs)


def _extract_xlsx(path: Path) -> str:
    workbook = load_workbook(
        filename=path,
        read_only=True,
        data_only=True
    )

    extracted_content = []

    try:
        for worksheet in workbook.worksheets:
            extracted_content.append(f"Sheet: {worksheet.title}")

            for row in worksheet.iter_rows(values_only=True):
                values = [
                    str(value)
                    for value in row
                    if value is not None
                ]

                if values:
                    extracted_content.append(" | ".join(values))
    finally:
        workbook.close()

    return "\n".join(extracted_content)
