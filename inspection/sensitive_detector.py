
import re


PATTERNS = {
    "EMAIL": re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    ),

    "MOROCCAN_PHONE": re.compile(
        r"(?<!\d)(?:\+212|00212|0)(?:[5-7])\d{8}(?!\d)"
    ),

    "MOROCCAN_CIN": re.compile(
        r"\b[A-Z]{1,2}\d{5,7}\b",
        re.IGNORECASE
    ),

    "CREDIT_CARD": re.compile(
        r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"
    ),

    "IBAN": re.compile(
        r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b",
        re.IGNORECASE
    )
}


def is_valid_credit_card(number: str) -> bool:
    """Validate a card number using the Luhn algorithm."""

    digits = re.sub(r"\D", "", number)

    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    reverse_digits = digits[::-1]

    for index, digit in enumerate(reverse_digits):
        value = int(digit)

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


def detect_sensitive_data(text: str) -> list[dict]:
    """
    Detect sensitive information in a text.

    Returns a list containing the type, matched value
    and position of each detection.
    """

    if not isinstance(text, str):
        raise TypeError("Input must be a string")

    findings = []

    for data_type, pattern in PATTERNS.items():

        for match in pattern.finditer(text):

            value = match.group()

            if data_type == "CREDIT_CARD":
                if not is_valid_credit_card(value):
                    continue

            findings.append({
                "type": data_type,
                "value": value,
                "start": match.start(),
                "end": match.end()
            })

    return sorted(findings, key=lambda item: item["start"])
