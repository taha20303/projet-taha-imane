
import pytest

from classification.classifier import classify_document
from classification.rules import (
    get_required_classification,
    get_classification_level
)


def test_no_sensitive_data():
    result = classify_document([])

    assert result["classification"] == "INTERNAL"
    assert result["sensitive_data_count"] == 0


def test_email_classification():
    findings = [{"type": "EMAIL", "value": "test@example.com"}]

    result = classify_document(findings)

    assert result["classification"] == "CONFIDENTIAL"


def test_phone_classification():
    findings = [{"type": "MOROCCAN_PHONE", "value": "0612345678"}]

    result = classify_document(findings)

    assert result["classification"] == "CONFIDENTIAL"


def test_credit_card_classification():
    findings = [{"type": "CREDIT_CARD", "value": "4111111111111111"}]

    result = classify_document(findings)

    assert result["classification"] == "HIGHLY_CONFIDENTIAL"


def test_highest_classification_wins():
    findings = [
        {"type": "EMAIL", "value": "test@example.com"},
        {"type": "MOROCCAN_PHONE", "value": "0612345678"},
        {"type": "IBAN", "value": "MA64011519000001205000534921"}
    ]

    result = classify_document(findings)

    assert result["classification"] == "HIGHLY_CONFIDENTIAL"


def test_unknown_data_type():
    findings = [{"type": "UNKNOWN"}]

    with pytest.raises(ValueError):
        classify_document(findings)


def test_invalid_input():
    with pytest.raises(TypeError):
        classify_document("EMAIL")


def test_classification_priority():
    assert get_classification_level("PUBLIC") < get_classification_level("INTERNAL")
    assert get_classification_level("INTERNAL") < get_classification_level("CONFIDENTIAL")
    assert get_classification_level("CONFIDENTIAL") < get_classification_level("HIGHLY_CONFIDENTIAL")


def test_required_classification():
    assert get_required_classification("EMAIL") == "CONFIDENTIAL"
    assert get_required_classification("IBAN") == "HIGHLY_CONFIDENTIAL"
