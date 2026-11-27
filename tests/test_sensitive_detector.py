
import pytest

from inspection.sensitive_detector import (
    detect_sensitive_data,
    is_valid_credit_card
)


def test_detect_email():
    results = detect_sensitive_data("Contact: imane@example.com")
    assert any(item["type"] == "EMAIL" for item in results)


def test_detect_moroccan_phone():
    results = detect_sensitive_data("Téléphone: 0612345678")
    assert any(item["type"] == "MOROCCAN_PHONE" for item in results)


def test_detect_cin():
    results = detect_sensitive_data("CIN: AB123456")
    assert any(item["type"] == "MOROCCAN_CIN" for item in results)


def test_detect_credit_card():
    results = detect_sensitive_data("Carte: 4111111111111111")
    assert any(item["type"] == "CREDIT_CARD" for item in results)


def test_luhn_validation():
    assert is_valid_credit_card("4111111111111111")
    assert not is_valid_credit_card("1234567890123456")


def test_no_sensitive_data():
    assert detect_sensitive_data("Bonjour, bienvenue dans notre entreprise.") == []


def test_invalid_input():
    with pytest.raises(TypeError):
        detect_sensitive_data(12345)
