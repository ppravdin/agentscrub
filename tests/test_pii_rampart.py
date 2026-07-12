"""Tests for the Rampart PII Python wrapper."""
import pytest

pytest.importorskip("onnxruntime")
pytest.importorskip("transformers")
pytest.importorskip("huggingface_hub")

from agentscrub.pii_rampart import KEEP_LABELS, RampartPiiDetector, Span


@pytest.fixture(scope="module")
def detector() -> RampartPiiDetector:
    return RampartPiiDetector()


def test_basic_name_and_ssn(detector: RampartPiiDetector) -> None:
    text = "My name is Alex Rivera and my SSN is 472-81-0094."
    result = detector.redact(text)
    assert "[GIVEN_NAME_1]" in result.text
    assert "[SURNAME_1]" in result.text
    assert "[SSN_1]" in result.text
    assert "Alex" not in result.text
    assert "Rivera" not in result.text
    assert "472-81-0094" not in result.text


def test_address_keeps_city_state_zip(detector: RampartPiiDetector) -> None:
    text = "I live at 123 Maple Street, Austin, TX 78701."
    result = detector.redact(text)
    assert "Austin" in result.text
    assert "TX" in result.text
    assert "78701" in result.text
    assert "[BUILDING_NUMBER_1]" in result.text
    assert "[STREET_NAME_1]" in result.text


def test_email_and_url(detector: RampartPiiDetector) -> None:
    text = "Email me at alex.rivera@example.com or visit https://example.com/profile."
    result = detector.redact(text)
    assert "[EMAIL_1]" in result.text
    assert "[URL_1]" in result.text
    assert "alex.rivera@example.com" not in result.text


def test_credit_card_luhn(detector: RampartPiiDetector) -> None:
    text = "My card is 4111111111111111."
    result = detector.redact(text)
    assert "[CREDIT_CARD_1]" in result.text
    assert "4111111111111111" not in result.text


def test_phone_number(detector: RampartPiiDetector) -> None:
    text = "Call me at 512-555-0199."
    result = detector.redact(text)
    assert "[PHONE_1]" in result.text
    assert "512-555-0199" not in result.text


def test_spanish_name(detector: RampartPiiDetector) -> None:
    text = "Mi nombre es José García."
    result = detector.redact(text)
    assert "José" not in result.text
    assert "García" not in result.text


def test_stable_placeholders_across_calls(detector: RampartPiiDetector) -> None:
    # Same value should map to the same placeholder within one detector instance.
    r1 = detector.redact("Alex Rivera lives here.")
    r2 = detector.redact("Alex Rivera lives here.")
    assert "[GIVEN_NAME_1]" in r1.text
    assert "[GIVEN_NAME_1]" in r2.text
    assert "[SURNAME_1]" in r1.text
    assert "[SURNAME_1]" in r2.text


def test_keep_labels_default() -> None:
    assert KEEP_LABELS == {"CITY", "STATE", "ZIP_CODE"}


def test_unicode_normalization_preserves_offsets() -> None:
    detector = RampartPiiDetector()
    original = "Mi nombre es José García."
    normalized, mapping = detector._normalize_with_map(original)
    assert normalized == "mi nombre es jose garcia."
    assert detector._map_offset(original, normalized, 13, mapping) == 13


def test_url_span_excludes_sentence_punctuation() -> None:
    detector = RampartPiiDetector()
    spans = detector._detect_deterministic("Visit https://example.com/profile.")
    assert [(span.label, span.text) for span in spans] == [
        ("URL", "https://example.com/profile")
    ]


def test_proof_does_not_expose_pii() -> None:
    detector = RampartPiiDetector()
    span = Span("EMAIL", 0, 21, "alex@example.com")
    proof = detector.proof(span)
    assert span.text not in proof
    assert "#" in proof
