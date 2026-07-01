import pytest

from audittool.core.validation import (
    ValidationError,
    validate_target,
    validate_url,
)


@pytest.mark.parametrize("value,expected", [
    ("example.com", "example.com"),
    ("EXAMPLE.COM", "example.com"),
    ("sub.domain.co.uk", "sub.domain.co.uk"),
    ("127.0.0.1", "127.0.0.1"),
    ("::1", "::1"),
])
def test_valid_targets(value, expected):
    assert validate_target(value) == expected


@pytest.mark.parametrize("value", [
    "example.com; rm -rf /",
    "$(whoami).com",
    "example.com && curl evil",
    "a b.com",
    "-oX",
    "",
    "not_a_domain",
    "http://example.com",  # scheme not allowed as a bare target
])
def test_injection_and_malformed_rejected(value):
    with pytest.raises(ValidationError):
        validate_target(value)


def test_validate_url_ok():
    assert validate_url("http://host/item?id=1") == "http://host/item?id=1"


@pytest.mark.parametrize("value", [
    "ftp://host/x",
    "http://host/;rm",
    "javascript:alert(1)",
    "host/item",
])
def test_validate_url_rejects(value):
    with pytest.raises(ValidationError):
        validate_url(value)
