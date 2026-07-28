"""validate_ans_name accepts ANS v2 + legacy names (TRUS-1550)."""
import pytest
from fastapi import HTTPException

from app.main import validate_ans_name


def test_v2_accepted_and_normalized():
    assert validate_ans_name("ans://v1.0.0.support.acme.com") == "ans://v1.0.0.support.acme.com"
    assert validate_ans_name("  ANS://v2.3.4.Bot.Example.CO.UK ") == "ans://v2.3.4.bot.example.co.uk"


def test_legacy_accepted_and_lowercased():
    assert validate_ans_name("Salesforce-Einstein-CRM") == "salesforce-einstein-crm"


@pytest.mark.parametrize(
    "bad",
    [
        "ans://support.acme.com",   # v2 scheme but no version
        "ans://v1.0.0.localhost",   # v2 single-label host
        "x",                        # legacy too short
        "-bad-",                    # legacy leading/trailing hyphen
        "has_underscore",           # legacy illegal char
    ],
)
def test_rejects(bad):
    with pytest.raises(HTTPException):
        validate_ans_name(bad)
