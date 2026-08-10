import pytest

from app.domain.ioc.parser import parse_ioc
from app.domain.ioc.types import IocType


@pytest.mark.parametrize(
    ("value", "expected_type", "expected_normalized"),
    [
        ("8.8.8.8", IocType.IPV4, "8.8.8.8"),
        ("2001:4860:4860::8888", IocType.IPV6, "2001:4860:4860::8888"),
        ("Example.COM", IocType.DOMAIN, "example.com"),
        ("https://Example.com:443/a/b?x=1", IocType.URL, "https://example.com:443/a/b?x=1"),
        ("44d88612fea8a8f36de82e1278abb02f", IocType.MD5, "44d88612fea8a8f36de82e1278abb02f"),
        (
            "3395856ce81f2b7382dee72602f798b642f14140",
            IocType.SHA1,
            "3395856ce81f2b7382dee72602f798b642f14140",
        ),
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IocType.SHA256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ),
        ("Analyst@Example.com", IocType.EMAIL, "analyst@example.com"),
        ("+1 (415) 555-0101", IocType.PHONE, "+14155550101"),
    ],
)
def test_parse_supported_iocs(value: str, expected_type: IocType, expected_normalized: str) -> None:
    parsed = parse_ioc(value)

    assert parsed.type == expected_type
    assert parsed.normalized == expected_normalized


@pytest.mark.parametrize("value", ["", "not an ioc", "999.999.999.999", "http://"])
def test_parse_unknown_iocs(value: str) -> None:
    assert parse_ioc(value).type == IocType.UNKNOWN
