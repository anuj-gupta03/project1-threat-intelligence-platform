import pytest

from tip.models import IndicatorType
from tip.normalization import normalize_indicator, normalize_ip


def test_normalizes_defanged_domain_and_url():
    assert normalize_indicator("Example[.]COM", IndicatorType.DOMAIN) == "example.com"
    assert normalize_indicator("hxxp://evil[.]example/path", IndicatorType.DOMAIN) == "evil.example"


def test_normalizes_ip_with_port():
    assert normalize_ip("8.8.8.8:443") == "8.8.8.8"


def test_rejects_invalid_domain():
    with pytest.raises(ValueError):
        normalize_indicator("not a domain", IndicatorType.DOMAIN)
