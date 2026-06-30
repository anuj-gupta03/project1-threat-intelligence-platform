from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from tip.models import IndicatorType

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def refang(value: str) -> str:
    return (
        value.strip()
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def normalize_ip(value: str) -> str:
    candidate = refang(value)
    if ":" in candidate and candidate.count(":") == 1 and "." in candidate:
        candidate = candidate.rsplit(":", 1)[0]
    return str(ipaddress.ip_address(candidate))


def normalize_domain(value: str) -> str:
    candidate = refang(value).strip().rstrip(".").lower()
    if "://" in candidate:
        candidate = urlparse(candidate).hostname or ""
    elif "/" in candidate:
        candidate = urlparse("https://" + candidate).hostname or ""
    if ":" in candidate:
        candidate = candidate.split(":", 1)[0]
    candidate = candidate.encode("idna").decode("ascii")
    if not DOMAIN_RE.fullmatch(candidate):
        raise ValueError(f"Invalid domain: {value!r}")
    return candidate


def normalize_indicator(value: str, indicator_type: IndicatorType) -> str:
    if indicator_type == IndicatorType.IP:
        return normalize_ip(value)
    if indicator_type == IndicatorType.DOMAIN:
        return normalize_domain(value)
    raise ValueError(f"Unsupported indicator type: {indicator_type}")
