from __future__ import annotations

import ipaddress
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from tip.models import FeedRecord, IndicatorType
from tip.normalization import normalize_indicator


def build_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=0.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.headers.update({"User-Agent": "Infotact-TIP/0.1"})
    return session


def parse_datetime(value: Any) -> datetime:
    if not value:
        return datetime.now(UTC)
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value).strip().replace("Z", "+00:00")
    for candidate in (text, text.replace(" ", "T")):
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            continue
    return datetime.now(UTC)


def record_from_value(
    value: str,
    *,
    source: str,
    confidence: int,
    tags: list[str] | None = None,
    first_seen: Any = None,
    last_seen: Any = None,
    reference: str | None = None,
) -> FeedRecord:
    candidate = value.strip()
    if "://" in candidate:
        candidate = urlparse(candidate.replace("hxxp", "http", 1)).hostname or candidate
    try:
        ipaddress.ip_address(candidate.rsplit(":", 1)[0] if candidate.count(":") == 1 else candidate)
        indicator_type = IndicatorType.IP
    except ValueError:
        indicator_type = IndicatorType.DOMAIN
    normalized = normalize_indicator(candidate, indicator_type)
    return FeedRecord(
        value=normalized,
        indicator_type=indicator_type,
        source=source,
        confidence=confidence,
        first_seen=parse_datetime(first_seen),
        last_seen=parse_datetime(last_seen),
        tags=sorted(set(tags or [])),
        reference=reference,
    )


class ThreatFeed(ABC):
    name: str

    def __init__(self, timeout: int = 20, limit: int = 1000) -> None:
        self.timeout = timeout
        self.limit = limit
        self.session = build_session()

    @abstractmethod
    def fetch(self) -> list[FeedRecord]:
        raise NotImplementedError
