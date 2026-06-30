from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


class IndicatorType(StrEnum):
    IP = "ip"
    DOMAIN = "domain"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeedRecord(BaseModel):
    value: str
    indicator_type: IndicatorType
    source: str
    confidence: int = Field(ge=0, le=100)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    tags: list[str] = Field(default_factory=list)
    reference: str | None = None


class CollectionStats(BaseModel):
    feed: str
    fetched: int = 0
    accepted: int = 0
    rejected: int = 0
    error: str | None = None


class PolicyDecision(BaseModel):
    indicator: str
    eligible: bool
    reason: str
    risk_score: int = 0
