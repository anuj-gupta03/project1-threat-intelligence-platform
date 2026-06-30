from __future__ import annotations

from tip.feeds.base import ThreatFeed, record_from_value
from tip.models import FeedRecord


class OTXFeed(ThreatFeed):
    name = "alienvault_otx"
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    def __init__(self, api_key: str, timeout: int = 20, limit: int = 1000) -> None:
        super().__init__(timeout=timeout, limit=limit)
        self.api_key = api_key

    def fetch(self) -> list[FeedRecord]:
        response = self.session.get(
            self.url,
            headers={"X-OTX-API-KEY": self.api_key},
            params={"limit": 50, "page": 1},
            timeout=self.timeout,
        )
        response.raise_for_status()
        records: list[FeedRecord] = []
        for pulse in response.json().get("results", []):
            pulse_tags = [str(tag) for tag in pulse.get("tags", [])]
            for item in pulse.get("indicators", []):
                if len(records) >= self.limit:
                    return records
                if item.get("type") not in {"IPv4", "domain", "hostname"}:
                    continue
                try:
                    records.append(
                        record_from_value(
                            item["indicator"],
                            source=self.name,
                            confidence=85,
                            tags=["otx", *pulse_tags],
                            first_seen=item.get("created") or pulse.get("created"),
                            last_seen=pulse.get("modified") or pulse.get("created"),
                            reference=f"https://otx.alienvault.com/pulse/{pulse.get('id', '')}",
                        )
                    )
                except (KeyError, TypeError, ValueError):
                    continue
        return records
