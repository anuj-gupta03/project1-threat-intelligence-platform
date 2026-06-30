from __future__ import annotations

from tip.feeds.base import ThreatFeed, record_from_value
from tip.models import FeedRecord


class ThreatFoxFeed(ThreatFeed):
    name = "threatfox"
    url = "https://threatfox-api.abuse.ch/api/v1/"

    def fetch(self) -> list[FeedRecord]:
        response = self.session.post(
            self.url,
            json={"query": "get_iocs", "days": 3},
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        data = payload.get("data")
        if not isinstance(data, list):
            return []
        records: list[FeedRecord] = []
        for item in data[: self.limit]:
            try:
                records.append(
                    record_from_value(
                        item["ioc"],
                        source=self.name,
                        confidence=min(95, int(item.get("confidence_level") or 75)),
                        tags=[
                            str(item.get("threat_type", "malware")),
                            str(item.get("malware_printable", "unknown")).lower(),
                        ],
                        first_seen=item.get("first_seen"),
                        last_seen=item.get("last_seen") or item.get("first_seen"),
                        reference=item.get("reference") or self.url,
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return records
