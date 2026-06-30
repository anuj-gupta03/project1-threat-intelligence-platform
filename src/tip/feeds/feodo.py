from __future__ import annotations

from tip.feeds.base import ThreatFeed, record_from_value
from tip.models import FeedRecord


class FeodoTrackerFeed(ThreatFeed):
    name = "feodo_tracker"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    def fetch(self) -> list[FeedRecord]:
        response = self.session.get(self.url, timeout=self.timeout)
        response.raise_for_status()
        records: list[FeedRecord] = []
        for item in response.json()[: self.limit]:
            try:
                records.append(
                    record_from_value(
                        item["ip_address"],
                        source=self.name,
                        confidence=95,
                        tags=["botnet-c2", str(item.get("malware", "unknown")).lower()],
                        first_seen=item.get("first_seen"),
                        last_seen=item.get("last_online") or item.get("first_seen"),
                        reference=self.url,
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
        return records
