from __future__ import annotations

import csv
import io

from tip.feeds.base import ThreatFeed, record_from_value
from tip.models import FeedRecord


class URLhausFeed(ThreatFeed):
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    def fetch(self) -> list[FeedRecord]:
        response = self.session.get(self.url, timeout=self.timeout)
        response.raise_for_status()
        lines = [line for line in response.text.splitlines() if not line.startswith("#")]
        records: list[FeedRecord] = []
        reader = csv.reader(io.StringIO("\n".join(lines)))
        for row in reader:
            if len(row) < 8 or len(records) >= self.limit:
                continue
            try:
                records.append(
                    record_from_value(
                        row[2],
                        source=self.name,
                        confidence=80,
                        tags=["malware-url", row[5], *row[6].split(",")],
                        first_seen=row[1],
                        last_seen=row[4] or row[1],
                        reference=row[7],
                    )
                )
            except (TypeError, ValueError):
                continue
        return records
