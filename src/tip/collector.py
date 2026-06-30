from __future__ import annotations

import logging

from tip.feeds.base import ThreatFeed
from tip.models import CollectionStats
from tip.storage import MongoStore

logger = logging.getLogger(__name__)


class Collector:
    def __init__(self, store: MongoStore, feeds: list[ThreatFeed]) -> None:
        self.store = store
        self.feeds = feeds

    def run(self) -> list[CollectionStats]:
        results: list[CollectionStats] = []
        for feed in self.feeds:
            stats = CollectionStats(feed=feed.name)
            try:
                records = feed.fetch()
                stats.fetched = len(records)
                for record in records:
                    try:
                        self.store.upsert_indicator(record)
                        stats.accepted += 1
                    except (TypeError, ValueError) as exc:
                        logger.warning("Rejected %s record: %s", feed.name, exc)
                        stats.rejected += 1
            except Exception as exc:
                logger.exception("Feed collection failed: %s", feed.name)
                stats.error = str(exc)
            results.append(stats)
        return results
