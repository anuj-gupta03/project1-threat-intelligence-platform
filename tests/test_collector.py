from tip.collector import Collector
from tip.models import FeedRecord, IndicatorType


class FakeFeed:
    name = "fake"

    def fetch(self):
        return [FeedRecord(value="bad.example", indicator_type=IndicatorType.DOMAIN, source="fake", confidence=80)]


class FakeStore:
    def __init__(self):
        self.records = []

    def upsert_indicator(self, record):
        self.records.append(record)


def test_collector_stores_records_and_reports_stats():
    store = FakeStore()
    result = Collector(store, [FakeFeed()]).run()
    assert result[0].accepted == 1
    assert result[0].fetched == 1
    assert store.records[0].value == "bad.example"
