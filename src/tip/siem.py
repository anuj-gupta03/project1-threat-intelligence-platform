from __future__ import annotations

import hashlib
from typing import Any

from elasticsearch import Elasticsearch

from tip.storage import MongoStore


def json_document(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in document.items():
        if key == "_id":
            continue
        if isinstance(value, list):
            result[key] = [str(item) if not isinstance(item, (str, int, float, bool)) else item for item in value]
        elif hasattr(value, "isoformat"):
            result[key] = value.isoformat()
        else:
            result[key] = value
    return result


class ElasticsearchSink:
    def __init__(self, url: str, index_prefix: str = "tip") -> None:
        self.client = Elasticsearch(url)
        self.indicator_index = f"{index_prefix}-indicators"
        self.action_index = f"{index_prefix}-policy-actions"

    def ensure_indexes(self) -> None:
        if not self.client.indices.exists(index=self.indicator_index):
            self.client.indices.create(
                index=self.indicator_index,
                mappings={
                    "properties": {
                        "value": {"type": "keyword"},
                        "type": {"type": "keyword"},
                        "sources": {"type": "keyword"},
                        "tags": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "risk_score": {"type": "integer"},
                        "confidence": {"type": "integer"},
                        "first_seen": {"type": "date"},
                        "last_seen": {"type": "date"},
                        "updated_at": {"type": "date"},
                        "policy_state": {"type": "keyword"},
                    }
                },
            )
        if not self.client.indices.exists(index=self.action_index):
            self.client.indices.create(
                index=self.action_index,
                mappings={
                    "properties": {
                        "indicator": {"type": "ip"},
                        "action": {"type": "keyword"},
                        "mode": {"type": "keyword"},
                        "success": {"type": "boolean"},
                        "reason": {"type": "text"},
                        "risk_score": {"type": "integer"},
                        "created_at": {"type": "date"},
                    }
                },
            )

    def sync(self, store: MongoStore) -> dict[str, int]:
        self.ensure_indexes()
        indicators = store.list_indicators(limit=1000)
        actions = store.list_policy_actions(limit=1000)
        for item in indicators:
            identity = hashlib.sha256(f"{item['type']}:{item['value']}".encode()).hexdigest()
            self.client.index(
                index=self.indicator_index,
                id=identity,
                document=json_document(item),
            )
        for item in actions:
            self.client.index(
                index=self.action_index,
                id=str(item["_id"]),
                document=json_document(item),
            )
        self.client.indices.refresh(index=f"{self.indicator_index},{self.action_index}")
        return {"indicators": len(indicators), "policy_actions": len(actions)}
