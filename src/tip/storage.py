from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pymongo import ASCENDING, DESCENDING, MongoClient, ReturnDocument

from tip.models import FeedRecord, IndicatorType
from tip.scoring import calculate_risk, severity_for


def utcnow() -> datetime:
    return datetime.now(UTC)


class MongoStore:
    def __init__(self, uri: str, database: str) -> None:
        self.client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        self.db = self.client[database]
        self.indicators = self.db.indicators
        self.policy_actions = self.db.policy_actions

    def ensure_indexes(self) -> None:
        self.indicators.create_index(
            [("type", ASCENDING), ("value", ASCENDING)],
            unique=True,
            name="unique_indicator",
        )
        self.indicators.create_index(
            [("risk_score", DESCENDING), ("last_seen", DESCENDING)],
            name="risk_and_recency",
        )
        self.policy_actions.create_index(
            [("indicator", ASCENDING), ("created_at", DESCENDING)],
            name="action_history",
        )

    def ping(self) -> bool:
        return bool(self.client.admin.command("ping").get("ok"))

    def upsert_indicator(self, record: FeedRecord) -> dict[str, Any]:
        now = utcnow()
        document = self.indicators.find_one_and_update(
            {"type": record.indicator_type.value, "value": record.value},
            {
                "$setOnInsert": {
                    "created_at": now,
                    "status": "active",
                    "policy_state": "not_blocked",
                },
                "$set": {
                    "updated_at": now,
                    "reference": record.reference,
                },
                "$min": {"first_seen": record.first_seen},
                "$max": {
                    "last_seen": record.last_seen,
                    "confidence": record.confidence,
                },
                "$addToSet": {
                    "sources": record.source,
                    "tags": {"$each": record.tags},
                },
            },
            upsert=True,
            return_document=ReturnDocument.AFTER,
        )
        score = calculate_risk(
            int(document.get("confidence", 0)),
            len(document.get("sources", [])),
            document.get("last_seen", now),
        )
        severity = severity_for(score).value
        self.indicators.update_one(
            {"_id": document["_id"]},
            {"$set": {"risk_score": score, "severity": severity}},
        )
        document["risk_score"] = score
        document["severity"] = severity
        return document

    def list_indicators(
        self,
        *,
        severity: str | None = None,
        indicator_type: str | None = None,
        minimum_risk: int | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if severity:
            query["severity"] = severity
        if indicator_type:
            query["type"] = indicator_type
        if minimum_risk is not None:
            query["risk_score"] = {"$gte": minimum_risk}
        return list(
            self.indicators.find(query)
            .sort([("risk_score", DESCENDING), ("last_seen", DESCENDING)])
            .limit(min(max(limit, 1), 1000))
        )

    def enforcement_candidates(self, minimum_risk: int, limit: int = 500) -> list[dict[str, Any]]:
        return list(
            self.indicators.find(
                {
                    "type": IndicatorType.IP.value,
                    "status": "active",
                    "risk_score": {"$gte": minimum_risk},
                    "policy_state": {"$ne": "blocked"},
                }
            )
            .sort("risk_score", DESCENDING)
            .limit(limit)
        )

    def record_policy_action(
        self,
        *,
        indicator: str,
        action: str,
        mode: str,
        success: bool,
        reason: str,
        risk_score: int | None = None,
    ) -> str:
        result = self.policy_actions.insert_one(
            {
                "indicator": indicator,
                "action": action,
                "mode": mode,
                "success": success,
                "reason": reason,
                "risk_score": risk_score,
                "created_at": utcnow(),
            }
        )
        if success and mode == "apply":
            state = "blocked" if action == "block" else "not_blocked"
            self.indicators.update_one(
                {"type": "ip", "value": indicator},
                {"$set": {"policy_state": state, "updated_at": utcnow()}},
            )
        return str(result.inserted_id)

    def list_policy_actions(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(
            self.policy_actions.find()
            .sort("created_at", DESCENDING)
            .limit(min(max(limit, 1), 1000))
        )

    def summary(self) -> dict[str, Any]:
        severity_counts = {
            item["_id"]: item["count"]
            for item in self.indicators.aggregate(
                [{"$group": {"_id": "$severity", "count": {"$sum": 1}}}]
            )
        }
        return {
            "total_indicators": self.indicators.count_documents({}),
            "blocked_indicators": self.indicators.count_documents({"policy_state": "blocked"}),
            "severity": severity_counts,
            "sources": self.indicators.distinct("sources"),
        }
