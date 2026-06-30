from __future__ import annotations

import argparse
import json
import logging
import time

import uvicorn

from tip.alerts import AlertSink
from tip.collector import Collector
from tip.config import Settings, get_settings
from tip.feeds import FeodoTrackerFeed, OTXFeed, ThreatFoxFeed, URLhausFeed
from tip.models import FeedRecord, IndicatorType
from tip.policy import DryRunBackend, IptablesBackend, PolicyEnforcer
from tip.siem import ElasticsearchSink
from tip.storage import MongoStore


def make_store(settings: Settings) -> MongoStore:
    store = MongoStore(settings.mongo_uri, settings.mongo_db)
    store.ensure_indexes()
    return store


def make_feeds(settings: Settings):
    feeds = [
        FeodoTrackerFeed(timeout=settings.request_timeout_seconds),
        ThreatFoxFeed(timeout=settings.request_timeout_seconds),
        URLhausFeed(timeout=settings.request_timeout_seconds),
    ]
    if settings.otx_api_key:
        feeds.append(
            OTXFeed(
                settings.otx_api_key,
                timeout=settings.request_timeout_seconds,
            )
        )
    return feeds


def make_enforcer(settings: Settings, store: MongoStore, apply: bool) -> PolicyEnforcer:
    if apply and not settings.firewall_enabled:
        raise SystemExit(
            "Refusing to modify the firewall: set TIP_FIREWALL_ENABLED=true "
            "and pass --apply after reviewing the dry-run output."
        )
    backend = IptablesBackend(settings.firewall_chain) if apply else DryRunBackend([])
    return PolicyEnforcer(
        store=store,
        backend=backend,
        allowlist_cidrs=settings.allowlist,
        risk_threshold=settings.risk_threshold,
        alerts=AlertSink(settings.alert_webhook_url),
        apply=apply,
    )


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="tipctl")
    sub = root.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="Create MongoDB indexes")
    sub.add_parser("collect", help="Fetch, normalize, and store threat feeds")
    sub.add_parser("seed-demo", help="Insert safe documentation-only demo indicators")
    sub.add_parser("sync-siem", help="Export MongoDB records to Elasticsearch")

    enforce = sub.add_parser("enforce", help="Evaluate or apply firewall policy")
    enforce.add_argument("--apply", action="store_true", help="Apply iptables rules")
    enforce.add_argument("--watch", action="store_true", help="Continuously poll")
    enforce.add_argument("--interval", type=int, default=60, help="Polling seconds")

    rollback = sub.add_parser("rollback", help="Remove a managed firewall rule")
    rollback.add_argument("indicator", help="IP address to unblock")
    rollback.add_argument("--apply", action="store_true", help="Apply rollback")

    serve = sub.add_parser("serve", help="Run the API and SOC dashboard")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    return root


def main() -> None:
    args = parser().parse_args()
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    if args.command == "serve":
        uvicorn.run("tip.api:app", host=args.host, port=args.port)
        return

    store = make_store(settings)
    if args.command == "init-db":
        print(json.dumps({"mongodb": "ready"}))
    elif args.command == "collect":
        stats = Collector(store, make_feeds(settings)).run()
        print(json.dumps([item.model_dump() for item in stats], indent=2))
    elif args.command == "seed-demo":
        for source in ("demo-feed-a", "demo-feed-b", "demo-feed-c"):
            store.upsert_indicator(
                FeedRecord(
                    value="203.0.113.66",
                    indicator_type=IndicatorType.IP,
                    source=source,
                    confidence=95,
                    tags=["documentation-only", "test-net-3"],
                )
            )
        print(json.dumps({"demo_indicator": "203.0.113.66", "safe": "reserved TEST-NET address"}))
    elif args.command == "sync-siem":
        result = ElasticsearchSink(
            settings.elastic_url,
            settings.elastic_index_prefix,
        ).sync(store)
        print(json.dumps(result, indent=2))
    elif args.command == "enforce":
        enforcer = make_enforcer(settings, store, args.apply)
        while True:
            print(json.dumps(enforcer.enforce_once(), indent=2))
            if not args.watch:
                break
            time.sleep(max(args.interval, 10))
    elif args.command == "rollback":
        make_enforcer(settings, store, args.apply).rollback(args.indicator)
        print(json.dumps({"rollback": args.indicator, "applied": args.apply}))


if __name__ == "__main__":
    main()
