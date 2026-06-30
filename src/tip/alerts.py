from __future__ import annotations

import logging

import requests

logger = logging.getLogger(__name__)


class AlertSink:
    def __init__(self, webhook_url: str | None, timeout: int = 10) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def policy_action(self, payload: dict[str, object]) -> None:
        logger.warning("Policy action: %s", payload)
        if not self.webhook_url:
            return
        response = requests.post(self.webhook_url, json=payload, timeout=self.timeout)
        response.raise_for_status()
