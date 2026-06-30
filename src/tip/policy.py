from __future__ import annotations

import ipaddress
import logging
import os
import platform
import subprocess
from dataclasses import dataclass
from typing import Protocol

from tip.alerts import AlertSink
from tip.models import PolicyDecision
from tip.storage import MongoStore

logger = logging.getLogger(__name__)


class FirewallBackend(Protocol):
    def block(self, ip: str) -> None: ...
    def unblock(self, ip: str) -> None: ...


@dataclass
class DryRunBackend:
    actions: list[tuple[str, str]]

    def block(self, ip: str) -> None:
        self.actions.append(("block", ip))
        logger.warning("DRY RUN: would block %s", ip)

    def unblock(self, ip: str) -> None:
        self.actions.append(("unblock", ip))
        logger.warning("DRY RUN: would unblock %s", ip)


class IptablesBackend:
    """Manage only a dedicated chain; never flush or replace unrelated rules."""

    def __init__(self, chain: str = "TIP_BLOCKLIST") -> None:
        if platform.system() != "Linux":
            raise RuntimeError("iptables enforcement is supported only on Linux")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise PermissionError("iptables enforcement requires root privileges")
        if not chain.replace("_", "").isalnum():
            raise ValueError("Invalid iptables chain name")
        self.chain = chain
        self._ensure_chain()

    @staticmethod
    def _run(arguments: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # nosec B603 - fixed executable and validated arguments
            ["iptables", "-w", "5", *arguments],
            check=check,
            text=True,
            capture_output=True,
        )

    def _ensure_chain(self) -> None:
        self._run(["-N", self.chain], check=False)
        attached = self._run(["-C", "INPUT", "-j", self.chain], check=False)
        if attached.returncode != 0:
            self._run(["-I", "INPUT", "1", "-j", self.chain])

    def block(self, ip: str) -> None:
        rule = ["-s", ip, "-m", "comment", "--comment", "tip-managed", "-j", "DROP"]
        exists = self._run(["-C", self.chain, *rule], check=False)
        if exists.returncode != 0:
            self._run(["-A", self.chain, *rule])

    def unblock(self, ip: str) -> None:
        rule = ["-s", ip, "-m", "comment", "--comment", "tip-managed", "-j", "DROP"]
        exists = self._run(["-C", self.chain, *rule], check=False)
        if exists.returncode == 0:
            self._run(["-D", self.chain, *rule])


class PolicyEnforcer:
    def __init__(
        self,
        store: MongoStore,
        backend: FirewallBackend,
        allowlist_cidrs: list[str],
        risk_threshold: int,
        alerts: AlertSink | None = None,
        apply: bool = False,
    ) -> None:
        self.store = store
        self.backend = backend
        self.allowlist = [ipaddress.ip_network(cidr) for cidr in allowlist_cidrs]
        self.risk_threshold = risk_threshold
        self.alerts = alerts or AlertSink(None)
        self.apply = apply

    def evaluate(self, indicator: str, risk_score: int) -> PolicyDecision:
        try:
            address = ipaddress.ip_address(indicator)
        except ValueError:
            return PolicyDecision(
                indicator=indicator,
                eligible=False,
                reason="not a valid IP address",
                risk_score=risk_score,
            )
        if address.version != 4:
            return PolicyDecision(
                indicator=indicator,
                eligible=False,
                reason="IPv6 enforcement is not supported by this backend",
                risk_score=risk_score,
            )
        if not address.is_global:
            return PolicyDecision(
                indicator=indicator,
                eligible=False,
                reason="non-global address is protected",
                risk_score=risk_score,
            )
        if any(address in network for network in self.allowlist):
            return PolicyDecision(
                indicator=indicator,
                eligible=False,
                reason="address is allowlisted",
                risk_score=risk_score,
            )
        if risk_score < self.risk_threshold:
            return PolicyDecision(
                indicator=indicator,
                eligible=False,
                reason="risk score is below threshold",
                risk_score=risk_score,
            )
        return PolicyDecision(
            indicator=indicator,
            eligible=True,
            reason="global IP meets risk threshold",
            risk_score=risk_score,
        )

    def enforce_once(self) -> dict[str, int]:
        result = {"evaluated": 0, "blocked": 0, "skipped": 0, "failed": 0}
        for item in self.store.enforcement_candidates(self.risk_threshold):
            result["evaluated"] += 1
            indicator = item["value"]
            score = int(item.get("risk_score", 0))
            decision = self.evaluate(indicator, score)
            if not decision.eligible:
                result["skipped"] += 1
                self.store.record_policy_action(
                    indicator=indicator,
                    action="block",
                    mode="apply" if self.apply else "dry-run",
                    success=False,
                    reason=decision.reason,
                    risk_score=score,
                )
                continue
            try:
                self.backend.block(indicator)
                result["blocked"] += 1
                self.store.record_policy_action(
                    indicator=indicator,
                    action="block",
                    mode="apply" if self.apply else "dry-run",
                    success=True,
                    reason=decision.reason,
                    risk_score=score,
                )
                self.alerts.policy_action(
                    {
                        "indicator": indicator,
                        "action": "block",
                        "mode": "apply" if self.apply else "dry-run",
                        "risk_score": score,
                    }
                )
            except Exception as exc:
                result["failed"] += 1
                self.store.record_policy_action(
                    indicator=indicator,
                    action="block",
                    mode="apply" if self.apply else "dry-run",
                    success=False,
                    reason=str(exc),
                    risk_score=score,
                )
        return result

    def rollback(self, indicator: str) -> None:
        normalized = str(ipaddress.ip_address(indicator))
        self.backend.unblock(normalized)
        self.store.record_policy_action(
            indicator=normalized,
            action="unblock",
            mode="apply" if self.apply else "dry-run",
            success=True,
            reason="analyst-requested rollback",
        )
        self.alerts.policy_action(
            {
                "indicator": normalized,
                "action": "unblock",
                "mode": "apply" if self.apply else "dry-run",
            }
        )
