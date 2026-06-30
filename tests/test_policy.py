from tip.policy import DryRunBackend, PolicyEnforcer


class FakeStore:
    def __init__(self, candidates):
        self.candidates = candidates
        self.actions = []

    def enforcement_candidates(self, minimum_risk):
        return [x for x in self.candidates if x["risk_score"] >= minimum_risk]

    def record_policy_action(self, **kwargs):
        self.actions.append(kwargs)
        return "action-id"


def test_dry_run_blocks_global_high_risk_ip():
    store = FakeStore([{"value": "8.8.8.8", "risk_score": 90}])
    backend = DryRunBackend([])
    enforcer = PolicyEnforcer(store, backend, [], 85, apply=False)
    result = enforcer.enforce_once()
    assert result["blocked"] == 1
    assert backend.actions == [("block", "8.8.8.8")]
    assert store.actions[0]["mode"] == "dry-run"


def test_never_blocks_private_or_allowlisted_ip():
    store = FakeStore([
        {"value": "10.0.0.7", "risk_score": 99},
        {"value": "8.8.8.8", "risk_score": 99},
    ])
    backend = DryRunBackend([])
    enforcer = PolicyEnforcer(store, backend, ["8.8.8.0/24"], 85)
    result = enforcer.enforce_once()
    assert result["skipped"] == 2
    assert backend.actions == []


def test_ipv6_is_not_sent_to_ipv4_firewall_backend():
    store = FakeStore([{"value": "2001:4860:4860::8888", "risk_score": 99}])
    backend = DryRunBackend([])
    result = PolicyEnforcer(store, backend, [], 85).enforce_once()
    assert result["skipped"] == 1
    assert backend.actions == []


def test_rollback_is_audited():
    store = FakeStore([])
    backend = DryRunBackend([])
    enforcer = PolicyEnforcer(store, backend, [], 85)
    enforcer.rollback("8.8.8.8")
    assert backend.actions == [("unblock", "8.8.8.8")]
    assert store.actions[0]["action"] == "unblock"
