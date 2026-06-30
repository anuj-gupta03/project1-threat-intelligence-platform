from __future__ import annotations

from typing import Any

from bson import ObjectId
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse

from tip.config import Settings, get_settings
from tip.storage import MongoStore


def serializable(value: Any) -> Any:
    if isinstance(value, ObjectId):
        return str(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, list):
        return [serializable(item) for item in value]
    if isinstance(value, dict):
        return {key: serializable(item) for key, item in value.items()}
    return value


DASHBOARD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Threat Intelligence Platform</title>
<style>
body{font-family:system-ui;background:#08111f;color:#e5edf7;margin:0;padding:2rem}
h1{margin-top:0}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:1rem}
.card,table{background:#111d2e;border:1px solid #263750;border-radius:10px}.card{padding:1rem}
strong{font-size:1.7rem;display:block}table{width:100%;margin-top:1rem;border-collapse:collapse}
th,td{text-align:left;padding:.7rem;border-bottom:1px solid #263750}small{color:#9fb0c7}
.critical{color:#ff6b6b}.high{color:#ffb86b}.medium{color:#ffe66d}.low{color:#8ce99a}
</style></head>
<body><h1>Threat Intelligence Platform</h1><small>Read-only SOC overview</small>
<div class="cards" id="cards"></div>
<table><thead><tr><th>Indicator</th><th>Type</th><th>Risk</th><th>Severity</th><th>Sources</th><th>Policy</th></tr></thead>
<tbody id="rows"></tbody></table>
<script>
async function load(){
 const s=await fetch('/summary').then(r=>r.json());
 const i=await fetch('/indicators?limit=100').then(r=>r.json());
 const parts=[['Indicators',s.total_indicators],['Blocked',s.blocked_indicators],
 ['Critical',s.severity.critical||0],['High',s.severity.high||0]];
 document.querySelector('#cards').innerHTML=parts.map(x=>'<div class="card"><small>'+x[0]+'</small><strong>'+x[1]+'</strong></div>').join('');
 document.querySelector('#rows').innerHTML=i.map(x=>'<tr><td>'+x.value+'</td><td>'+x.type+'</td><td>'+x.risk_score+'</td><td class="'+x.severity+'">'+x.severity+'</td><td>'+(x.sources||[]).join(', ')+'</td><td>'+x.policy_state+'</td></tr>').join('');
}load();
</script></body></html>"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = MongoStore(settings.mongo_uri, settings.mongo_db)
    app = FastAPI(title="Threat Intelligence Platform", version="0.1.0")

    @app.on_event("startup")
    def startup() -> None:
        store.ensure_indexes()

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return DASHBOARD

    @app.get("/health")
    def health() -> dict[str, object]:
        return {"status": "ok", "mongodb": store.ping()}

    @app.get("/summary")
    def summary() -> dict[str, Any]:
        return serializable(store.summary())

    @app.get("/indicators")
    def indicators(
        severity: str | None = None,
        indicator_type: str | None = Query(default=None, alias="type"),
        minimum_risk: int | None = Query(default=None, ge=0, le=100),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> list[dict[str, Any]]:
        return serializable(
            store.list_indicators(
                severity=severity,
                indicator_type=indicator_type,
                minimum_risk=minimum_risk,
                limit=limit,
            )
        )

    @app.get("/policy/actions")
    def policy_actions(limit: int = Query(default=100, ge=1, le=1000)) -> list[dict[str, Any]]:
        return serializable(store.list_policy_actions(limit=limit))

    return app


app = create_app()
