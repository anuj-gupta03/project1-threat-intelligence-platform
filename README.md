<<<<<<< HEAD
# Advanced Threat Intelligence Platform and Dynamic Policy Enforcer

A safe-by-default implementation of Infotact Cybersecurity Project 1. The platform collects public threat intelligence, normalizes and deduplicates indicators, assigns risk scores, stores them in MongoDB, exports them to Elasticsearch/Kibana, and can manage high-risk IP blocks through a dedicated Linux iptables chain.

## What is implemented

- Four OSINT integrations: Feodo Tracker, ThreatFox, URLhaus, and optional AlienVault OTX
- IP and domain normalization, refanging, validation, and MongoDB deduplication
- Corroboration-aware 0-100 risk scoring
- FastAPI SOC dashboard and read-only API
- Elasticsearch export for Kibana analysis
- Dry-run-first policy enforcement
- Dedicated TIP_BLOCKLIST iptables chain
- Private, reserved, and configured CIDR protection
- Analyst rollback and immutable policy-action history
- Optional webhook alerting
- Docker Compose lab, automated tests, and GitHub Actions CI

## Architecture

~~~mermaid
flowchart LR
  F1[Feodo Tracker] --> C[Python Collector]
  F2[ThreatFox] --> C
  F3[URLhaus] --> C
  F4[AlienVault OTX] --> C
  C --> N[Normalize and deduplicate]
  N --> M[(MongoDB)]
  M --> A[FastAPI SOC Dashboard]
  M --> S[Elasticsearch Sync]
  S --> K[Kibana]
  M --> P[Policy Enforcer]
  P --> G{Safety gates}
  G -->|Dry run| L[Audit log]
  G -->|Explicit apply on Linux| I[Dedicated iptables chain]
  I --> L
  L --> M
~~~

## Quick start

Requirements: Docker Desktop with Compose and approximately 2 GB of free memory.

1. Copy the environment template:

   ~~~powershell
   Copy-Item .env.example .env
   ~~~

2. Start MongoDB, Elasticsearch, Kibana, and the SOC dashboard:

   ~~~powershell
   docker compose up -d mongo elasticsearch kibana api
   ~~~

3. Collect public intelligence:

   ~~~powershell
   docker compose --profile jobs run --rm collector
   ~~~

4. Export it to Elasticsearch:

   ~~~powershell
   docker compose --profile jobs run --rm siem-sync
   ~~~

5. Review the interfaces:

   - SOC dashboard: http://127.0.0.1:8000
   - API documentation: http://127.0.0.1:8000/docs
   - Kibana: http://127.0.0.1:5601

6. Preview policy decisions without changing the firewall:

   ~~~powershell
   docker compose --profile jobs run --rm enforcer-dry-run
   ~~~

The Docker enforcer is intentionally dry-run only.

For an offline safety demonstration, run `docker compose run --rm api seed-demo`. It inserts only the reserved TEST-NET address 203.0.113.66; the policy engine must reject it as non-global.

## AlienVault OTX

Create an OTX API key and place it only in the local .env file:

~~~text
TIP_OTX_API_KEY=your_key_here
~~~

Never commit .env. The three abuse.ch feeds work without credentials, so OTX is optional.

## Kibana setup

After the first SIEM sync:

1. Open Kibana and go to Stack Management, then Data Views.
2. Create a data view named TIP Indicators using tip-indicators.
3. Set last_seen as the time field.
4. Create a second data view named TIP Policy Actions using tip-policy-actions.
5. Build Lens panels for indicators by severity, top sources, risk over time, and applied block/rollback actions.

See docs/KIBANA_DASHBOARD.md for the exact panel definitions.

## Real firewall enforcement

Only perform this inside an authorized, disposable Linux lab VM. Review the MongoDB candidates and dry-run output first.

The enforcer requires two independent approvals:

- TIP_FIREWALL_ENABLED=true
- The explicit --apply command flag

Example on the Linux host:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
export TIP_MONGO_URI='mongodb://127.0.0.1:27017'
export TIP_FIREWALL_ENABLED=true
sudo -E .venv/bin/tipctl enforce --apply
~~~

Continuously monitor every 60 seconds:

~~~bash
sudo -E .venv/bin/tipctl enforce --apply --watch --interval 60
~~~

Rollback a false positive:

~~~bash
sudo -E .venv/bin/tipctl rollback 1.2.3.4 --apply
~~~

The implementation creates only TIP_BLOCKLIST and attaches it to INPUT. It never flushes the firewall or edits unrelated rules.

## API

- GET /health
- GET /summary
- GET /indicators
- GET /indicators?severity=critical&type=ip
- GET /policy/actions

The API has no authentication because this is an isolated internship lab. Keep it bound to localhost. Add authentication and TLS before any shared deployment.

## Risk model

- Feed confidence: up to 70 points
- Independent source corroboration: up to 20 points
- Recency: up to 10 points
- Critical threshold: 85 by default

A high score is not sufficient by itself. The firewall module also rejects private, reserved, loopback, multicast, and explicitly allowlisted addresses.

## Development

~~~bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check src tests
bandit -q -r src
~~~

## Project documentation

- docs/FOUR_WEEK_PLAN.md - sprint and GitHub contribution plan
- docs/THREAT_MODEL.md - abuse cases and mitigations
- docs/KIBANA_DASHBOARD.md - dashboard construction
- docs/DEMO.md - evaluation demonstration
- docs/OPERATIONS.md - collection, enforcement, rollback, and recovery

## Important evaluation note

The internship specification requires visible GitHub commits during all four weeks. Do not upload this project in one final commit. Follow the branch and commit schedule in docs/FOUR_WEEK_PLAN.md.
=======
# project1-threat-intelligence-platform
>>>>>>> 71e7c9175584a7be59855db1fc2b786e0a5a9c78
