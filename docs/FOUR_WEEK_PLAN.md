# Four-week engineering and Git plan

The evaluator requires contributions throughout all four weeks. Use short-lived branches, pull requests, local rebasing, and squash merges. Never fabricate or rewrite dates.

## Week 1: ingestion and MongoDB

Goals:

- Establish the Python package and Docker lab
- Integrate Feodo Tracker, ThreatFox, URLhaus, and OTX
- Normalize IPs and domains
- Add unique MongoDB indexes and risk scoring

Suggested branches and commits:

- feature/project-scaffold - feat: create TIP project structure
- feature/feodo-threatfox - feat: ingest Feodo and ThreatFox indicators
- feature/urlhaus-otx - feat: add URLhaus and OTX collectors
- feature/normalization - feat: normalize and deduplicate indicators
- tests/collector - test: cover feed normalization and collection

## Week 2: SIEM and dashboard

Goals:

- Export indicators to Elasticsearch
- Create Kibana data views and panels
- Build the FastAPI SOC overview
- Document the scoring model

Suggested commits:

- feat: export normalized indicators to Elasticsearch
- feat: add SOC summary API
- feat: create analyst dashboard
- docs: document Kibana threat views

## Week 3: policy engine

Goals:

- Implement dedicated-chain iptables management
- Protect local, private, reserved, and allowlisted ranges
- Add dual approval gates and dry-run mode
- Record every policy decision

Suggested commits:

- feat: evaluate high-risk IP policy candidates
- feat: add dry-run firewall backend
- feat: manage dedicated iptables chain
- fix: protect allowlisted and non-global addresses
- test: verify block safety gates

## Week 4: rollback, alerts, tests, and reporting

Goals:

- Add false-positive rollback
- Add webhook alerts
- Complete CI and security scans
- Capture successful and failed test evidence
- Finalize the report and architecture diagram

Suggested commits:

- feat: add analyst rollback workflow
- feat: send policy-action alerts
- ci: run tests and security checks
- docs: add deployment and incident runbooks
- docs: publish final evaluation evidence

## Pull-request workflow

1. Create a feature branch from an updated main branch.
2. Make small imperative commits.
3. Run tests and security checks.
4. Rebase locally onto main.
5. Open a pull request.
6. Review the diff and CI output.
7. Squash merge.
8. Delete the feature branch.
