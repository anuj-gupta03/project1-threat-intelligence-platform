# Threat model

## Assets

- Threat indicators and source provenance
- API keys and webhook URLs
- MongoDB and Elasticsearch records
- Firewall availability and rule integrity
- Analyst audit history

## Trust boundaries

- Public OSINT services are untrusted inputs.
- MongoDB and Elasticsearch are internal lab services.
- The policy enforcer crosses from application logic into privileged operating-system state.
- Alert webhooks cross an external network boundary.

## Main abuse cases and controls

| Risk | Impact | Control |
|---|---|---|
| Malformed feed data | Parser failure or poisoned records | Strict IP/domain validation, timeouts, record limits |
| Duplicate indicators | Inflated analyst workload | Unique type/value index and upsert |
| False-positive block | Service outage | Risk threshold, source corroboration, dry-run, allowlist, rollback |
| Blocking internal ranges | Loss of management access | Reject all non-global and configured allowlisted networks |
| Command injection | Host compromise | Validate addresses and use subprocess argument arrays without a shell |
| Accidental enforcement | Unauthorized firewall changes | Disabled configuration plus explicit --apply flag |
| Compromised container | Lateral movement | Non-root application container and localhost-only exposed ports |
| Secret disclosure | API abuse | Environment variables, .env ignored by Git |
| Audit modification | Loss of accountability | Append-only policy action records; restrict database write access |
| Feed outage | Stale intelligence | Per-feed error isolation and collection statistics |

## Residual risks

- Public feeds can contain incorrect or stale indicators.
- The development Docker Compose configuration disables Elasticsearch authentication.
- MongoDB audit records are not cryptographically immutable.
- iptables protects only the host and does not block domains.

These are acceptable for an isolated internship lab, not for a production bank. Production deployment requires authentication, TLS, database access controls, signed audit logs, change approval, high availability, and staged policy rollout.
