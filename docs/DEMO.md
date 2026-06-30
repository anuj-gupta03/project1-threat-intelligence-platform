# Evaluation demonstration

## Safe demo sequence

1. Show the four-week GitHub contribution graph and pull requests.
2. Start the Docker lab.
3. Open the API health endpoint.
4. Run the collector and explain each feed's collection statistics.
5. Open the SOC dashboard and filter critical IP indicators.
6. Run the Elasticsearch sync.
7. Open the Kibana dashboard and explain severity, source, and recency.
8. Run the policy enforcer without --apply.
9. Show that private and reserved addresses are rejected.
10. Show the MongoDB policy-action audit through GET /policy/actions.
11. In an isolated Linux VM, demonstrate one authorized block.
12. Immediately demonstrate rollback.
13. Show test, lint, Bandit, dependency-audit, and Docker-build CI results.

## Evidence to capture

- Successful and partially failed feed collection
- Deduplication of one indicator reported by multiple sources
- Critical score caused by corroboration
- Dry-run block decision
- Protected private or reserved address
- Dedicated TIP_BLOCKLIST chain
- Successful analyst rollback
- Kibana dashboard
- Green GitHub Actions workflow

Never use a production server, campus network, or personal daily-use machine for the firewall demonstration.
