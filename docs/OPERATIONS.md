# Operations runbook

## Collection

Run collection manually or schedule it every 15 minutes:

~~~bash
tipctl collect
~~~

One feed failure does not stop the others. Review the returned fetched, accepted, rejected, and error fields.

## SIEM synchronization

~~~bash
tipctl sync-siem
~~~

This upserts indicators and policy actions into stable Elasticsearch indexes.

## Policy preview

~~~bash
tipctl enforce
~~~

This is dry-run mode. It records decisions but does not execute iptables.

## Applying policy

Before applying:

1. Confirm the machine is an authorized Linux lab VM.
2. Ensure console access is available if remote connectivity fails.
3. Review the allowlist.
4. Review candidates with GET /indicators?minimum_risk=85&type=ip.
5. Run dry-run.
6. Set TIP_FIREWALL_ENABLED=true.
7. Apply once before using watch mode.

## Rollback

~~~bash
tipctl rollback 1.2.3.4
tipctl rollback 1.2.3.4 --apply
~~~

The first command previews and audits the rollback. The second applies it when the environment gate is enabled.

## Emergency recovery

From the VM console:

~~~bash
iptables -L TIP_BLOCKLIST -n --line-numbers
iptables -D TIP_BLOCKLIST <rule-number>
~~~

Do not flush INPUT. Remove only the specific TIP-managed rule.

## Shutdown

~~~bash
docker compose down
~~~

To remove lab data deliberately:

~~~bash
docker compose down -v
~~~

The second command permanently deletes MongoDB and Elasticsearch volumes.
