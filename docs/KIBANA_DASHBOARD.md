# Kibana dashboard

Run tipctl sync-siem before creating the dashboard.

## Data views

Create these data views in Stack Management:

| Name | Index pattern | Time field |
|---|---|---|
| TIP Indicators | tip-indicators | last_seen |
| TIP Policy Actions | tip-policy-actions | created_at |

## Dashboard panels

Create a dashboard named Threat Intelligence and Policy Overview.

1. Metric: total indicators
   - Data view: TIP Indicators
   - Metric: Records

2. Donut: severity distribution
   - Data view: TIP Indicators
   - Slice by: severity.keyword if available, otherwise severity

3. Bar chart: top intelligence sources
   - Data view: TIP Indicators
   - Break down by: sources

4. Line chart: indicators observed over time
   - Data view: TIP Indicators
   - Horizontal axis: last_seen
   - Break down by: severity

5. Metric: actively blocked indicators
   - Data view: TIP Indicators
   - Filter: policy_state : "blocked"

6. Table: policy action audit
   - Data view: TIP Policy Actions
   - Columns: created_at, indicator, action, mode, success, risk_score, reason

7. Bar chart: applied blocks and rollbacks
   - Data view: TIP Policy Actions
   - Filter: mode : "apply"
   - Break down by: action

Save the dashboard and export it from Stack Management, Saved Objects as part of the final evaluation evidence.
