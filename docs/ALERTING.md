# Alerting: risk rules, grouping policy and triage

Two decisions are made for every analysed flow: **how risky is it** (risk level) and **does it become
an alert** (grouping policy). Both are deterministic, both are exposed by the API, and nothing in the
UI paraphrases them — the Alerts page renders `GET /api/alerts/rules` verbatim.

## 1. Risk score

```
risk_score = attack_severity_weight[predicted_class] × confidence + sensitive_port_bonus

sensitive_port_bonus = 0.05 for each flow whose destination port is in the sensitive list, capped at 0.10
```

| Level | Threshold | Meaning |
| --- | --- | --- |
| CRITICAL | `≥ 0.96` | a high-severity family at near-certain confidence (e.g. Bot/DDoS/Infiltration ≥ 0.96) |
| HIGH | `≥ 0.85` | high-severity family with strong confidence, or a medium family on a sensitive port |
| MEDIUM | `≥ 0.65` | credible attack prediction |
| LOW | `< 0.65` | everything else — including **all** normal traffic |

Severity weights: Infiltration 1.00, Heartbleed 0.98, DDoS 0.95, Bot 0.92, Web Attack 0.88,
Brute Force 0.86, DoS 0.80, Port Scanning 0.72 (unknown class 0.75).
Sensitive ports: 21, 22, 23, 25, 110, 135, 139, 143, 445, 993, 995, 1433, 1521, 2049, 3306, 3389,
5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017.

Two properties worth pointing out in a viva:

* **Normal traffic can never alert.** Its score only records model uncertainty
  (`(1 − confidence) × 0.4`) so it can still be sorted, and it is always LOW.
* **CRITICAL is reachable but not automatic.** Port Scanning tops out at `0.72 + 0.10 = 0.82`, so a
  port sweep — the most common event in the sample data — is HIGH at best. Reaching CRITICAL requires
  a high-severity family *and* high confidence.

Worked examples (real model output): PortScan 0.999 on :80 → MEDIUM 0.719; DoS 1.0 → MEDIUM 0.80;
DDoS 1.0 → HIGH 0.95; Bot 0.999 → CRITICAL 0.969; Infiltration 1.0 on :22 → CRITICAL 1.00.

## 2. Which flows become alerts, and how many

1. Only attack predictions with risk **MEDIUM, HIGH or CRITICAL** are eligible (LOW never alerts).
2. Eligible flows are ranked by risk score (confidence breaks ties) and processed in that order.
3. The **first flow of each `(attack type, destination port)` pair creates that pair's alert**.
   Every further flow of the same pair is folded into it: `occurrences=N` grows, the severity is
   raised if a worse flow joins, `confidence` keeps the maximum, and `prediction_id` stays on the
   highest-risk record of the pair. A pair that occurs once keeps its single-flow form; because the
   fold is what produces `"<Attack> (burst)"` alerts, real captures are dominated by bursts. Only the
   first 50 *created* alerts can remain single-flow (nothing else changes about the policy).
4. **Ceiling:** at most 300 distinct pairs own an alert per job. Flows of pairs beyond that ceiling
   fold into one overflow alert per attack type (`destination_port = null`), so even a pathological
   50 000-port sweep cannot flood the queue.

**Invariants** (asserted by the test suite):
* exactly one alert per `(attack type, destination port)` per job — no duplicates, ever;
* every alert records `occurrences=N` and links a real prediction, so aggregation never hides a flow;
* total alerts ≤ 300 + (number of attack types).

A 1 000-flow port sweep therefore produces a handful of rows, not 1 000 notifications — and because
each row links a real prediction you can still open the representative flow, its TreeSHAP explanation
and its features.

Alert types: `"<Attack> detected"` (the pair occurred once), `"<Attack> (burst)"` (aggregated pair,
`occurrences=N`).
Statuses: `new → reviewed → resolved` (`PATCH /api/alerts/{id}`, with an optional note).

## 3. Verified behaviour

On the bundled 1 500-flow held-out sample (593 suspicious flows, 160 distinct attack/port pairs) the
bootstrap analysis produced **160 alerts for 160 pairs** — 155 MEDIUM, 4 HIGH, 1 CRITICAL, zero
duplicates. The largest groups were `DDoS:80` (183 flows) and `DoS:80` (166 flows), i.e. two rows
stand in for 349 detections. This is covered by
`tests/test_alerts.py::test_no_duplicate_alert_pairs_across_every_job` (scans every alert in the
database) and `test_alert_generation_is_flood_controlled` (short-job path).

## 4. Why the policy is shaped this way

* Analysts need both granularity *and* a bounded queue: individual alerts for the worst flows,
  aggregation for the long tail.
* Severity is never inflated: the queue's own composition (mostly MEDIUM/HIGH) is evidence that the
  rules are doing something, rather than labelling everything CRITICAL.
* Every rule is testable and documented — `GET /api/alerts/rules` returns the thresholds, the weights,
  the sensitive-port list and the grouping policy, so the documentation cannot drift from the code.
