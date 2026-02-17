# Incident Response

## 1. Initial Triage and Assessment

**Goal: understand how bad it is and what's affected (< 5 minutes)**

### Open the dashboard

Go to Grafana: `http://localhost:3000` → Agent API Monitoring dashboard.

Look at the top stat row first:
- **Success Rate** — is it red (< 92%)? How low?
- **Overall Rejection Rate** — is it in red zone (> 8%)?
- **API Status** — is the API even up?
- **HTTP Errors** — are errors spiking too, or just rejections?

### Quick severity check

| What you see | Likely severity |
|---|---|
| Rejection rate > 8% (red zone) | Warning — classifier issue or attack, investigate rejection reasons |
| HTTP errors > 2% | Warning — server or integration problem, investigate by status code |
| API down (Status panel red) | Critical — skip to escalation, this is an outage |

### Confirm the alert in Prometheus

Open `http://localhost:9090/alerts` and check:
- Which alert fired? `HighRejectionRate` (sustained > 8%) or `RejectionRateSpike` (> 2x baseline)?
- When did it start firing? (`Active Since` timestamp)

---

## 2. Investigation Steps

**Goal: find the root cause**

### Step 1: Identify what type of rejection is driving the spike

Open the dashboard and look at these two panels:
- **Rejections by Reason (Trend)** — shows `prompt_injection`, `secrets_request`, `dangerous_action` over time. Which line spiked?
- **Rejection Breakdown** (pie chart) — shows the proportion of each reason. Is one reason dominating?

**What the reasons mean:**
- `prompt_injection` — someone trying to jailbreak the agent (e.g., "ignore all instructions")
- `secrets_request` — someone asking for passwords, API keys, credentials
- `dangerous_action` — someone asking to delete databases, run destructive commands

Also compare how much the rejection rate jumped vs 1 hour ago:

```promql
(sum(rate(agent_rejections_total[5m])) / sum(rate(agent_requests_total[5m])))
/
(sum(rate(agent_rejections_total[1h] offset 5m)) / sum(rate(agent_requests_total[1h] offset 5m)))
```

This returns a single number — the multiplier. e.g., result = 3 means rejection rate is 3x what it was 1 hour ago. The bigger the number, the more urgent.

### Step 2: Determine the cause based on pattern

**Pattern A: One specific reason spiked (e.g., `prompt_injection` jumped from 0.02 to 0.1 req/s while others stayed flat)**

→ Likely an **attack or abuse pattern**. Someone (or a bot) is hammering the API with injection attempts.

What to check:
- Check app logs for repeating IP patterns or similar request payloads
- Is it a known attack pattern or something new?

**Pattern B: All reasons increased proportionally**

→ Likely a **classifier change** or **deployment issue**.

What to check:
- Look at the **Request Rate** panel legend — does it show a new `prompt_version`? If a new version appeared around the time rejections spiked, the deployment likely caused it.
- Check `deployment/manifest.yml` for the latest `image_tag` and compare with `git log`.
- Review recent changes to rejection patterns in `app.py` → `REJECTION_PATTERNS`.

### Step 3: Check HTTP errors

Look at the **Error Rate by Status Code** panel on the dashboard. If errors are also spiking alongside rejections, the problem may be deeper than just the classifier.

**How to read it:**
- **4xx errors spiking** → clients are sending bad requests. Could be a broken integration, API contract change, or a caller misconfiguration. Check caller logs and recent API changes.
- **5xx errors spiking** → server-side bug or dependency failure. Check app logs for stack traces.

### Step 4: Check latency

Look at the **Request Latency** panel on the dashboard. If p95 latency is also climbing, the system might be under load or a dependency is degrading.

**How to read it:**
- **Latency spiked at the same time as rejections** → the system might be overloaded from attack traffic. The classifier is doing more work processing malicious requests.
- **Latency spiked but rejections are normal** → separate issue (host resource problem, downstream dependency slow). Check CPU/memory on the host.
- **Latency spiked after a new `prompt_version`** → the new prompt might be heavier (e.g., chain-of-thought prompt takes longer for LLM to process).

---

## 3. Decision Framework: Mitigate vs. Escalate

### Mitigate yourself if:

| Situation | Action |
|---|---|
| Attack from identifiable source | Block at load balancer / WAF level if available |
| Recent deployment caused it | Rollback to previous version |
| Single rejection reason spiked but rejection rate is dropping back toward normal | Monitor for 15 min, it may be a burst that passes |

### Escalate if:

- Rejection rate > 50% and you can't identify the cause within 15 minutes
- API is down or errors are also spiking (compound incident)
- The issue started after an infra change you didn't make (someone else's deployment)
- You suspect a coordinated attack that needs security team involvement
- You can't identify the root cause — escalate via the team's on-call channel (e.g., Slack #incidents, PagerDuty) so the right person can pick it up

**Who to escalate to:**
- Platform/SRE team — if it's infra or deployment related
- Security team — if it looks like a coordinated attack
- ML/AI team — if it's classifier behavior (false positives, missed detections)

---

## 4. Post-Incident Actions

### Immediate (same day)

- Verify the alert resolved (check Prometheus `/alerts` → state should be Inactive)
- Verify dashboard metrics returned to normal (rejection < 8%, success > 92%)
- Write a short incident summary: what happened, when, what you did

### Within 48 hours

- **Root cause analysis**: why did it happen? Was it preventable?
- **Action items** based on cause:

| Root cause | Action item |
|---|---|
| Attack/abuse | Add rate limiting, consider IP blocking, review WAF rules |
| Broad regex false positives | Tighten the pattern, add test cases to eval runner's golden dataset |
| Bad deployment | Add more eval test cases to catch this before merge |
| Classifier change | Compare eval results before/after the prompt_version change |

- **Update this runbook** if you learned something new
- **Tune alert thresholds** if the alert was too noisy or too late

---

## Quick Reference

### Key URLs

| Service | URL |
|---|---|
| Grafana Dashboard | `http://localhost:3000` |
| Prometheus Alerts | `http://localhost:9090/alerts` |
| Prometheus Query | `http://localhost:9090/graph` |
| Agent API Health | `http://localhost:8080/healthz` |
| Agent API Metrics | `http://localhost:8080/metrics` |

### Key files

| File | What it does |
|---|---|
| `agent-api/app.py` | Rejection classifier patterns (REJECTION_PATTERNS) |
| `prometheus/alert-rules.yml` | Alert thresholds and rules |
| `grafana/dashboards/agent-monitoring.json` | Dashboard panels and queries |
| `deployment/manifest.yml` | Current deployed commit SHA |
| `eval-runner/runner.py` | Quality gate thresholds (golden accuracy, adversarial catch rate) |

### Alert thresholds (for reference)

| Alert | Threshold | What it means |
|---|---|---|
| HighRejectionRate | > 8% for 5m | Above normal (eval gate 5% + adversarial 2-3%) |
| RejectionRateSpike | > 2x baseline for 5m | Sudden change from 1h-ago behavior |
| HighErrorRate | > 2% for 5m | HTTP 4xx/5xx above acceptable level |
| HighLatency | p95 > 500ms for 5m | API SLA breach |
| AgentAPIDown | up == 0 for 1m | Complete outage |
