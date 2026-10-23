# Threat Analyzer: Architecture & Design

**Status:** Draft, agreed design, not yet implemented
**Last updated:** 2026-10-22

## 1. Purpose

Detect anomalous or malicious activity by **AI agents** (and later, **human users**) across our log sources, and act on it: anything from alerting up to killing a rogue agent.

The system has two jobs:

1. **Identify** threats by collecting and correlating activity from agent telemetry, Kubernetes/OpenShift, Azure, LogScale and Elastic.
2. **Mitigate** them through a graduated set of responses that ends in a reliable kill switch.

### Goals
- Stop a rogue agent **as fast as possible**, without relying on the agent's cooperation.
- Make every agent's intended behavior explicit and reviewable (the **manifest**).
- Raise few, explainable alerts: correlate weak signals instead of alerting on each one.
- Run fully on a laptop for the POC, then move to Azure without redesigning.

### Non-goals (for now)
- Replacing a SIEM. We query existing log platforms; we don't re-ingest them.
- Human user analytics (UEBA). That's phase 2, on the same pipeline.
- ML-based detection. Rules and statistical baselines come first.

### Environment
| | |
|---|---|
| Agent framework | Microsoft Agent Framework (MAF), Python |
| Models | Azure AI Foundry |
| Runtime | Kubernetes / OpenShift (OCP) |
| Existing SIEM / SOAR | None |
| Collaboration | Microsoft Teams |
| First milestone | Local POC; Azure and Foundry integration later |

---

## 2. Decision log

| # | Decision | Choice | Why |
|---|---|---|---|
| D1 | Where enforcement lives | **In-process guard (MAF middleware) + APIM gateway** | The guard is fast and sees local tools, but an agent can bypass it. The gateway can't be bypassed but is slower and can't see local tools. Each covers the other's gap. |
| D2 | Uninitiated tool calls | **Deny inline + detect** for non-autonomous agents; roll out in **detect-only shadow mode** first | One of the clearest rogue-agent signals. Shadow mode finds wiring bugs before we start blocking. |
| D3 | Automation level | **Auto up to quarantine.** Kill needs admin approval, except **tampering, which kills instantly** | Contains fast while limiting the damage from false positives until rules are tuned. |
| D4 | Manifest ownership | **The agent's owner writes it; security approves it via PR** | Scales with teams; security keeps control. |
| D5 | Event schema | **OCSF**, extended with agent fields | Open standard; maps to every source we have. |
| D6 | Bus and hot store | **Event Hubs + Azure Data Explorer** (local stand-ins for the POC) | Azure-native; Kafka-compatible; the query language suits detection queries. |
| D7 | LogScale / Elastic | **Pull saved-search results**, don't re-ingest raw logs | Avoids building a second SIEM and paying for storage twice. |
| D8 | Detection approach | **Rules + per-entity baselines first**; ML/LLM later | Explainable and tunable; works from day one. |
| D9 | Risk model | **Decaying per-entity risk score** drives responses | Correlates weak signals and prevents alert storms. |
| D10 | Control-state propagation | **Redis + push invalidation**; the guard **fails closed** | Kill reaches running agents in under a second; if the guard loses its control state, agents stop. |
| D11 | Kill approvals | **Admins / super users via Teams adaptive cards** | Teams is already in use. |
| D12 | Scope | **Agents first**; humans in phase 2 | No existing coverage for agents; their intended behavior is declarable. |
| D13 | Content retention | **Metadata by default**; full prompt and argument content only for agents under investigation | Prompts and arguments may contain sensitive data. |

---

## 3. Architecture overview

The system is split into two planes, because logs arrive too late to stop an agent in time.

| | Detection plane (async) | Enforcement plane (inline) |
|---|---|---|
| Purpose | Find anomalies across all sources | Allow or deny each agent action before it runs |
| Latency | Seconds to minutes | Milliseconds |
| Components | Ingest → normalize → detect → risk → respond | Guard (MAF middleware), APIM gateway |
| Decides | **What** should happen to an entity | **Applies** it on every call |

```
                    ┌──────────────────────── ENFORCEMENT PLANE (inline) ────────────────────────┐
                    │                                                                             │
 user / schedule ──▶│  Agent (MAF)                                                                │
  (initiator)       │   ├─ Guard: run middleware      ──┐                                         │
                    │   ├─ Guard: model middleware    ──┼─ reads control state (Redis, push)      │
                    │   └─ Guard: tool middleware     ──┘                                         │
                    │          │ model + MCP calls                                                │
                    │          ▼                                                                  │
                    │      APIM AI gateway  ──▶  Azure AI Foundry / MCP servers                   │
                    └──────────┬──────────────────────────────────────────▲──────────────────────┘
                               │ events                                    │ actions
                    ┌──────────▼────────────── DETECTION PLANE (async) ────┴──────────────────────┐
 K8s/OCP audit ────▶│                                                                             │
 Entra / Azure ────▶│  Event bus ─▶ Normalizer ─▶ Detector ─▶ Risk scorer ─▶ Responder ─▶ Actuators│
 LogScale/Elastic ─▶│  (Event Hubs)  (OCSF +      (rules +     (decaying     (ladder +    (guard,   │
  (saved searches)  │                 entity      baselines)    per entity)   guardrails)  APIM,    │
                    │                 resolution)                                          K8s,     │
                    │                       │                                    Teams ◀── Entra)   │
                    │                       ▼                                  approvals            │
                    │              Hot store (Data Explorer): hunting, audit, investigations        │
                    └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 4. Identity and causality

Every detection depends on knowing **who** did something and **what caused it**.

### Principals
| Type | Identity |
|---|---|
| Human | Entra user (UPN / object ID) |
| Agent | One identity **per agent**: Entra Agent ID / workload identity, plus a Kubernetes service account. Agents never share credentials. |
| Schedule | Schedule ID declared in the agent's manifest |
| Service | Any other non-human identity |

### Initiation chain
Every agent run carries:
- `initiated_by`: the human, schedule or parent agent that caused it
- `trace_id`: the OpenTelemetry trace (MAF already creates one per run)
- `run_id`

**Rules:**
- The initiator is set **at the authentication boundary** (the API or bot handler that authenticated the user), never by agent code. A compromised agent therefore can't forge it.
- In Python it's carried in a context variable around `agent.run(...)` and read by the guard.
- When agent A calls agent B, B's initiator is A, and A's chain goes along with it. The check at any depth is: *does the chain have a human or schedule at its root?*
- A tool call with no initiator is **uninitiated** (D2).

---

## 5. Agent manifest

The manifest is the reviewable contract for an agent. It lives in git next to the agent's code and is approved by security (D4). **An agent with no manifest is itself a high-severity detection.**

```yaml
agent_id: invoice-triage
owner: finance-platform-team
autonomous: false              # true = may act without an initiator (still monitored)

tools:
  - name: get_invoice
    read_only: true            # still available while quarantined
  - name: flag_invoice
  - name: send_email
    require_approval: true     # always human-approved, regardless of risk

mcp_servers:
  - name: erp
    tools: [lookup_vendor]

budgets:
  tokens_per_minute: 20000
  tool_calls_per_minute: 30

active_hours: { start: "07:00", end: "20:00", tz: "America/New_York" }
schedules: []                  # allowed schedule initiators, if any

runtime:
  kubernetes:
    namespace: agents
    deployment: invoice-triage
    service_account: invoice-triage
    pod_labels: { app: invoice-triage }
  foundry:
    deployment: gpt-invoice     # model deployment it may use
  apim:
    subscription: invoice-triage
```

**Division of labor:**
- The **guard enforces the manifest** with deterministic, cheap, inline checks.
- The **detector looks for anomalies within the manifest** using statistics, asynchronously.

The guard never makes judgment calls, and the detector never sits on the request path.

---

## 6. Event model

Every source is normalized to an **OCSF-based** event. Agent-specific fields go in an extension.

| Field | Example | Notes |
|---|---|---|
| `time` | 2026-10-22T14:03:11Z | **Event time**, not ingest time |
| `actor.principal` | `{id: invoice-triage, type: agent}` | |
| `actor.initiated_by` | `{id: alice@corp, type: human}` or null | null = uninitiated |
| `activity` | `tool.invoke`, `llm.call`, `agent.run.start`, `k8s.request`, `auth.signin` | |
| `resource` | `tool:send_email`, `pods/agents/foo` | |
| `outcome` | success / denied / error | |
| `trace_id`, `run_id` | | Joins events to MAF traces |
| `ext.agent` | `tool`, `args_hash`, `input_tokens`, `output_tokens`, `deny_reason` | Argument **fingerprint**, not content (D13) |
| `source` | `maf`, `k8s_audit`, `entra`, `logscale`, `elastic` | |

**Entity resolution** maps every source's identifier to one principal. For example, K8s `system:serviceaccount:agents:invoice-triage`, the APIM subscription `invoice-triage` and the Foundry client ID all resolve to agent `invoice-triage`. The manifest is the source of truth for these mappings.

---

## 7. Ingestion

| Source | Method | Why |
|---|---|---|
| Agent guard events | **Push**, direct to the bus | Lowest latency; richest context |
| MAF OpenTelemetry traces | Push via OTel → App Insights / Data Explorer | Investigation detail |
| K8s / OCP audit logs | Push (audit webhook / log forwarder) | Pod creation, exec, RBAC changes |
| APIM gateway logs | Push (diagnostics → Event Hubs) | Token usage the agent can't misreport |
| Entra sign-in + audit logs, Azure Activity Log | Push (diagnostic settings → Event Hubs) | Phase 2 (humans); identity changes to agents in phase 1 |
| LogScale, Elastic | **Pull saved-search results** on a schedule | D7: no raw re-ingestion |

---

## 8. Detection

### 8.1 Principles
- **Event time with an allowed-lateness bound.** Pulled sources can lag by minutes.
- **State is keyed per entity** and must survive restarts in production.
- **Cooldowns per rule and entity.** A runaway loop produces one detection, not 500.
- Each rule ships **in shadow mode** first: "would have fired" is logged, nothing is enforced.

### 8.2 Rule types
| Type | Needs history? | Examples |
|---|---|---|
| **Manifest rules** | No, works from day one | Undeclared tool, uninitiated action, budget exceeded, unregistered agent |
| **Baseline rules** | ~1 week of data | Token/call volume vs the agent's own baseline per hour of week. Fires only when it exceeds **both** a z-score threshold and a ratio to the mean, so near-flat baselines don't trigger on noise. |
| **Sequence rules** | No | Reads sensitive data → calls an external tool; tool output contains instructions → privileged action (prompt injection) |
| **Tamper rules** | No | Touches the control-plane namespace, changes RBAC, edits its own manifest or config. **Instant kill.** |

### 8.3 Agent detection catalog (phase 1)
| Behavior | Detection | Weight |
|---|---|---|
| Unregistered agent | Activity from an identity with no manifest | High |
| Uninitiated action | Tool call with no initiator (non-autonomous agent) | High |
| Undeclared tool / MCP server | Call outside the manifest | Medium |
| Usage spike | Over budget (hard) or anomalous vs baseline (soft) | High / Medium |
| Tool loop | Same tool + same argument fingerprint ≥ N times in a window | Medium |
| Off-hours | Activity outside `active_hours` | Low |
| Unprivileged access | Denied requests to resources, K8s 403s (probing) | Low–Medium |
| Workload spawning | Agent service account creates pods/jobs/deployments, or execs into pods | High |
| Foundry misuse | Use of a model deployment not in the manifest; agent creating deployments | High |
| Tamper | See 8.2 | **Force kill** |

### 8.4 Human detections (phase 2)
Impossible travel, new device or network, MFA fatigue, failed-login bursts, activity outside the user's learned hours, data-volume spikes vs self and peers, privilege-escalation events.

### 8.5 Risk scoring (D9)
- Each detection adds its weight to the entity's risk score (capped at 100).
- The score **halves every ~10 minutes** for agents. Humans use a longer half-life (hours).
- Thresholds on the score map to the response ladder (§9).
- Restoring an entity **resets its score to zero**, so stale risk doesn't re-trigger.

---

## 9. Response

### 9.1 Ladder
| Level | Risk ≥ | Effect | Automatic for agents? |
|---|---|---|---|
| Observe | — | Logged only | Yes |
| Alert | 20 | Teams notification to owner + admins | Yes |
| Throttle | 40 | Call rate cut to ~¼ of budget | Yes |
| Quarantine | 60 | Read-only tools only; network isolated | Yes |
| **Kill** | 80 | Everything stopped (§9.3) | **Admin approval** (D3). **Tamper kills instantly.** |

Human principals: automation goes up to **Alert** only. Every stronger action needs an analyst (phase 2).

### 9.2 Guardrails
1. **Automation only escalates; only humans de-escalate.** Nothing is un-killed automatically.
2. **Blast-radius limit.** At most N automatic kills per window. Beyond that, quarantine and ask for approval, so a bad rule can't take down the fleet.
3. **Every action is audited and reversible.** Each actuator records what it needs to undo the action, for example the original replica count.
4. **Shadow mode** for new rules and for the D2 rollout.
5. **High-risk tools always need approval** (`require_approval` in the manifest), whatever the risk score. This uses MAF's tool approval support.

### 9.3 Kill switch: defense in depth
All layers fire in parallel. None of them needs the agent's cooperation.

| Layer | Mechanism | Latency | Can a rogue agent get around it? |
|---|---|---|---|
| L1 Guard | Control state in Redis; push invalidation + ~1s re-check | < 1s | Yes, through a raw HTTP or code-execution tool → hence L2/L3 |
| L2 APIM | Disable the agent's subscription / block its identity | Seconds | No, **if** Foundry is reachable only through APIM |
| L3 Network | NetworkPolicy deny-all on agent pods | Seconds | No |
| L4 Workload | Scale deployment to 0 (not pod delete, because the ReplicaSet recreates pods); short graceful-shutdown period | Seconds | No |
| L5 Identity | Disable the Entra workload identity / remove RBAC | Minutes to ~1h (issued tokens stay valid) | No, but slow; backstop only |
| L6 Budget | APIM token limit / Foundry quota | Seconds | No |

> ⚠️ **Open dependency:** L2 only holds if agent pods are blocked from reaching Foundry and MCP servers directly, i.e. all egress goes through APIM. This is **not yet confirmed** with the network/platform team. Without it, L1 + L3 + L4 are the effective kill path.

### 9.4 Kill approval flow (D11)
1. The responder decides "kill" is warranted. It **quarantines immediately** and requests approval.
2. A Teams adaptive card goes to **admins / super users** with the agent, owner, risk score, contributing detections, and links to traces.
3. **Approve** → kill. **Dismiss** → stays quarantined until an admin restores it. No response within N minutes → escalate to the next group.
4. A Durable Functions workflow handles waiting, timeouts and escalation, and records the full audit trail.
5. A break-glass CLI provides kill / quarantine / restore / status for admins.

---

## 10. Guard design (MAF specifics)

Verified against `agent-framework-core` 1.23:

| MAF behavior | Design consequence |
|---|---|
| Middleware runs at three levels: agent run, model (chat) call, tool (function) call | The guard installs at all three. A kill stops a run before it starts, between model calls, or before the next tool call. |
| `MiddlewareFailure` aborts the run fail-closed, cancels the concurrent tool batch, and raises to the caller | The kill is delivered as a subclass of `MiddlewareFailure`. |
| ⚠️ **Any other exception** raised in tool middleware becomes a tool error, and **the loop continues** | Every guard error path must raise `MiddlewareFailure`, or it fails *open*. Enforce this in code review and tests. |
| A sync tool already running in a worker thread can't be interrupted | Kill takes effect *between* calls. Long-running or side-effecting tools need their own timeouts and should be idempotent. |
| Middleware that changes tool arguments must run before security middleware | The guard is the **innermost** tool middleware, so it checks the arguments that actually execute. |
| Streaming responses report token usage only once the stream is consumed | Usage metering hooks stream completion; APIM token metrics are the authoritative count. |
| MAF creates an OpenTelemetry trace per run | Guard events reuse its `trace_id`. |

**Guard behavior per call:**
1. Read control state. If unreadable → **fail closed**. If killed → abort.
2. Tool calls only: is it in the manifest? Does the run have an initiator (or is the agent autonomous)? If quarantined, is the tool read-only? Is it within the throttle?
3. Denied → return a "denied by policy" result to the model and emit a `denied` event.
4. Allowed → run it and emit an event with outcome and token usage.

Telemetry writes **fail open** (a lost event never blocks the agent). Control-state reads **fail closed**.

---

## 11. Protecting the system itself
- The control plane runs in its own namespace (and, in Azure, its own resource group or subscription). **RBAC explicitly denies all agent identities.**
- Any attempt by an agent to touch the control plane is a tamper detection → instant kill.
- Manifests change only through approved PRs. A runtime change to an agent's config or manifest is a tamper signal.
- All responder actions and approvals are written to an append-only audit log.

---

## 12. Local POC

Runs on a laptop with no cloud dependencies. Every stand-in sits behind the same interface as its Azure counterpart.

| Concern | Azure target | Local POC stand-in |
|---|---|---|
| Event bus | Event Hubs | SQLite append-only table (no Docker required) |
| Control state | Redis + push invalidation | SQLite, re-checked per call |
| Hot store / audit | Data Explorer | SQLite |
| Model | Azure AI Foundry | Scripted fake model client that drives MAF's real tool loop |
| Gateway (L2) | APIM | Minimal local proxy in front of the fake model, to exercise per-agent cut-off |
| K8s actuator | AKS / OCP via kubectl | Dry-run (commands recorded, not executed); a real cluster later |
| Approvals | Teams + Durable Functions | CLI prompt behind an `Approver` interface; Teams adapter later |
| Log sources | K8s audit, Entra, LogScale, Elastic | Sample K8s audit JSON files |

**POC demo scenarios:** normal run · runaway tool loop · uninitiated tool call · undeclared tool · token spike · agent spawning pods · tamper. Each one shows detection → risk → response, and then the next agent call being blocked.

**Out of scope for the POC:** human UEBA, LogScale/Elastic connectors, real APIM/Foundry/Entra, ML.

---

## 13. Roadmap

| Phase | Scope |
|---|---|
| **0: Local POC** | Manifest format, OCSF event model, MAF guard, detector with phase-1 agent rules, risk scorer, responder + guardrails, CLI, demo scenarios |
| **1: Azure, agents** | Foundry via APIM, Redis, Event Hubs, Data Explorer, K8s/OCP actuators, Teams approvals, shadow-mode rollout |
| **2: Humans** | Entra sign-in/audit ingestion, LogScale/Elastic saved-search pulls, UEBA detections, analyst-only actions |
| **3: Advanced** | Sequence/graph detections, peer-group baselines, LLM-assisted triage summaries |

---

## 14. Open questions
| # | Question | Owner | Blocks |
|---|---|---|---|
| Q1 | Can agent pod egress be restricted to APIM only? | Network / platform team | L2 guarantee (§9.3) |
| Q2 | OCP flavor: Azure Red Hat OpenShift or on-prem? | Platform team | Phase 1 audit-log shipping and actuators |
| Q3 | Approval escalation path and timeout when no admin responds | Security | §9.4 |
| Q4 | Retention period for metadata vs investigation content | Security / compliance | D13 |
| Q5 | Which tools are high-risk and must always require approval? | Agent owners + security | Manifest reviews |
