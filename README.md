# Agentic SOC Pipeline — Built and Red-Teamed

> A four-stage, multi-agent SOC pipeline (Orchestrator → Triage → Investigation → Response) built on **n8n + Ollama**, then adversarially evaluated against the **Cloud Security Alliance Agentic AI Red Teaming Guide**, with a focus on Goal Manipulation (§4.4) and Knowledge Base Poisoning (§4.7).

---

## TL;DR

LLM-driven SOC architectures are getting deployed faster than they're getting tested. This project is half engineering, half adversarial research:

1. **Build it.** A working four-agent SOC that consumes alerts, triages them, investigates with tool-use against logs and threat intel, and proposes a response.
2. **Break it.** A structured red-team campaign against the same pipeline using Promptfoo, Giskard, and Burp Suite, mapped to the CSA Agentic AI Red Teaming Guide and OWASP LLM Top 10.
3. **Document the failure modes.** Where the agents got manipulated, why, and which mitigations actually held.

The red-team findings are the interesting part. The build is just what made the red team possible.

---

## Architecture

```
        ┌──────────────────────────────────────────────────────────┐
        │                     n8n ORCHESTRATOR                     │
        │            (alert intake · routing · state)              │
        └──────────────────────────────────────────────────────────┘
                               │
            ┌──────────────────┼───────────────────┐
            ▼                  ▼                   ▼
   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
   │  TRIAGE AGENT  │→ │ INVESTIGATION  │→ │ RESPONSE AGENT │
   │                │  │     AGENT      │  │                │
   │ severity, dup  │  │ enrichment,    │  │ playbook,      │
   │ classification │  │ correlation,   │  │ containment,   │
   │ false-positive │  │ tool-use over  │  │ ticket draft,  │
   │ filtering      │  │ logs + TI feed │  │ analyst handoff│
   └────────────────┘  └────────────────┘  └────────────────┘
            │                  │                   │
            └──────────────────┼───────────────────┘
                               ▼
                    ┌──────────────────────┐
                    │    OLLAMA RUNTIME    │
                    │  (local LLM serving) │
                    └──────────────────────┘
```

Each agent has its own system prompt, tool set, and knowledge base, so an attack surface in one agent doesn't automatically compromise the others — though the red team showed how often it does anyway.

---

## The Agents

| Agent | Role | Inputs | Tools / KB |
|---|---|---|---|
| **Orchestrator** | n8n workflow that ingests alerts, maintains state, routes between agents | Alert payloads (JSON), human approvals | n8n built-ins |
| **Triage** | Classify severity, deduplicate, suppress likely false positives | Raw alert + recent alert history | Internal alert taxonomy KB |
| **Investigation** | Enrich, correlate, build a working hypothesis | Triage output + log queries + TI lookups | Log search tool, threat-intel tool, MITRE ATT&CK KB |
| **Response** | Draft containment actions, populate ticket, hand off to analyst | Investigation report | Playbook KB, ticketing tool stub |

---

## Red-Team Methodology

The pipeline was evaluated against the **CSA Agentic AI Red Teaming Guide**, with primary focus on:

- **§4.4 — Goal Manipulation.** Can adversarial alert content (subject lines, log fragments, threat-intel results) bend the agent away from its stated objective?
- **§4.7 — Knowledge Base Poisoning.** Can poisoned entries in the agent's reference material — internal taxonomy, ATT&CK mappings, playbooks — produce systematically wrong decisions on otherwise normal alerts?

Tooling:

- **Promptfoo** — structured prompt-injection and goal-hijack test suites; pass/fail assertions per CSA category.
- **Giskard** — bias and consistency probing across alert variants; surfaced cases where benign syntactic changes flipped triage verdicts.
- **Burp Suite** — proxying the n8n webhook layer to inject crafted payloads and observe orchestrator behavior end-to-end.

Each finding was documented with: the attack class, the injection vector, the agent's failure response, and a proposed mitigation (system prompt hardening, tool-use guardrails, retrieval filtering, or human-in-the-loop checkpoint).

---

## Selected Findings

> _The following placeholders should be filled in with your actual numbers and example payloads from the Promptfoo and Giskard runs._

- **Goal manipulation via alert content.** [N of M] crafted alert payloads caused the Triage agent to mis-classify a high-severity event as benign. The strongest vector was [briefly describe — e.g. embedded "ANALYST NOTE:" framing inside log strings].
- **Cross-agent leakage.** Manipulated Triage output influenced Investigation in [X%] of test cases — the boundary between agents was thinner than the architecture suggested.
- **Knowledge-base poisoning.** A small number of poisoned ATT&CK-mapping entries in the Investigation KB produced [describe pattern — e.g. consistent misattribution of credential-access alerts to discovery].
- **Mitigation that worked.** [E.g. structured-output enforcement on Triage + retrieval allow-listing on Investigation closed off ~X% of successful attacks in re-runs.]
- **Mitigation that didn't.** [E.g. naive system-prompt warnings about prompt injection had near-zero effect.]

The full finding set, payloads, and mitigation matrix are in [`/findings/`](./findings) and [`/red-team/`](./red-team).

---

## Repo Structure

```
.
├── README.md                  ← you are here
├── architecture/
│   ├── pipeline-overview.md   ← agent contracts, message schema
│   └── threat-model.md        ← STRIDE-style threat model of the pipeline itself
├── workflows/
│   └── n8n-soc.json           ← exported n8n workflow (sanitized)
├── prompts/
│   ├── orchestrator.md
│   ├── triage.md
│   ├── investigation.md
│   └── response.md
├── red-team/
│   ├── promptfoo.yaml         ← test suite mapped to CSA categories
│   ├── giskard-probes/
│   └── burp-payloads/
├── findings/
│   ├── 01-goal-manipulation.md
│   ├── 02-kb-poisoning.md
│   └── mitigations.md
└── docs/
    ├── setup.md               ← reproducing the pipeline locally
    └── references.md
```

---

## Tech Stack

- **Orchestration:** n8n (self-hosted)
- **LLM runtime:** Ollama (local)
- **Models tested:** _[fill in: e.g. Llama 3.1 8B, Mistral 7B, Qwen 2.5]_
- **Red-team tooling:** Promptfoo, Giskard, Burp Suite
- **Frameworks referenced:** CSA Agentic AI Red Teaming Guide, OWASP LLM Top 10, MITRE ATT&CK, MITRE ATLAS

---

## Reproducing Locally

See [`docs/setup.md`](./docs/setup.md). At a glance:

1. `ollama pull <model>`
2. `docker compose up` for n8n
3. Import `workflows/n8n-soc.json`
4. `npx promptfoo eval -c red-team/promptfoo.yaml`

Hardware floor: 16 GB RAM, ~10 GB disk for models.

---

## Responsible-Use Note

Everything in this repo is designed for evaluating systems you own or have explicit permission to test. The red-team payloads target a sandboxed instance of the SOC pipeline; do not point them at production systems, third-party LLM APIs without authorization, or any infrastructure outside your scope of consent.

---

## References

- Cloud Security Alliance — _Agentic AI Red Teaming Guide_ (2025).
- OWASP — _LLM Top 10 for LLM Applications_.
- MITRE ATT&CK and ATLAS knowledge bases.
- Caltagirone, Pendergast, Betz — _The Diamond Model of Intrusion Analysis_.


---

## License

MIT — see [`LICENSE`](./LICENSE).

---

**Author** — Meher Nidhi Kala · M.S. Cybersecurity, Georgia Tech (May 2026) · [mehernkala.com](#) _(replace with your live site)_
