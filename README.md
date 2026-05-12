# security-recipes.ai

[security-recipes.ai](https://security-recipes.ai/) is a Hugo documentation site, prompt library, generated evidence corpus, and read-only MCP server for agentic security remediation.

The project's thesis is simple: AI coding agents can help close security findings, but only when they are given trusted context, narrow scope, deterministic gates, reviewable evidence, and clear stop conditions. SecurityRecipes turns that operating model into open recipes, machine-readable workflow policy, runtime decision evaluators, and MCP-accessible evidence packs.

## What this project is

SecurityRecipes is the trusted secure context layer for agentic AI and MCP-based security work.

It helps security, platform, and engineering teams answer:

- Which AI coding agents can we use for remediation work?
- What rules, prompts, skills, and guardrails should those agents follow?
- Which workflows are safe enough to run, and under what scope?
- Which MCP context can an agent read before acting?
- What evidence should be produced for reviewers, auditors, buyers, and incident responders?
- When should an agent run be allowed, held, denied, or killed?

The site is intentionally tool-agnostic, but it includes concrete recipes for the major agent surfaces covered by the content today: GitHub Copilot, Devin, Cursor, Codex, and Claude.

## What is implemented

This repository currently ships:

- A Hugo + Hextra site published as `security-recipes.ai`.
- A custom landing page and documentation experience.
- 200+ content pages covering fundamentals, quick starts, agent setup, prompt reuse, MCP server access, control-plane concepts, secure-context patterns, and remediation workflows.
- A prompt library for general security tasks, agent-specific workflows, CVE remediation, crypto/DeFi checks, classic vulnerable defaults, SAST triage, sensitive-data cleanup, dependency remediation, and OWASP-style audit/remediation prompts.
- Agent recipes for GitHub Copilot, Devin, Cursor, Codex, and Claude.
- A workflow control plane under `data/control-plane/` with schema validation and generated policy output.
- 50+ generated evidence packs under `data/evidence/`.
- 90+ Python generator, validator, and evaluator scripts under `scripts/`.
- A read-only FastMCP server in `mcp_server.py` exposing search, recipe retrieval, evidence packs, and deterministic runtime evaluators.
- A server-side chatbot API in `chatbot_server.py` for OpenAI, Grok/xAI, and Anthropic-backed chat.
- A browser-side agent planner documented in `README.browser-agents.md`.
- Docker images for the static site, chatbot API, and MCP server.
- A `docker-compose.yml` stack that serves the site, `/api/chat`, and `/mcp` behind one origin.
- GitHub Pages-friendly Hugo output and forkable repo links.

## Repository map

| Path | Purpose |
| --- | --- |
| `content/` | Hugo docs, recipes, prompt library entries, and security-remediation pages. |
| `layouts/` | Custom Hugo templates, JSON indexes, shortcodes, and partials. |
| `assets/` | Site CSS and JavaScript, including search, navigation, Mermaid viewing, and chatbot UI. |
| `static/` | Static images, integration logos, schemas, CNAME, and generated visual assets. |
| `data/control-plane/` | Workflow manifests and schema for governed agentic remediation workflows. |
| `data/policy/` | Generated MCP gateway policy. |
| `data/evidence/` | Generated assurance, trust, runtime, readiness, red-team, identity, and secure-context packs. |
| `data/assurance/` | Source profiles and models used by evidence generators. |
| `data/marketplace/` | Control-plane marketplace catalog data for inputs, outputs, reports, workflows, and readiness. |
| `scripts/` | Generators, evaluators, validators, and GitHub Advisory Database import tooling. |
| `mcp_server.py` | Read-only FastMCP server for recipes, packs, and runtime decisions. |
| `chatbot_server.py` | Small HTTP chatbot API used by the Docker/nginx production stack. |
| `Dockerfile` | Multi-stage Hugo/nginx site image with proxy routes for chat, MCP, and provider relays. |
| `Dockerfile.mcp-server` | Standalone MCP server image. |
| `Dockerfile.chatbot-server` | Standalone chatbot API image. |

## Site content

The Hugo site is organized around the way a team adopts agentic remediation:

- `Quick Start`: a five-minute path to a first reviewer-gated agent PR.
- `Fundamentals`: plain-English explanations of agents, MCP, prompts, skills, and threat models.
- `Docs`: how to use the site, integrate an AI agent, and understand the marketplace/control-plane surface.
- `Agents`: setup and guardrails for GitHub Copilot, Devin, Cursor, Codex, and Claude.
- `Prompt Library`: reusable prompts, rules, skills, CVE playbooks, and remediation patterns.
- `MCP Server Access`: the shipped read-only MCP server and its tool surface.
- `Security Remediation`: generated policy, evidence, runtime evaluators, secure-context controls, incident response, readiness, red-team, identity, and trust packs.
- `Automation`: where deterministic automation should still be preferred over agentic behavior.
- `Contribute`: how to add recipes, prompts, and workflow content.

## Control plane and evidence model

SecurityRecipes treats each operated agentic workflow as a governed deployment unit.

Workflow manifests declare:

- eligible findings
- deterministic automation that should run before an agent
- allowed MCP context and access modes
- file/path scope
- admission, tool-call, output, pre-merge, post-merge, and runtime gates
- required evidence
- KPIs and promotion criteria
- kill signals

The validator and generators turn those declarations into policy and evidence artifacts. The MCP server exposes those artifacts so an agent, gateway, reviewer, or platform workflow can ask structured questions instead of scraping prose.

Important implemented pack families include:

- MCP gateway policy, connector trust, connector intake, authorization conformance, elicitation boundaries, tool-risk contracts, tool-surface drift, and STDIO launch boundaries.
- Agentic assurance, readiness, posture, AIVSS risk scoring, system BOM, run receipts, telemetry contracts, SOC detections, action runtime, approval receipts, and incident response.
- Agent identity, delegation, entitlement review, memory boundaries, handoff boundaries, skill supply-chain controls, A2A Agent Card trust, and browser-agent boundaries.
- Secure context trust, release, attestation, lineage, evals, evidence contracts, egress boundaries, poisoning guardrails, customer proof, buyer diligence, value modeling, and hosted MCP readiness.
- Red-team drill packs, replay harnesses, measurement probes, exposure graphs, standards crosswalks, source freshness, critical infrastructure profiles, and catastrophic-risk annexes.

## MCP server

The shipped MCP server is read-only. It does not create pull requests, edit tickets, rotate secrets, run scanners, call cloud APIs, or write to external systems.

It does expose:

- `recipes_search`, `recipes_list`, `recipes_get`, and `recipes_match_finding`
- workflow control-plane and MCP gateway policy tools
- evidence-pack retrieval tools
- deterministic evaluator tools that return decisions such as allow, hold, deny, kill-session, guarded, monitor, triage, contain, or fail depending on the pack

The implementation is `mcp_server.py`, the config template is `mcp-server.toml.example`, and localhost setup is documented in `README.mcp-localhost.md`.

Run the MCP server in Docker:

```powershell
docker build -f Dockerfile.mcp-server -t mcp.server .
docker run --rm -it -p 8123:80 mcp.server
```

Then connect an MCP client to:

```text
http://localhost:8123/mcp
```

For Python local development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-mcp-server.txt
python mcp_server.py
```

On Windows PowerShell, activate with:

```powershell
.\.venv\Scripts\Activate.ps1
```

## Chatbot and browser planner

The site includes an AI chatbot UI and a small server-side API.

- `chatbot_server.py` exposes `/api/chat` and `/api/chat/health`.
- `assets/js/ai-chatbot.js` and `assets/css/ai-chatbot.css` implement the browser UI.
- Provider keys are supplied through environment variables such as `OPENAI_API_KEY`, `XAI_API_KEY`, `GROK_API_KEY`, and `ANTHROPIC_API_KEY`.
- The Docker/nginx runtime can proxy `/api/chat` to the chatbot API so provider keys stay server-side.

The browser-side agent planner is beta and local-profile based. It gathers page, recipe, GitHub, and dependency context, asks the selected provider for a remediation handoff, and delivers draft outputs through user-selected routes. See `README.browser-agents.md` for its security model and limits.

## Run the site locally

Prerequisites:

- Hugo extended `>= 0.139`
- Go `>= 1.21`
- Git

From the repository root:

```bash
hugo mod get -u
hugo server -D
```

Open:

```text
http://localhost:1313
```

## Run the production-style Docker stack

Copy the environment template and set at least the public URL. Add provider keys if you want the server-side chatbot to work.

```bash
cp .env.example .env
docker compose up -d --build
```

The compose stack starts:

- `security-recipes`: Hugo/nginx site
- `chatbot-api`: server-side chat API
- `mcp-server`: hosted read-only MCP server

Default routes:

```text
site: / 
chat health: /api/chat/health?provider=openai
MCP endpoint: /mcp
```

## Generate and validate artifacts

Most generated artifacts follow the same pattern:

```bash
python scripts/generate_agentic_assurance_pack.py
python scripts/generate_agentic_assurance_pack.py --check
```

The workflow control plane has a dedicated validator:

```bash
python scripts/validate_workflow_control_plane.py
```

Representative generator and evaluator families:

- `generate_*_pack.py`: produces JSON evidence packs under `data/evidence/`.
- `evaluate_*_decision.py`: evaluates runtime requests against generated packs.
- `generate_mcp_gateway_policy.py`: derives gateway policy from workflow manifests.
- `validate_workflow_control_plane.py`: validates workflow manifests and emits an audit report.
- `generate_cve_recipes_from_ghad.py`: drafts CVE recipe pages from a local GitHub Advisory Database checkout.

Generated files are part of the repo's source-controlled evidence surface. When changing source models, manifests, policies, or scripts, regenerate the affected artifacts and run the corresponding `--check` commands.

## Add content

Add an agent recipe:

```bash
hugo new content/<agent-name>/_index.md
```

Add a prompt:

```text
content/prompt-library/<tool-or-category>/<prompt-name>.md
```

Prompts should include frontmatter with the author, team, maturity, and model they were validated against. Existing prompts in `content/prompt-library/general/` are good templates.

Add or update workflow controls:

```text
data/control-plane/workflow-manifests.json
data/control-plane/workflow-manifest.schema.json
scripts/validate_workflow_control_plane.py
```

Then regenerate dependent policy and evidence packs.

## Standards alignment

The project content and evidence model are written to align with security and AI governance references such as:

- OWASP application security and agentic AI/MCP risk guidance
- NIST AI RMF
- NIST SSDF
- CISA Secure by Design
- least-privilege, reviewable, auditable control design for MCP and agentic workflows

The goal is not just to link to standards. The goal is to make workflow scope, runtime decisions, evidence, and review gates machine-readable enough that teams can operate them.

## Deployment notes

The repo is ready for GitHub Pages-style static publishing and for containerized hosting.

For a single-origin production deployment, the provided Docker stack is the most complete shape. It serves the static site, proxies the server-side chatbot API, and exposes the hosted MCP endpoint from the same public origin. Set `SECURITY_RECIPES_BASE_URL`, `SECURITY_RECIPES_REPO_URL`, `RECIPES_MCP_PUBLIC_BASE_URL`, and provider keys in `.env`.

Use TLS in front of the container through your platform load balancer or a host-level reverse proxy such as Caddy or Nginx.

## Deeper docs

- `README.mcp-localhost.md`: connect to the MCP server on localhost.
- `README.browser-agents.md`: browser planner behavior, outputs, scheduling limits, and security notes.
- `CONTRIBUTING.md`: contribution workflow and review expectations.
- `SECURITY.md`: vulnerability reporting.
- `GOVERNANCE.md`: project governance.
- `content/docs/agent-integration/_index.md`: integration patterns for using the site from inside AI agents.
- `content/security-remediation/control-plane/_index.md`: workflow control-plane design.
- `content/mcp-servers/_index.md`: full MCP server documentation.

## License

This project is licensed under the MIT License. Logos, product names, and brand marks remain the property of their respective owners.
