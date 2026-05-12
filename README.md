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
- A browser chatbot UI that accepts a user-supplied provider key and proxies provider calls through the same-origin site for that request.
- A browser-side agent planner documented in `README.browser-agents.md`.
- Docker images for the static site and MCP server.
- A `docker-compose.yml` stack that serves the site, provider relay paths, and `/mcp` behind one origin.
- Hugo output for static hosting, containerized DigitalOcean deployment, and forkable repo links.

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
| `chatbot_server.py` | Legacy local chatbot API kept for development experiments; not used by the production Compose stack. |
| `Dockerfile` | Multi-stage Hugo/nginx site image with proxy routes for MCP and BYO-key provider relays. |
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

The site includes an AI chatbot UI that uses user-supplied provider credentials. The production Docker stack does not store OpenAI, xAI/Grok, or Anthropic keys in server environment variables.

- `assets/js/ai-chatbot.js` and `assets/css/ai-chatbot.css` implement the browser UI.
- Users paste their provider key in the browser settings panel.
- The key is held only in page memory for the current tab/session.
- The Docker/nginx runtime proxies that single request through `/ai-provider-proxy/openai/`, `/ai-provider-proxy/xai/`, or `/ai-provider-proxy/anthropic/`.
- `chatbot_server.py` remains in the repo as a legacy/local development helper, but the production Compose stack does not run it.

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

Copy the environment template and set at least the public URL. Do not put model-provider API keys in `.env`; users bring their own keys in the browser.

```bash
cp .env.example .env
docker compose up -d --build
```

If a droplet only has the legacy Python `docker-compose` binary, install Compose
v2 or run legacy Compose in detached mode. Attached legacy runs can throw a
Python `compose.cli.log_printer` event-watcher exception even when the site
container is healthy.

```bash
sudo bash scripts/setup_digitalocean_droplet.sh --no-caddy --no-firewall --no-upgrade
docker compose up -d --build
```

The compose stack starts:

- `security-recipes`: Hugo/nginx site
- `mcp-server`: hosted read-only MCP server

Default routes:

```text
site: / 
provider relay: /ai-provider-proxy/openai/v1/responses
MCP endpoint: /mcp
```

For a fresh Ubuntu DigitalOcean droplet, you can use the bootstrap script:

```bash
sudo bash scripts/setup_digitalocean_droplet.sh \
  --domain security-recipes.ai \
  --email admin@security-recipes.ai
```

The script installs Docker/Compose, creates a locked `security-recipes` host
user to own the checkout and `.env`, enables unattended security updates,
configures fail2ban and UFW, binds the compose site to localhost, starts the
site/MCP stack, and places Caddy in front for HTTPS.

The managed app user has no password, no sudo, no SSH keys by default, and is
not added to the Docker group. This limits host file access if a web-facing
process is compromised. Root still performs package, firewall, Caddy, and Docker
orchestration.

The setup script is idempotent: it can be run again after a pull to update
packages, refresh managed host config, rebuild containers, repair checkout
ownership, and restart the compose stack. It does not write model-provider API
keys to `.env`.

### GitHub Actions deployment

The repository workflow builds the Hugo site, checks the Docker Compose config,
builds the Docker images, and then deploys to the DigitalOcean droplet over SSH.
It no longer publishes to `gh-pages`.

Configure these GitHub repository secrets:

- `DIGITALOCEAN_HOST`: droplet IP address or DNS name.
- `DIGITALOCEAN_SSH_PRIVATE_KEY`: private SSH key whose public key is authorized on the droplet.

Optional secrets:

- `DIGITALOCEAN_USER`: SSH user. Defaults to `root`.
- `DIGITALOCEAN_PORT`: SSH port. Defaults to `22`.
- `DIGITALOCEAN_APP_DIR`: repo checkout path. Defaults to `/opt/security-recipes.ai`.
- `DIGITALOCEAN_APP_USER`: locked host user that owns the checkout. Defaults to `security-recipes`.

On deploy, the action SSHes into the droplet, fetches the deployed branch,
resets the checkout to that remote branch, preserves `.env`, rebuilds the
Compose stack, restores checkout ownership to the managed app user, and
restarts the site and MCP server.

To uninstall the managed deployment while leaving Docker packages and the repo in place:

```bash
sudo bash scripts/uninstall_digitalocean_droplet.sh
```

For deeper cleanup:

```bash
sudo bash scripts/uninstall_digitalocean_droplet.sh \
  --remove-repo \
  --remove-images \
  --remove-app-user
```

## Regenerate artifacts

The build and deployment workflow only builds the Hugo site. It does not run
generator checks, checksum comparisons, or control-plane validations as required
build gates.

Generated artifacts can still be refreshed manually when you intentionally
change source models, manifests, policies, or scripts:

```bash
python scripts/generate_agentic_assurance_pack.py
```

Optional maintenance scripts remain available for deeper local review, but they
are not required before building or deploying the site:

```bash
python scripts/validate_workflow_control_plane.py
python scripts/generate_agentic_assurance_pack.py --check
```

Representative generator and evaluator families:

- `generate_*_pack.py`: produces JSON evidence packs under `data/evidence/`.
- `evaluate_*_decision.py`: evaluates runtime requests against generated packs.
- `generate_mcp_gateway_policy.py`: derives gateway policy from workflow manifests.
- `validate_workflow_control_plane.py`: validates workflow manifests and emits an audit report.
- `generate_cve_recipes_from_ghad.py`: drafts CVE recipe pages from a local GitHub Advisory Database checkout.

Generated files are part of the repo's source-controlled evidence surface, but
checksum and validation drift no longer blocks the site build.

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

The repo is ready for containerized DigitalOcean hosting and can still be built
as a static Hugo site for other platforms.

For a single-origin production deployment, the provided Docker stack is the most complete shape. It serves the static site, proxies browser-supplied model-provider requests, and exposes the hosted MCP endpoint from the same public origin. Set `SECURITY_RECIPES_BASE_URL`, `SECURITY_RECIPES_REPO_URL`, and `RECIPES_MCP_PUBLIC_BASE_URL` in `.env`.

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
