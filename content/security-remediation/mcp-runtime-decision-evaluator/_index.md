---
title: MCP Runtime Decision Evaluator
linkTitle: Runtime Decision Evaluator
weight: 6
sidebar:
  open: true
description: >
  A deterministic runtime evaluator that turns the generated MCP gateway
  policy into allow, hold, deny, and kill-session decisions for agent
  tool calls.
---

{{< callout type="info" >}}
**Why this page exists.** A policy pack is valuable when buyers can
review it. It becomes enterprise infrastructure when an agent host, MCP
gateway, or CI admission check can execute the same policy before a tool
call happens.
{{< /callout >}}

## The product bet

Agentic security programs will not scale because a prompt says "stay in
scope." They scale when the platform can make boring, repeatable
decisions about what an agent may do right now.

The runtime decision evaluator is the enforcement bridge. It consumes the
generated [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
and one runtime request, then returns a structured decision:

- `allow` for declared read-only context.
- `allow_scoped_branch` for branch writes that satisfy branch, path, file
  count, and diff limits.
- `allow_scoped_ticket` for declared ticket or incident writes.
- `hold_for_approval` when a tool scope or change class needs a typed
  human approval record.
- `deny` when the workflow, agent class, namespace, gate phase, branch,
  path, or diff size drifts from policy.
- `kill_session` when a runtime kill signal fires.

This makes AI easier for the enterprise operator: agents do not need to
interpret policy text, and reviewers do not need to reconstruct why a
tool call was allowed.

## What was added

The evaluator lives in the runtime surface, not just the docs:

- `scripts/evaluate_mcp_gateway_decision.py` - a dependency-free CLI and
  importable Python decision function.
- `recipes_evaluate_mcp_gateway_decision` - an MCP tool that exposes the
  same decision function to connected agent hosts and policy sidecars.
- CI checks that exercise allow, deny, hold, and kill decisions against
  the checked-in gateway policy.

Example allowed branch write:

```bash
python3 scripts/evaluate_mcp_gateway_decision.py \
  --workflow-id vulnerable-dependency-remediation \
  --agent-id sr-agent::vulnerable-dependency-remediation::codex \
  --run-id run-123 \
  --tool-namespace repo.contents \
  --tool-access-mode write_branch \
  --branch-name sec-auto-remediation/fix-cve \
  --changed-path package.json \
  --changed-path package-lock.json \
  --diff-line-count 120 \
  --gate-phase tool_call
```

Example approval hold:

```bash
python3 scripts/evaluate_mcp_gateway_decision.py \
  --workflow-id artifact-cache-quarantine \
  --agent-id sr-agent::artifact-cache-quarantine::codex \
  --run-id incident-77 \
  --tool-namespace registries.quarantine \
  --tool-access-mode approval_required \
  --gate-phase tool_call \
  --expect-decision hold_for_approval
```

Example MCP tool call:

```text
recipes_evaluate_mcp_gateway_decision(
  workflow_id="vulnerable-dependency-remediation",
  agent_id="sr-agent::vulnerable-dependency-remediation::codex",
  run_id="run-123",
  tool_namespace="repo.contents",
  tool_access_mode="write_branch",
  gate_phase="tool_call",
  branch_name="sec-auto-remediation/fix-cve",
  changed_paths=["package.json", "package-lock.json"],
  diff_line_count=120
)
```

The response includes the decision, matched workflow, matched scope,
violations, approval state, source manifest hash, and observed runtime
attributes. That output can be attached to PR evidence, MCP gateway logs,
or red-team transcripts.

## Decision model

The evaluator fails closed:

1. Unknown workflow IDs return `deny`.
2. Inactive workflows return `deny`.
3. Missing runtime attributes return `deny`.
4. Undeclared agent classes return `deny`.
5. Undeclared namespace and access-mode pairs return `deny`.
6. Unknown gate phases return `deny`.
7. Branch writes must use the workflow branch prefix and declared file
   scope.
8. Forbidden paths beat allowed paths.
9. Approval-required scopes return `hold_for_approval` until a typed
   approval record is present.
10. Runtime kill signals return `kill_session` before ordinary allow or
    deny checks.

The important design choice is that the evaluator does not ask the model
to decide whether a call is safe. The model requests a tool call; the
policy layer decides.

## Industry alignment

This is the practical enforcement layer implied by current AI security
guidance:

- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) calls out
  MCP authentication, authorization, audit telemetry, command execution,
  shadow servers, and over-sharing risks. A deterministic evaluator gives
  gateways a repeatable authorization and audit decision for each call.
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)
  centers tool misuse, goal hijacking, identity abuse, and rogue agent
  behavior. The evaluator restricts each action to workflow, identity,
  namespace, gate phase, and scope.
- [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework)
  frames trustworthy AI around govern, map, measure, and manage. Runtime
  decisions turn mapped policy into measurable control evidence.
- [NIST AI RMF Generative AI Profile](https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence)
  emphasizes lifecycle governance and measurement for generative AI
  systems. The evaluator creates a repeatable measurement point for
  agentic tool use.
- [CISA Secure by Design](https://www.cisa.gov/securebydesign) pushes
  secure defaults, transparency, and customer security outcomes. Default
  deny plus auditable reasons is the secure default for agent actions.

## Enterprise checklist

Before using the evaluator in production:

- Pin the gateway policy artifact by `source_manifest.sha256`.
- Require every tool call to include `workflow_id`, `agent_id`, `run_id`,
  namespace, access mode, gate phase, and any write scope.
- Store every non-allow decision in the MCP gateway audit log.
- Treat `hold_for_approval` records as typed approvals, not chat
  messages.
- Attach the evaluator response to PR evidence for branch writes.
- Alert on repeated denials, forbidden path attempts, and kill-session
  events.

## See also

- [MCP Gateway Policy Pack]({{< relref "/security-remediation/mcp-gateway-policy" >}})
  - the generated policy input.
- [Agent Identity & Delegation Ledger]({{< relref "/security-remediation/agent-identity-ledger" >}})
  - the identity contract checked by runtime requests.
- [MCP Connector Trust Registry]({{< relref "/security-remediation/mcp-connector-trust-registry" >}})
  - the namespace trust inventory used before production rollout.
- [Agentic Red-Team Drill Pack]({{< relref "/security-remediation/agentic-red-team-drills" >}})
  - the adversarial drills that should include evaluator transcripts.
- [Runtime Controls]({{< relref "/security-remediation/runtime-controls" >}})
  - where inline proxies and session disablement fit.
