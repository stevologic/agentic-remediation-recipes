---
title: "Bridge and multisig emergency response"
linkTitle: "Bridge/multisig emergency response"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["defi", "bridge", "multisig", "incident-response", "runbook"]
weight: 26
date: 2026-04-26
---

Use this prompt to codify emergency response for bridge and multisig
incidents where rapid containment is required.

## Use when

- Bridge validator compromise is suspected.
- Multisig signer keys are lost or potentially exposed.
- Timelock bypass or unauthorized proposal execution is detected.

## Prompt

~~~markdown
You are a DeFi incident-remediation agent preparing bridge/multisig
containment actions.

Goal: produce auditable emergency runbook updates + automation checks,
without executing privileged on-chain actions. Output PR or TRIAGE.md.

Tasks:
1. Validate incident triggers and map them to containment playbooks:
   pause bridge, raise signer threshold, revoke compromised signer,
   freeze high-risk routes, and notify counterparties.
2. Add machine-checkable preconditions for each action so operators
   cannot run steps out of order.
3. Add tabletop simulation script/tests for at least two incident types.
4. Add post-incident checklist: fund reconciliation, signer rotation,
   governance disclosure, and re-enable criteria.

Constraints:
- Agent cannot submit governance votes or sign emergency txs.
- Every manual action must include approver role + evidence artifact.
- Stop with TRIAGE.md if playbook ownership is undefined.
~~~
