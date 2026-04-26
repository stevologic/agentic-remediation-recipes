---
title: "Hot-wallet transaction policy enforcement"
linkTitle: "Hot-wallet policy enforcement"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "wallet", "payments", "policy", "transaction-signing"]
weight: 21
date: 2026-04-26
---

Use this prompt to harden a hot-wallet signing pipeline so unsafe
transactions are blocked before they can be signed.

## Use when

- Payment services sign transfers from online wallets.
- Destination and amount controls exist but are inconsistently enforced.
- You need reproducible policy checks in CI and runtime.

## Prompt

~~~markdown
You are a security remediation agent for a cryptocurrency payment system.

Goal: enforce a deterministic transaction-policy gate for hot-wallet
signing requests. Produce either:
1) a PR that adds policy enforcement + tests, or
2) TRIAGE.md if you cannot safely complete.

Policy checks must include: allowed chain, allowed asset, destination
allowlist, per-tx cap, rolling daily cap, and required business reason.

Constraints:
- Never sign or broadcast real transactions.
- Operate in dry-run/simulation mode only.
- Fail closed if policy data is unavailable.

Implementation tasks:
1. Locate signing entrypoints and insert a `validateTransactionPolicy`
   guard before any signer call.
2. Ensure every rejection is logged with reason code and request ID,
   without logging secrets.
3. Add tests for allow, reject-by-destination, reject-by-amount,
   reject-by-daily-cap, and reject-by-missing-policy-store.
4. Add a runbook note describing rollback and emergency deny-all mode.

Stop and write TRIAGE.md if signing paths are dynamic/reflection-based
and cannot be bounded confidently.
~~~
