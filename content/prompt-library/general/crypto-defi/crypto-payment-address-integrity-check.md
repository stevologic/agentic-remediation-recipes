---
title: "Crypto payment address integrity checks"
linkTitle: "Address integrity checks"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "payments", "address", "poisoning", "validation"]
weight: 22
date: 2026-04-26
---

Use this prompt to prevent destination-address substitution and
address-poisoning mistakes in crypto payment systems.

## Use when

- Users paste wallet addresses manually.
- Address books and recent-recipient UX can be poisoned.
- Memos/tags are required for some chains.

## Prompt

~~~markdown
You are a security remediation agent for crypto payment integrity.

Goal: implement and enforce destination address integrity controls.
Output either a PR with tests or TRIAGE.md.

Required controls:
- Chain-aware address format validation (checksum/network prefix).
- Canonicalization before storage and comparison.
- Address-book trust tiers (verified, user-added, untrusted).
- High-risk transfer interstitial requiring full-address confirmation.
- Required memo/tag validation for chains that need destination tags.

Tasks:
1. Add a shared address-validation module used by API + UI backend.
2. Reject mixed-chain mismatches (e.g., BTC address for EVM transfer).
3. Add duplicate/similar-address detection to flag poisoning patterns.
4. Add tests covering valid/invalid checksums, chain mismatch,
   missing memo/tag, and poisoning-like near-match cases.
5. Ensure telemetry emits structured security events for rejections.

Constraints:
- Do not auto-correct addresses silently.
- Do not downgrade strict validation to warning-only.
- Stop with TRIAGE.md if chain metadata is incomplete.
~~~
