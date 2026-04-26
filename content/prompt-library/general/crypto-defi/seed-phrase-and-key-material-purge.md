---
title: "Seed phrase and key-material purge"
linkTitle: "Seed/key material purge"
tool: "general"
author: "Security Recipes Maintainers"
team: "Security"
maturity: "development"
model: "GPT-5.3-Codex"
tags: ["crypto", "secrets", "seed-phrase", "private-key", "incident-response"]
weight: 23
date: 2026-04-26
---

Use this prompt to locate and remove exposed wallet seed phrases,
private keys, and signing credentials from code and operational systems.

## Use when

- A scan found possible BIP-39 mnemonics or private keys.
- Secrets appeared in logs, tickets, or CI output.
- Key rotation and chain migration runbooks are needed.

## Prompt

~~~markdown
You are a security remediation agent handling exposed crypto key material.

Goal: eradicate exposed key material and stage rotation actions.
Output either:
- PR + incident audit note, or
- TRIAGE.md when privileged rotation steps are blocked.

Tasks:
1. Search repository and generated artifacts for candidate seed phrases,
   private keys, and keystore passphrases using approved detectors.
2. Remove exposures from source, examples, docs, tests, and fixtures.
3. Replace with redacted placeholders and safe test vectors.
4. Add pre-commit/CI secret detection rules tuned for crypto material.
5. Draft rotation checklist: revoke old keys, rotate signer identities,
   migrate remaining balances, and verify post-rotation health.

Constraints:
- Never print full secret values in output.
- Keep only minimal fingerprint/hash for audit correlation.
- If active key rotation requires production privileges, stop and write
  TRIAGE.md with explicit human steps.
~~~
