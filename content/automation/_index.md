---
title: Automation, not agentic
linkTitle: Automation
weight: 11
toc: true
sidebar:
  open: true
description: >
  Deterministic, well-worn automation for risk reduction — Dependabot,
  Renovate, npm audit, pip-audit, code scanning, and friends. Use these
  before (and alongside) your agentic flows.
---

{{< callout type="info" >}}
**Before you reach for a model, reach for a `--fix` flag.** A huge
amount of remediation work is deterministic, well-understood, and
already solved by tools that don't need an LLM in the loop. Agentic
flows earn their keep on the problems these tools can't touch —
not the ones they already handle.
{{< /callout >}}

## When automation beats agents

A dependency bump that a lockfile resolver can produce byte-for-byte is
not a job for a reasoning model. Neither is a lint auto-fix, a formatter
run, or a mechanical rename. Deterministic tools give you three things
an agent cannot:

- **Reproducibility.** The same input produces the same output, every
  time, on every developer machine and every CI runner.
- **Zero cost at scale.** No token bill, no rate limits, no per-repo
  opt-in. They run on every push, cheerfully, forever.
- **A trust surface you already have.** Dependabot PRs have been
  reviewed in your org for years. Your reviewer muscle memory works.

The rule of thumb: if the fix is mechanical and the diff is the same
for everyone, automation wins. If the fix requires reading the
surrounding code to decide *whether* to apply it, *where* to apply
it, or *how* to migrate callers, an agent is earning its keep.

## The catalog

### Version bumps & SCA

- **GitHub Dependabot** — version updates, security updates, grouped
  updates. Native to GitHub; configuration lives in
  `.github/dependabot.yml`. Great first line of defense against known
  CVEs in `package.json`, `requirements.txt`, `go.mod`, `Gemfile`,
  `composer.json`, and more.
- **Renovate** — the open-source competitor to Dependabot with
  substantially more configuration surface: custom schedules, auto-
  merge rules per dep, regex managers for arbitrary manifests, and
  presets. Worth the setup if you need fine control.
- **npm audit / pnpm audit / yarn audit** — built-in CVE reports.
  `npm audit fix` applies lockfile-only upgrades within your semver
  ranges; `npm audit fix --force` also crosses major versions (review
  carefully).
- **pip-audit** — `pip-audit --fix` rewrites `requirements.txt`
  pinning against PyPI's vulnerability database. Pair with a
  `requirements.in` / `pip-compile` workflow for clean diffs.
- **uv / Poetry** — both expose `add`/`lock` commands that resolve
  bumps deterministically; Poetry has a `poetry update` and uv has
  `uv lock --upgrade-package`.
- **Go** — `go get -u ./...` followed by `go mod tidy` gives you a
  clean, verifiable bump. `govulncheck` reports reachable CVEs.
- **Cargo** — `cargo update` for bumps; `cargo audit` for CVE
  reporting via RustSec.
- **Bundler** — `bundle update --conservative <gem>` bumps a single
  gem without cascading the rest of the lockfile.

### Code scanning & lint auto-fix

- **GitHub code scanning (CodeQL)** — SARIF output, PR annotations,
  default setup for most languages. Starts showing value the same day
  you flip it on.
- **ESLint / Prettier / Biome** — `--fix` flags. Wire into a
  pre-commit hook and a CI job; most style drift disappears on its
  own.
- **Ruff** — `ruff check --fix` and `ruff format` for Python. Fast
  enough that there's no reason not to run it on every save.
- **gofmt / goimports** — the table stakes for Go style.
- **Clippy** — `cargo clippy --fix` for Rust.

### Secret detection

- **Gitleaks** — open-source SAST for secrets. Detects hardcoded
  credentials, API keys, tokens, and high-entropy strings across
  source code, git history, and uncommitted changes. Configuration
  lives in `.gitleaks.toml` (rules, allowlists, path filters).
  Typical deployment:
  - **Pre-commit hook** — `gitleaks protect --staged` blocks a
    commit before the secret ever lands in history.
  - **CI job** — `gitleaks detect --source . --log-opts="--all"`
    scans the full history on every PR and fails the build if a
    new secret appears.
  - **GitHub Action** — the official `gitleaks/gitleaks-action` is
    a drop-in; enable `GITLEAKS_ENABLE_UPLOAD_ARTIFACT` to get the
    SARIF into the Security tab.

  Tune the ruleset: the defaults are generous, and allowlisting
  legitimate fixtures / test data (via `[allowlist]` entries with
  `paths`, `regexes`, or `stopwords`) is what makes Gitleaks usable
  in a large repo. Pair with `gitleaks git` in the pre-receive hook
  if you run a self-hosted git server.

- **TruffleHog** — credential detection with **verified / unverified**
  confidence tiers. The killer feature is live verification: when
  TruffleHog finds what looks like an AWS key, it calls AWS to
  confirm the key is active before flagging it. Dramatically cuts
  false positives but requires the scanner to have outbound network
  access.
- **GitHub secret scanning** — built into GitHub for supported
  partners, with push protection. Flip it on — zero config, and
  the push-protection path stops secrets at the git-push boundary
  rather than after the fact.

### Sensitive Data Element (SDE) detection

Secret scanners catch credentials. **SDE scanners** catch the
broader category — PII, PHI, PCI data, and other regulated
content that shouldn't live in source, logs, or shared configs.

- **Earlybird** (American Express,
  [github.com/americanexpress/earlybird](https://github.com/americanexpress/earlybird))
  — open-source SDE scanner with a deliberately broad module set:
  credentials (API keys, tokens, private keys), PII (SSNs, credit
  card numbers, email addresses, phone numbers), PHI patterns, and
  language-specific hotspots (SQL-in-strings, hard-coded IPs, weak
  crypto calls). Written in Go, fast enough to run in a pre-commit
  hook on monorepos.

  Where Earlybird earns its keep:
  - **Pre-commit.** `earlybird scan --path .` with `--severity
    high` as a blocking gate; lower severities report but don't
    block. Install via the project's binary release or `go install`.
  - **CI.** Run against the diff (`--git-staged` or `--git-tracked`)
    to catch regressions on PR. Full-repo scans belong on a
    schedule, not on every push.
  - **Custom modules.** The `.ge_ignore` file and
    `config/*.json` rule packs make it straightforward to add
    organisation-specific sensitive patterns (internal account
    ID shapes, proprietary identifiers) without forking.
  - **Output formats.** JSON, JUnit XML, and human-readable —
    JUnit plugs directly into most CI dashboards.

  Earlybird overlaps with Gitleaks on the credential side. Running
  both is common — Gitleaks for git-history-aware secret sweeps,
  Earlybird for the wider SDE surface on the working tree. Dedupe
  downstream if you route both into the same triage queue.

- **detect-secrets** (Yelp) — the original audit-style scanner
  with a `.secrets.baseline` file so reviewers can snooze known
  findings deliberately rather than by allowlist regex.
- **Presidio** (Microsoft) — PII detection and redaction library
  aimed at structured and unstructured text (logs, free-form
  fields, CSV exports), with named-entity and regex recognizers
  bundled. Heavier to stand up than Earlybird but the right tool
  when the SDE surface is data flowing through services, not just
  code in a repo.

**Where this pairs with the agentic workflow.** The
[Sensitive Data Element remediation workflow]({{< relref
"/security-remediation/sensitive-data" >}}) assumes a deterministic
scanner like Earlybird (or the equivalent) is already surfacing
findings; the agent's job is the *fix-and-PR* step, not the
detection step. Running a good SDE scanner is a prerequisite, not
an alternative.

### Policy-as-code

- **OPA / Conftest** — deterministic policy checks against Terraform
  plans, Kubernetes manifests, Dockerfiles. The fix is usually "edit
  the file"; the automation is the *enforcement* of what "correct"
  means.
- **tfsec / Checkov / kube-linter** — category-specific scanners
  that ship with sensible defaults and `--fix` in many cases.

### CI-level auto-remediation

- **GitHub Actions** — a tiny workflow that runs `npm audit fix` /
  `pip-audit --fix` / `go mod tidy` on a schedule and opens a PR is
  often enough to close the long tail of low-severity findings
  without touching a single agent.
- **Scheduled `make fix`** — if you have a `Makefile` target that
  runs every `--fix` flag you trust, a weekly scheduled job that
  commits the result to a branch and opens a PR is a surprisingly
  powerful pattern.

## How automation and agentic flows compose

The two patterns are complementary, not competitive. A healthy setup
looks roughly like this:

1. **Automation runs first and closes the easy cases.** Dependabot
   grouped updates merge themselves when CI is green and the diff is
   lockfile-only.
2. **The remainder lands in the agentic queue.** Findings that
   require code edits — a deprecated API migration, a policy
   violation that needs refactoring, a transitive CVE with no upstream
   patch — route to the agent recipes on this site.
3. **The agent uses the same deterministic tools you do.** The PR an
   agent opens should still pass `eslint --fix`, `ruff`, `go vet`,
   your OPA policies, and your test suite — because those are the
   gate, whether a human or an agent produced the diff.

Agents don't replace automation. They *extend* the reach of
automation into problems that need judgment.

## Getting started

A minimal "automation first" posture, in order of return on effort:

1. **Turn on Dependabot security updates.** Zero config required,
   immediate CVE-closing PRs.
2. **Add `.github/dependabot.yml`** for grouped version updates so
   you're not reviewing 40 bumps a week.
3. **Enable GitHub secret scanning + push protection.**
4. **Enable GitHub code scanning (CodeQL default setup).**
5. **Wire `npm audit` / `pip-audit` / `go vet` / `govulncheck` into
   CI** with a non-blocking "report" job first, then promote to
   blocking once the noise floor is manageable.
6. **Add a scheduled auto-fix PR workflow** that runs your trusted
   `--fix` commands and commits the result.
7. **Only then** layer the agent recipes on top — they'll have much
   less to do, and the work that's left is genuinely the work that
   needs judgment.

## See also

- [Agents]({{< relref "/agents" >}}) — per-tool remediation recipes for the problems automation can't handle
- [MCP Server Access]({{< relref "/mcp-servers" >}}) — how agents reach the context that deterministic tools don't need
- [Agentic Security Remediation]({{< relref "/security-remediation" >}}) — security-team-operated workflows that combine both patterns
- [Prompt Library]({{< relref "/prompt-library" >}}) — community prompts that extend automation into judgment calls
