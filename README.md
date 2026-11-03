# Argus for Jira, JSM and Bitbucket

[![CI](https://github.com/upgradedev/argus-atlassian/actions/workflows/ci.yml/badge.svg)](https://github.com/upgradedev/argus-atlassian/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/upgradedev/argus-atlassian)](LICENSE)

Argus links JSM incidents to Bitbucket pipelines via Teamwork Graph, fires a synthetic canary to expose fake-green gates, and opens the verified repair PR.

For Dimitris Lagos, SRE and Release Lead on JSM incident standby at a fintech engineering team. His P1 opens in Jira Service Management minutes after a Bitbucket Pipeline and a Jira Release showed all green. The green badge was the lie. Argus reads the exit codes under the badge.

**Try it with no account:** open the
[anonymous interactive demo](https://upgradedev.github.io/argus-atlassian/),
paste a `bitbucket-pipelines.yml`, and watch twenty deterministic rules
judge it in your browser. Nothing leaves the page.

## Contents

- [Status, read this before the claims](#status-read-this-before-the-claims)
- [How the verification works](#how-the-verification-works)
- [The twenty rules](#the-twenty-rules)
- [Architecture](#architecture)
- [Quickstart](#quickstart)
- [Install on your Atlassian site](#install-on-your-atlassian-site)
- [Zero egress and least privilege](#zero-egress-and-least-privilege)
- [Evidence](#evidence)
- [Well-Architected and EU AI Act notes](#well-architected-and-eu-ai-act-notes)
- [Repository layout](#repository-layout)

## Status, read this before the claims

| Surface | State today |
|---|---|
| Domain core (canary, change IR, evidence, provenance, receipts, standby, shield, rules r01-r20) | Implemented and tested. `node --test` gives 62 pass, 0 fail |
| Kill-test benchmark | Implemented. `node scripts/run_killtest_benchmark.js` gives rules accepted 20/20 on Argus synthetic fixtures. It is a fixture separation result, not a field measurement |
| Forge manifest | Written and gate-checked. Zero egress, Rovo agent plus MCP plus skill. Not deployed: `app.id` arrives when the owner runs `forge register` on the Atlassian dev site |
| Live Atlassian reads | Reader adapter implemented behind an injected client and unit tested with a fake client. Not yet exercised against a live site |
| Governed writes | The digest-guarded writer path exists and is unit tested. The shipped action still cannot execute, because approved plans are not persisted yet. It refuses instead |
| Repair PR opening | Proposal synthesis is real (Typed Change IR with a SHA-256 digest). Opening the Bitbucket PR is not wired yet |
| Teamwork Graph connector ingestion | Not implemented. The documented connector shape pairs with external fetch and an auth provider, which would break zero egress, so Argus walks issue and pull request links instead. Recorded as an open decision, not a quiet gap |
| Anonymous demo | Live as a static page (link above). It evaluates YAML you paste. It never connects to your site |

## How the verification works

The contract is an exit code, not an opinion.

1. A trigger fires on its own when a JSM incident or Jira issue is created
   or updated. Nobody has to ask.
2. The reader collects evidence and a provenance thread links incident to
   pipeline run to commit, sealed with SHA-256 so a broken link shows.
3. The Elenchos rules evaluate pipeline facts. A candidate repair must
   first pass the Socratic Kill-Test: a violating fixture exits 1, a clean
   fixture exits 0. A check that passes the violating fixture, or fails
   clean traffic, is thrown out before a human sees it.
4. Repairs are proposed as Typed Change IR, never as raw shell. Shell
   syntax in any field is rejected at construction.
5. The one write path runs only after a human approves the exact plan and
   its SHA-256 digest matches. The approval receipt is Merkle sealed and
   renders as plain text, a spoken sentence, and a Braille-ready line.
6. If the primary responder misses the ack window, the standby roster
   fails over deterministically, one step per window.

## The twenty rules

| Rule | Fails when |
|---|---|
| r01 | Test exit code masked (`\|\| true`) |
| r02 | Test step allowed to fail |
| r03 | Tests skipped |
| r04 | No test step in the pipeline |
| r05 | Passing with no tests allowed |
| r06 | Coverage gate missing or below 80 |
| r07 | No lint step in the pipeline |
| r08 | Lint step allowed to fail |
| r09 | No security scan step |
| r10 | Security scan cannot fail the build |
| r11 | Deploy not gated on tests |
| r12 | Production deploy without manual approval |
| r13 | Required merge checks not enforced |
| r14 | Secret material detected in code |
| r15 | No dependency lockfile |
| r16 | Dependency install not frozen |
| r17 | Cache key ignores the lockfile |
| r18 | Unpinned container image |
| r19 | No job timeout set |
| r20 | Success status forced, not from exit codes |

Each rule earned its place by separating fixtures through the kill-test
machine. The badge-only check a status page uses is thrown out on all
twenty fixtures in the same benchmark. That gap is the product.

## Architecture

```mermaid
flowchart LR
  JSM[JSM Incident and Change] --> Panel[jira:issuePanel + JSM queue page]
  Jira[Jira Release issue] --> Panel
  BB[Bitbucket PR] --> Merge[bitbucket:mergeCheck]
  BB --> PRPanel[PR overview panel]
  Compass[Compass component] --> CPage[Scorecard evidence page]
  Conf[Confluence space] --> PIR[Post-incident page]
  Panel --> Adapter[src/index.js Forge adapter]
  Merge --> Adapter
  PRPanel --> Adapter
  CPage --> Adapter
  PIR --> Adapter
  Agent[rovo:agent Argus Incident Governor] --> Actions[action modules]
  MCP[rovo:mcp Argus Evidence MCP] --> Actions
  Skill[rovo:skill argus-socratic-canary-skill] --> Agent
  Actions --> Adapter
  Adapter --> Core[src/argus pure domain core]
  Adapter --> Atl[src/adapters Atlassian reader and writer]
  Core -. no Forge or Atlassian SDK .-> Atl
```

```mermaid
sequenceDiagram
  participant JSM as JSM incident
  participant Argus as Argus
  participant Core as Pure core
  participant Human as Standby lead
  participant BB as Bitbucket
  JSM->>Argus: issue created trigger
  Argus->>Core: walk provenance, seal thread
  Argus->>Core: evaluate r01-r20 on pipeline facts
  Core-->>Argus: exit 1 with named violations
  Argus->>Core: propose Typed Change IR
  Core-->>Human: plan with SHA-256 digest, three role lenses
  Human-->>Argus: approve exact digest
  Argus->>Core: verify digest before write
  Core-->>BB: writer executes only on match
```

## Quickstart

Prerequisites: Node 20 or newer, Python 3 with PyYAML for the manifest
gate. No install is needed for the tests themselves.

```bash
git clone https://github.com/upgradedev/argus-atlassian
cd argus-atlassian
node --test
```

Expected: `# pass 62` and `# fail 0` (measured 2026-11-03). Under a minute.

```bash
node scripts/run_killtest_benchmark.js
```

Expected tail: `rules accepted: 20/20`, `badge-only check thrown out: 20/20`,
median full validation under 1 ms on the measuring machine. Your machine
will differ; the count must not.

```bash
pip install pyyaml
python scripts/check_manifest.py
```

Expected: eight `PASS` lines and one `USER-GATED` line for `app.id` (see
below). Exit code 0. The gated line is a named manual step, never a pass.

To rebuild the demo page after a domain change:

```bash
node scripts/build_demo.js
```

It rewrites `demo/`, `docs/`, and `static/argus-ui/build/` from the same
source, so the browser and the panel cannot drift.

## Install on your Atlassian site

1. Create a free developer site at
   [go.atlassian.com/cloud-dev](https://go.atlassian.com/cloud-dev) with
   Jira, Jira Service Management, Confluence, and a Bitbucket workspace.
2. Install the Forge CLI and log in: `npm install -g @forge/cli`,
   then `forge login`.
3. From this directory, register the app once: `forge register`.
   Atlassian writes `app.id` into `manifest.yml`. We never ship an
   invented app id.
4. `forge deploy`, then `forge install` into Jira, JSM, Bitbucket,
   Compass, and Confluence on that site. Consent shows 16 scopes and
   zero external domains.
5. In Bitbucket workspace settings, enable Custom merge checks and mark
   Argus Socratic Canary required where you want it to block merges.
6. Open any JSM incident. The Argus panel runs the seed canary on an
   empty site, and the Rovo agent accepts pasted pipeline YAML through
   its kill-test action for an immediate rule verdict.

## Zero egress and least privilege

The manifest declares no external domains, no remotes, no providers, no
Connect modules, and no web triggers. Storage is Forge hosted storage
only. That is stricter than the Runs on Atlassian badge minimum, which
permits analytics egress. `scripts/check_manifest.py` fails the build if
any egress surface returns. Run it against a manifest with a `remotes:`
block added and watch it exit 1; a gate that cannot fail is decoration.

Forge grants one union scope set per app, so the Reader, Evaluator, and
Writer split is enforced in code: the reader adapter throws on write
attempts, and the writer runs only after the approval digest check. Both
behaviors have tests that fail if the guard is removed.

GDPR note: Argus reads issue, pull request, and pipeline metadata inside
the installed Atlassian tenancy, stores nothing outside it, and has no
vendor server to receive personal data. Account ids appear in evidence
records because responders are account ids. No personal data leaves the
tenancy, because no egress path exists in the manifest.

## Evidence

Every number below names its command. Re-run them; do not take our word.

| Claim | Command | Result on 2026-11-03 |
|---|---|---|
| Core and adapter tests | `node --test` | 62 pass, 0 fail |
| Rule separation | `node scripts/run_killtest_benchmark.js` | 20/20 accepted; badge-only check thrown out 20/20; scope is synthetic fixtures |
| Manifest shape | `python scripts/check_manifest.py` | 0 FAIL, 1 USER-GATED (`app.id`) |
| Python twin still green | `python -m unittest discover` in the sister core | 39 tests OK; shared digests pinned in this repo tests |

## Well-Architected and EU AI Act notes

Well-Architected, mapped to Forge instead of recited. Operational
excellence: every gate is a script that prints its counts. Security: zero
egress plus digest-guarded writes. Reliability: standby failover is a
pure function of elapsed seconds. Performance efficiency: the full rule
validation medians under 1 ms locally. Cost: Forge hosted, no vendor
infrastructure. Sustainability: no always-on server exists to idle.

EU AI Act (Regulation EU 2024/1689), by article, with the gap kept in.

| Article | What Argus does | Residual gap |
|---|---|---|
| 10 (data) | Inputs are pipeline and issue facts inside the tenancy; rules are deterministic, no training data | Heuristic facts extraction can misread unusual YAML and must stay labelled as extracted facts |
| 13 (transparency) | Every verdict names the rules, the exit codes, and whether evidence was live, pasted, or seed | The Rovo agent wording is model generated around those facts and can still phrase them badly |
| 14 (human oversight) | The one write path needs a human supplied plan digest; proposals never self-approve | Digest persistence and identity binding arrive with the storage wiring |
| 15 (accuracy) | Rules must separate fixtures in the kill-test before they exist for users; benchmark ships in repo | Fixture separation is not field accuracy; no customer pipeline corpus has been measured |
| 50 (disclosure) | Panels and demo state plainly when a result is seed or not connected | Marketplace listing copy still has to carry the same labels through review |

## Repository layout

```text
manifest.yml            Forge app: zero egress, Rovo pair plus skill
src/index.js            thin Forge adapter (the only SDK aware layer)
src/argus/              pure domain core, zero vendor SDK imports
src/adapters/           Atlassian reader and writer, Forge client factory
skills/argus-canary/    Agent Skills SKILL.md, also the rovo:skill source
tests/                  node:test suites for core, rules, handlers, adapters
scripts/                kill-test benchmark, manifest gate, demo builder
demo/  docs/  static/   generated single-file demo (do not edit by hand)
```

License: MIT. See [LICENSE](LICENSE).

