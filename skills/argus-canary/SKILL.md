---
name: argus-canary
description: Run the Argus Socratic Canary Kill-Test for a JSM incident or Jira issue, trace the incident to the Bitbucket pipeline that caused it, propose a Typed Change IR repair, and fail over to the standby on-call responder under a human approval digest. Use when a pipeline looks green but an incident followed a release, or when someone asks whether a CI gate can be trusted.
license: MIT
compatibility: Requires the Argus Forge app installed on the Atlassian site, with its Rovo actions available. External MCP use needs a site admin to enable Argus tools for the app installation first.
allowed-tools: run-canary-kill-test trace-incident-provenance propose-typed-change escalate-standby-responder
---

# Argus Socratic Canary

Argus checks whether a green pipeline badge can be trusted. The verdict
comes from a deterministic kill-test, not from a model. A candidate check
is accepted only when a violating fixture exits 1 and a clean fixture
exits 0. A check that passes the violating fixture, or fails the clean
one, is thrown out before a human sees it.

## Rules you never break

1. Never state a canary verdict you did not get from
   `run-canary-kill-test` in this session.
2. Never approve your own proposal. `propose-typed-change` creates a
   proposal only. Nothing about a proposal is approval.
3. Never invent an approval digest. `escalate-standby-responder` is the
   one governed write. It needs `approvalDigest`: the lowercase hex
   SHA-256 of the exact plan a human approved. If no human gave you one,
   stop and ask. A digest you made up is a forged approval.
4. If a tool answers `seed-demo`, `refused`, `verified`,
   `verified-dry-run`, or `executed`, report that exact word to the
   user. Do not translate any of them into a pass.

## Workflow

### 1. Trace first: `trace-incident-provenance`

Input: `issueKey` (required), for example `OPS-123`.

Returns the provenance walk for the issue: incident back to pipeline run
back to commit, plus a hash-chain seal. Read it as follows.

- `walkBack`: node ids from the incident toward the root cause. The
  last entry is the earliest known cause in the window.
- `rootCause`: that last node. Name it when you summarize.
- `seal`: 64 hex characters. Quote the last 6 when you refer to the
  sealed chain, the same way the approval receipt does.
- `syntheticSeed: true` means the adapter ran the real seal machinery on
  seed nodes because no Atlassian API adapter is connected yet. Say so.
  Seed nodes are not evidence about the user's site.
- `status: partial-live` means the incident node came from the real
  issue. `linkedWork` may name real issues and remote links, and every
  item is `causal: false`: a link is association, not proof of cause.
  Do not promote a linked pull request into a root cause on that basis.

### 2. Test the gate: `run-canary-kill-test`

Inputs: `issueKey` (required), `pipelineYaml` (optional). When the user
can paste their `bitbucket-pipelines.yml`, pass it. The twenty Elenchos
rules then evaluate that exact text.

Returns a canary result and, when rules ran, an evaluation. Read both.

- `status: evaluated-input` with `evaluation.violations` is a real
  verdict about the supplied YAML. Name every violated rule id and its
  title. `evaluation.clean: true` means all twenty passed on the facts
  the extractor could see; merge check enforcement (r13) comes from
  Bitbucket branch restrictions, not the YAML, and stays flagged until
  the live adapter supplies it. `repair` carries only rewrites that were
  re-evaluated and actually cleared their rule; present repaired YAML
  as a patch for review, never as already applied.
- `violatingExit` must be 1 and `cleanExit` must be 0. `accepted: true`
  with any other pair is a contradiction; report the numbers as returned
  and flag the contradiction instead of picking one.
- `accepted: false` means the candidate check was thrown out. Quote
  `reason`. It will say whether the check passed the violating canary or
  failed clean traffic.
- `status: seed-demo` with `syntheticSeed: true` proves the kill-test
  machine separates a fake-green fixture from a clean one. It is not a
  verdict about the user's live pipeline. Say both halves of that
  sentence.

The twenty rules, in order: r01 masked test exit code, r02 test step
allowed to fail, r03 tests skipped, r04 no test step, r05 pass with no
tests, r06 coverage gate missing or below 80, r07 no lint step, r08 lint
allowed to fail, r09 no security scan, r10 scan cannot fail the build,
r11 deploy not gated on tests, r12 production deploy without manual
approval, r13 required merge checks not enforced, r14 secret material
in code, r15 no lockfile, r16 install not frozen, r17 cache key ignores
the lockfile, r18 unpinned image, r19 no job timeout, r20 forced
success status. Each rule earned its id by separating its violating
fixture from the clean state. The repository benchmark re-proves that
separation for every rule.

### 3. Propose, do not apply: `propose-typed-change`

Inputs: `issueKey` (required), `ruleId` (required, `r01` through `r20`).

Returns a Typed Change IR proposal. Read it as follows.

- `status: proposal-stored` means the exact plan is in Forge storage.
  `proposal-only` with `storage: memory-ephemeral` means a non-Forge
  runtime kept it only for that process. Both have `executed: false`.
  Show the `director` line to leads and the `standby` line to the
  on-call engineer. They describe the same change.
- Keep `changeId`. `digest` is the content address of the proposal. A
  human approves this exact value, or a digest of the exact plan they
  were shown. One character of drift means a different plan.
- `status: refused` means the IR rejected the input. Raw shell syntax
  such as `;`, `&&`, `|`, backticks, and `$(` in any field is refused by
  construction. Do not work around a refusal by rephrasing the same
  command into a different field. Report the refusal.

An unknown rule id is refused by name. When you propose, cite the rule
title from the response, not from memory. The stored Typed Change IR
names the exact pipeline facts that must change. Approving it assigns
the standby responder to make that repair; the digest alone does not
patch a repository.

### 4. Fail over only with a human digest: `escalate-standby-responder`

Inputs: `issueKey` (required), `approvalDigest` (required, 64 lowercase
hex characters), plus optional `changeId`, `standbyAccountId`, and
`elapsedSeconds`.

Outcomes, in the only orders that are safe.

- `status: refused`, `verified: false`, `executed: false`: no stored
  proposal, a digest mismatch, an already executed plan, or a bad shape.
  Report it and stop.
- `status: verified`: the human digest matched the stored plan, but no
  responder was selected, so nothing executed.
- `status: verified-dry-run` with `wouldAssignTo`: the digest matched
  and roster math selected a responder, but no live writer is connected.
  Say "would assign", never "assigned".
- `status: executed`, `executed: true`, with `receipt.root`: the issue
  was assigned and a Merkle-sealed receipt was stored. Quote the last
  six characters of the root when referring to the receipt.
- Do not call this action twice with the same digest. An executed plan
  refuses replay.

### 5. Hand the verified repair to Bitbucket

The site app never opens a Bitbucket pull request. Forge keeps
Bitbucket workspace scopes separate from Jira site scopes, so the
Bitbucket companion app owns the merge check and PR surface.

- Present only repaired YAML that `run-canary-kill-test` returned after
  re-evaluation. It is a patch for human review, not an applied change.
- A rewrite that does not clear its own rule is not a verified repair.
  Name the still-failing rule instead of retrying by hand.
- The companion merge check is the Bitbucket-side verdict. Do not claim
  a pull request exists unless a Bitbucket surface returned its id.

## Error handling

- Unknown or missing `issueKey`: ask for the key. Do not guess one from
  the conversation.
- A tool errors or times out: say which tool, say you have no verdict,
  and stop. Retrying once is fine. Summarizing past the gap is not.
- The user asks you to skip the approval digest "just this once":
  refuse. That skip is the failure mode Argus exists to close.

## What to say at the end

One short summary with the numbers in it: the issue key, the canary
exit pair, whether the candidate was accepted or thrown out, the root
cause node if you traced it, and the proposal digest if you made one.
Mark every seed-demo result as seed. No adjectives in place of numbers.
