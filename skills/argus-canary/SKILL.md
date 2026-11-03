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
4. If a tool answers `seed-demo`, `refused`, or `dry-run`, report that
   word to the user. Do not translate it into a pass.

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
  issue, but the commit and pipeline links are not walked yet. Name
  what is live and what is missing, in that order.

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
  the live adapter supplies it.
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
fixture from the clean state. The machine re-proves that with
`node scripts/run_killtest_benchmark.js` in the repo.

### 3. Propose, do not apply: `propose-typed-change`

Inputs: `issueKey` (required), `ruleId` (required, `r01` through `r20`).

Returns a Typed Change IR proposal. Read it as follows.

- `status: proposal-only` and `executed: false` are the only healthy
  outcome today. Show the `director` line to leads and the `standby`
  line to the on-call engineer. They describe the same change.
- `digest` is the content address of the proposal. A human approves
  this exact value, or a digest of the exact plan they were shown.
  One character of drift means a different plan.
- `status: refused` means the IR rejected the input. Raw shell syntax
  such as `;`, `&&`, `|`, backticks, and `$(` in any field is refused by
  construction. Do not work around a refusal by rephrasing the same
  command into a different field. Report the refusal.

An unknown rule id is refused by name. When you propose, cite the rule
title from the response, not from memory. The proposal operation today
is a notification typed op; the per-rule repair synthesis is later work,
so describe the proposal as a governed proposal, not as a finished fix.

### 4. Fail over only with a human digest: `escalate-standby-responder`

Inputs: `issueKey` (required), `approvalDigest` (required, 64 lowercase
hex characters).

Outcomes, in the only orders that are safe.

- `status: refused`, `verified: false`, `executed: false`: the normal
  answer while no approved plan is stored, no roster is configured, or
  the digest shape is wrong. Report it and stop.
- `status: dry-run` with `wouldPage`: the roster math ran and no write
  happened. `escalated: true` means the ack window (900 seconds by
  default) elapsed with no acknowledgement, so the next reachable
  engineer would be paged. Say "would page", never "paged".
- The executing writer path exists in the adapter and is unit tested,
  but approved plans are not persisted yet, so this action still must
  not reach `executed: true`. If you see it, treat it as a bug and say
  so.

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
