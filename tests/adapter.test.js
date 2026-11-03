'use strict';

// Maintained tests for the Forge adapter handlers (src/index.js).
// These prove honesty properties, not happy paths: the seed is labelled
// synthetic, no handler claims a live verdict, and the governed write
// can never report executed=true while no Atlassian adapter is wired.
// Run: node --test tests/

const test = require('node:test');
const assert = require('node:assert/strict');

const adapter = require('../src/index.js');

test('seed canary separates fake-green from clean and is labelled synthetic', async () => {
  const out = await adapter.runCanaryKillTest({ issueKey: 'OPS-1' });
  assert.equal(out.status, 'seed-demo');
  assert.equal(out.issueKey, 'OPS-1');
  assert.match(out.liveEvidence, /not-connected/);
  assert.equal(out.canary.syntheticSeed, true);
  assert.deepEqual([out.canary.violatingExit, out.canary.cleanExit], [1, 0]);
  assert.equal(out.canary.accepted, true);
});

test('provenance seed walk ends at the seed commit with a verifiable shape', async () => {
  const out = await adapter.traceIncidentProvenance({ issueKey: 'OPS-1' });
  assert.equal(out.syntheticSeed, true);
  assert.deepEqual(out.walkBack, ['seed-incident', 'seed-pipeline', 'seed-commit']);
  assert.equal(out.rootCause, 'seed-commit');
  assert.match(out.seal, /^[0-9a-f]{64}$/);
});

test('propose: shell syntax in ruleId is refused by the Typed Change IR', async () => {
  const out = await adapter.proposeTypedChange({ issueKey: 'OPS-1', ruleId: 'r01; rm -rf /' });
  assert.equal(out.status, 'refused');
  assert.equal(out.executed, false);
});

test('propose: valid ruleId yields a proposal with digest and nothing executed', async () => {
  const out = await adapter.proposeTypedChange({ issueKey: 'OPS-1', ruleId: 'r01' });
  assert.equal(out.status, 'proposal-only');
  assert.equal(out.executed, false);
  assert.match(out.digest, /^[0-9a-f]{64}$/);
});

test('propose: missing ruleId refuses', async () => {
  const out = await adapter.proposeTypedChange({ issueKey: 'OPS-1' });
  assert.equal(out.status, 'refused');
  assert.equal(out.executed, false);
});

test('escalate: bad digest format refuses, never executes', async () => {
  const out = await adapter.escalateStandbyResponder({ issueKey: 'OPS-1', approvalDigest: 'yes' });
  assert.equal(out.status, 'refused');
  assert.equal(out.verified, false);
  assert.equal(out.executed, false);
});

test('escalate: valid digest shape but no roster still refuses', async () => {
  const out = await adapter.escalateStandbyResponder({
    issueKey: 'OPS-1', approvalDigest: 'a'.repeat(64),
  });
  assert.equal(out.status, 'refused');
  assert.equal(out.executed, false);
});

test('escalate: with roster it is a dry run and pages the standby after the window', async () => {
  const out = await adapter.escalateStandbyResponder({
    issueKey: 'OPS-1',
    approvalDigest: 'a'.repeat(64),
    elapsedSeconds: 901,
    roster: [{ id: 'e1', name: 'Nikos' }, { id: 'e2', name: 'Maria' }],
  });
  assert.equal(out.status, 'dry-run');
  assert.equal(out.executed, false);
  assert.equal(out.wouldPage, 'e2');
  assert.equal(out.escalated, true);
});

test('kill-test evaluates supplied pipeline YAML with the real rules', async () => {
  const yaml = [
    'image: node:latest',
    'pipelines:',
    '  default:',
    '    - step:',
    '        script:',
    '          - npm test || true',
  ].join('\n');
  const out = await adapter.runCanaryKillTest({ issueKey: 'OPS-1', pipelineYaml: yaml });
  assert.equal(out.status, 'evaluated-input');
  assert.equal(out.evaluation.clean, false);
  assert.ok(out.evaluation.violations.includes('r01'));
  assert.ok(out.evaluation.violations.includes('r18'));
  assert.equal(out.evaluation.results.length, 20);
});

test('propose refuses an unknown rule id by name', async () => {
  const out = await adapter.proposeTypedChange({ issueKey: 'OPS-1', ruleId: 'r99' });
  assert.equal(out.status, 'refused');
  assert.equal(out.executed, false);
});

test('resolver reports the rule validation count from the real machine', async () => {
  const out = await adapter.resolver();
  assert.equal(out.rulesAccepted, '20/20');
});

test('resolver and merge check never claim live evidence', async () => {
  for (const name of ['resolver', 'socraticCanaryMergeCheck', 'onIssueEvent']) {
    const out = await adapter[name]();
    assert.match(out.liveEvidence, /not-connected/, name);
  }
});
