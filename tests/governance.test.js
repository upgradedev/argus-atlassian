'use strict';

// Persistence and approval-execution contract for stored Typed Change IR.
// The important properties are negative: a wrong digest never reaches the
// writer, an already executed plan cannot replay, and a verified plan with
// no live writer is a dry run rather than claimed success.
// Run: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createGovernance,
  serializeChange,
  deserializeChange,
} = require('../src/governance.js');
const { InMemoryPlanStore } = require('../src/adapters/plan_store.js');
const { AtlassianWriter } = require('../src/adapters/atlassian.js');
const { TypedChangeIR } = require('../src/argus/index.js');

const NOW = '2026-11-04T05:45:00.000Z';
const clock = { nowIso: () => NOW };

function fakeClient() {
  const calls = [];
  return {
    calls,
    async assignIssue(issueKey, accountId) {
      calls.push(['assignIssue', issueKey, accountId]);
      return { status: 204 };
    },
  };
}

function makeGovernance({ writerClient = fakeClient() } = {}) {
  const store = new InMemoryPlanStore();
  return {
    store,
    client: writerClient,
    governance: createGovernance({
      store,
      writer: writerClient ? new AtlassianWriter(writerClient) : null,
      clock,
      storageMode: 'memory-test',
    }),
  };
}

test('change serialization round-trips through storage JSON with the same digest', () => {
  const { governance } = makeGovernance();
  return governance.propose({ issueKey: 'OPS-12', ruleId: 'r01', proposedBy: 'acc-owner' })
    .then((proposal) => {
      const revived = deserializeChange(JSON.parse(JSON.stringify(proposal.change)));
      assert.ok(revived instanceof TypedChangeIR);
      assert.equal(revived.digest(), proposal.digest);
      assert.deepEqual(serializeChange(revived), proposal.change);
    });
});

test('proposal is stored and latest-by-issue resolves to it', async () => {
  const { governance, store } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r06' });
  assert.equal(proposal.status, 'proposed');
  assert.equal(proposal.storage, 'memory-test');
  assert.equal(await store.get(`latest:OPS-12`), proposal.changeId);
  assert.equal((await governance.getProposal({ issueKey: 'OPS-12' })).digest, proposal.digest);
});

test('wrong approval digest refuses before any client write and keeps plan proposed', async () => {
  const { governance, client, store } = makeGovernance();
  await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-12',
    approvalDigest: '0'.repeat(64),
    standbyAccountId: 'acc-standby',
    approvedBy: 'acc-owner',
  });
  assert.equal(out.status, 'refused');
  assert.equal(out.verified, false);
  assert.equal(out.executed, false);
  assert.deepEqual(client.calls, []);
  assert.equal((await store.get('proposal:proposal-OPS-12-r01-1')).status, 'proposed');
});

test('verified plan without a responder executes nothing', async () => {
  const { governance, client } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-12', approvalDigest: proposal.digest, approvedBy: 'acc-owner',
  });
  assert.equal(out.status, 'verified');
  assert.equal(out.verified, true);
  assert.equal(out.executed, false);
  assert.deepEqual(client.calls, []);
});

test('verified plan with a responder executes once and seals a receipt', async () => {
  const { governance, client, store } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-12',
    approvalDigest: proposal.digest,
    standbyAccountId: 'acc-standby',
    approvedBy: 'acc-owner',
  });
  assert.equal(out.status, 'executed');
  assert.equal(out.verified, true);
  assert.equal(out.executed, true);
  assert.equal(out.assignedTo, 'acc-standby');
  assert.match(out.receipt.root, /^[0-9a-f]{64}$/);
  assert.match(out.receipt.spoken, /acc-owner approved/);
  assert.deepEqual(client.calls, [['assignIssue', 'OPS-12', 'acc-standby']]);
  const stored = await store.get(`proposal:${proposal.changeId}`);
  assert.equal(stored.status, 'executed');
  assert.equal(stored.receipt.root, out.receipt.root);
});

test('an executed plan cannot replay with the same valid digest', async () => {
  const { governance, client } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const args = {
    issueKey: 'OPS-12', approvalDigest: proposal.digest,
    standbyAccountId: 'acc-standby', approvedBy: 'acc-owner',
  };
  await governance.approveAndEscalate(args);
  const replay = await governance.approveAndEscalate(args);
  assert.equal(replay.status, 'refused');
  assert.equal(replay.executed, false);
  assert.equal(client.calls.length, 1);
});

test('verified plan without a live writer is an explicit dry run', async () => {
  const { governance } = makeGovernance({ writerClient: null });
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-12', approvalDigest: proposal.digest,
    standbyAccountId: 'acc-standby', approvedBy: 'acc-owner',
  });
  assert.equal(out.status, 'verified-dry-run');
  assert.equal(out.verified, true);
  assert.equal(out.executed, false);
  assert.equal(out.wouldAssignTo, 'acc-standby');
});

test('roster timing chooses the second reachable responder only after the window', async () => {
  const { governance, client } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-12',
    approvalDigest: proposal.digest,
    approvedBy: 'acc-owner',
    elapsedSeconds: 901,
    roster: [
      { accountId: 'acc-primary', name: 'Nikos' },
      { accountId: 'acc-standby', name: 'Maria' },
    ],
  });
  assert.equal(out.assignedTo, 'acc-standby');
  assert.equal(out.escalated, true);
  assert.deepEqual(client.calls, [['assignIssue', 'OPS-12', 'acc-standby']]);
});

test('repair PR execution is separately replay-guarded from standby escalation', async () => {
  const { governance, client } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const repaired = await governance.approveAndOpenRepairPr({
    issueKey: 'OPS-12',
    approvalDigest: proposal.digest,
    approvedBy: 'acc-owner',
    workspace: 'ws',
    repository: 'repo',
    repairer: async (change, digest, args) => {
      client.calls.push(['repairPr', change.changeId, digest === proposal.digest, args.workspace]);
      return { branch: 'argus/repair', pullRequestId: 9, applied: ['r01'] };
    },
  });
  assert.equal(repaired.status, 'repair-pr-open');
  assert.equal(repaired.executed, true);
  assert.equal(repaired.repairPr.pullRequestId, 9);

  const replay = await governance.approveAndOpenRepairPr({
    issueKey: 'OPS-12', approvalDigest: proposal.digest,
    workspace: 'ws', repository: 'repo', repairer: async () => ({}),
  });
  assert.equal(replay.status, 'refused');

  const escalated = await governance.approveAndEscalate({
    issueKey: 'OPS-12', approvalDigest: proposal.digest,
    standbyAccountId: 'acc-standby', approvedBy: 'acc-owner',
  });
  assert.equal(escalated.status, 'executed');
});

test('verified repair PR without a writer returns a re-evaluated YAML preview', async () => {
  const { governance } = makeGovernance({ writerClient: null });
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndOpenRepairPr({
    issueKey: 'OPS-12',
    approvalDigest: proposal.digest,
    pipelineYaml: 'pipelines:\n  default:\n    - step:\n        script:\n          - npm test || true\n',
  });
  assert.equal(out.status, 'verified-dry-run');
  assert.equal(out.executed, false);
  assert.ok(out.repair.applied.includes('r01'));
  assert.doesNotMatch(out.repair.yaml, /\|\| true/);
});

test('a plan for another issue cannot be approved through this issue key', async () => {
  const { governance, client } = makeGovernance();
  const proposal = await governance.propose({ issueKey: 'OPS-12', ruleId: 'r01' });
  const out = await governance.approveAndEscalate({
    issueKey: 'OPS-99', changeId: proposal.changeId, approvalDigest: proposal.digest,
    standbyAccountId: 'acc-standby',
  });
  assert.equal(out.status, 'refused');
  assert.deepEqual(client.calls, []);
});
