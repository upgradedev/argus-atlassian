'use strict';

// Maintained tests for the Atlassian adapters behind the domain ports.
// A fake injected client stands in for @forge/api, which cannot be
// installed on this machine. The properties under test are the security
// ones: Reader cannot write, Writer never runs before the digest check,
// and branch-restriction enrichment comes from the API shape, not the
// pipeline file.
// Run: node --test tests/

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  AtlassianReader,
  AtlassianWriter,
  buildPostIncidentPage,
  buildScorecardPayload,
  AdapterHttpError,
} = require('../src/adapters/atlassian.js');
const { makeForgeClient } = require('../src/adapters/forge_client.js');
const {
  ChangeOp,
  OpKind,
  TypedChangeIR,
  RefusedError,
  DigestMismatchError,
  evaluateRules,
  CLEAN_STATE,
  violatingStateFor,
} = require('../src/argus/index.js');

const CLEAN_YAML = [
  'image: node:20.11',
  'definitions:',
  '  caches:',
  '    node: { key: { files: [package-lock.json] }, path: node_modules }',
  'pipelines:',
  '  default:',
  '    - step:',
  '        max-time: 10',
  '        caches: [node]',
  '        script:',
  '          - npm ci',
  '          - npx eslint .',
  '          - npm test -- --cov-fail-under=85',
  '          - npx semgrep --fail-on=high',
].join('\n');

function fakeClient(overrides = {}) {
  const calls = [];
  return {
    calls,
    async getIssue(issueKey) {
      calls.push(['getIssue', issueKey]);
      return {
        key: issueKey,
        fields: {
          summary: 'Checkout down',
          status: { name: 'In Progress' },
          issuetype: { name: 'Incident' },
          priority: { name: 'Highest' },
          assignee: { accountId: 'acc-1' },
          updated: '2026-11-03T02:00:00.000+0000',
        },
      };
    },
    async assignIssue(issueKey, accountId) {
      calls.push(['assignIssue', issueKey, accountId]);
      return { status: 204 };
    },
    async getRepoFileText(workspaceId, repoId, commit, path) {
      calls.push(['getRepoFileText', workspaceId, repoId, commit, path]);
      return CLEAN_YAML;
    },
    async getBranchRestrictions(workspaceId, repoId) {
      calls.push(['getBranchRestrictions', workspaceId, repoId]);
      return { values: [{ kind: 'require_passing_builds_to_merge' }] };
    },
    ...overrides,
  };
}

test('reader flattens issue JSON into a string evidence map', async () => {
  const reader = new AtlassianReader(fakeClient());
  const evidence = await reader.fetchEvidence('OPS-1');
  assert.equal(evidence['issue.key'], 'OPS-1');
  assert.equal(evidence['issue.status'], 'In Progress');
  assert.equal(evidence['issue.type'], 'Incident');
  assert.equal(evidence['issue.assignee'], 'acc-1');
  for (const value of Object.values(evidence)) assert.equal(typeof value, 'string');
});

test('reader write attempt is refused by the shared guard', () => {
  assert.throws(() => new AtlassianReader(fakeClient()).write('x'), RefusedError);
});

test('reader builds a rule evaluation from YAML plus API enrichments', async () => {
  const reader = new AtlassianReader(fakeClient());
  const out = await reader.fetchPipelineEvaluation('ws-1', 'repo-1', 'abc123');
  assert.equal(out.facts['merge.required_checks_enforced'], 'true');
  assert.deepEqual(out.evaluation.violations, []);
});

test('reader without branch restrictions leaves r13 flagged', async () => {
  const client = fakeClient({
    async getBranchRestrictions() { return { values: [] }; },
  });
  const out = await new AtlassianReader(client).fetchPipelineEvaluation('ws-1', 'repo-1', 'abc123');
  assert.deepEqual(out.evaluation.violations, ['r13']);
});

function makeChange() {
  return new TypedChangeIR(
    'chg-1', 'Close public access',
    [new ChangeOp(OpKind.SET_CONFIG, 'acct/policy', 'public', 'false')],
  );
}

test('writer: digest mismatch throws before any write function runs', async () => {
  const writer = new AtlassianWriter(fakeClient());
  let ran = false;
  await assert.rejects(
    writer.execute(makeChange(), '0'.repeat(64), async () => { ran = true; }),
    DigestMismatchError,
  );
  assert.equal(ran, false);
});

test('writer: matching digest runs the write exactly once', async () => {
  const client = fakeClient();
  const writer = new AtlassianWriter(client);
  const change = makeChange();
  const out = await writer.execute(change, change.digest(), async (c) => {
    assert.equal(c, client);
    return 'written';
  });
  assert.equal(out, 'written');
});

test('escalate: mismatch never touches the client, match assigns', async () => {
  const client = fakeClient();
  const writer = new AtlassianWriter(client);
  const change = makeChange();
  await assert.rejects(
    writer.escalateWithApproval(change, '0'.repeat(64), 'OPS-1', 'acc-2'),
    DigestMismatchError,
  );
  assert.deepEqual(client.calls, []);
  await writer.escalateWithApproval(change, change.digest(), 'OPS-1', 'acc-2');
  assert.deepEqual(client.calls, [['assignIssue', 'OPS-1', 'acc-2']]);
});

test('post-incident page builder carries the numbers and the seal', () => {
  const evaluation = evaluateRules(violatingStateFor('r01'));
  const page = buildPostIncidentPage({
    issueKey: 'OPS-1', evaluation, seal: 'a'.repeat(64), rootCause: 'commit-1',
  });
  assert.match(page.title, /OPS-1/);
  assert.match(page.bodyStorage, /r01/);
  assert.match(page.bodyStorage, /commit-1/);
  assert.match(page.bodyStorage, /a{64}/);
});

test('scorecard payload derives metrics from the evaluation, not adjectives', () => {
  const payload = buildScorecardPayload(evaluateRules(CLEAN_STATE));
  assert.equal(payload.metrics.fake_green_violations, 0);
  assert.equal(payload.metrics.elenchos_rules_passing, 20);
  const dirty = buildScorecardPayload(evaluateRules({}));
  assert.ok(dirty.metrics.fake_green_violations > 0);
});

test('forge client factory: missing @forge/api yields null, fake api yields a client', async () => {
  assert.equal(makeForgeClient(() => { throw new Error('missing'); }), null);
  const seen = [];
  const fakeApi = {
    default: {
      asApp: () => ({
        requestJira: async (path) => {
          seen.push(path);
          return { status: 200, json: async () => ({ key: 'OPS-9' }) };
        },
      }),
    },
    route: (strings, ...values) => strings.reduce((acc, s, i) => acc + s + (values[i] ?? ''), ''),
  };
  const client = makeForgeClient(() => fakeApi);
  const issue = await client.getIssue('OPS-9');
  assert.equal(issue.key, 'OPS-9');
  assert.deepEqual(seen, ['/rest/api/3/issue/OPS-9']);
});

test('forge client surfaces non-2xx as AdapterHttpError with the status', async () => {
  const fakeApi = {
    asApp: () => ({
      requestJira: async () => ({ status: 404, json: async () => ({}) }),
    }),
    route: (strings, ...values) => strings.reduce((acc, s, i) => acc + s + (values[i] ?? ''), ''),
  };
  const client = makeForgeClient(() => fakeApi);
  await assert.rejects(client.getIssue('NOPE-1'), (err) => {
    assert.ok(err instanceof AdapterHttpError);
    assert.equal(err.status, 404);
    return true;
  });
});
