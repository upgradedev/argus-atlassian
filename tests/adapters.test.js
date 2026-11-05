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
const { makeBitbucketClient } = require('../apps/bitbucket/src/adapters/bitbucket_client.js');
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
    async getRepository(workspaceId, repoId) {
      calls.push(['getRepository', workspaceId, repoId]);
      return { uuid: '{repo-uuid}', mainbranch: { name: 'main' } };
    },
    async getBranch(workspaceId, repoId, branch) {
      calls.push(['getBranch', workspaceId, repoId, branch]);
      return { target: { hash: branch === 'main' ? 'parent123' : 'repair456' } };
    },
    async commitTextFile(args) {
      calls.push(['commitTextFile', args]);
      return { status: 201 };
    },
    async createPullRequest(args) {
      calls.push(['createPullRequest', args]);
      return { id: 77, links: { html: { href: 'https://bitbucket.org/ws/repo/pull-requests/77' } } };
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

test('writer opens a repair PR only after digest verification and a verified rewrite', async () => {
  const fakeGreen = [
    'image: node:latest',
    'pipelines:',
    '  default:',
    '    - step:',
    '        script:',
    '          - npm test || true',
  ].join('\n');
  const client = fakeClient({
    async getRepoFileText(...args) {
      client.calls.push(['getRepoFileText', ...args]);
      return fakeGreen;
    },
  });
  const writer = new AtlassianWriter(client);
  const change = new TypedChangeIR(
    'proposal-OPS-1-r01-1',
    'Repair proposal for r01: Test exit code masked (|| true)',
    [new ChangeOp(OpKind.SET_CONFIG, 'bitbucket-pipelines.yml', 'test.masked_exit', 'false')],
    { evidenceClaims: ['OPS-1:r01'], preventionRule: 'r01' },
  );
  await assert.rejects(
    writer.openRepairPullRequest(change, '0'.repeat(64), {
      workspace: 'ws', repository: 'repo', issueKey: 'OPS-1',
    }),
    DigestMismatchError,
  );
  assert.deepEqual(client.calls, []);

  const out = await writer.openRepairPullRequest(change, change.digest(), {
    workspace: 'ws', repository: 'repo', issueKey: 'OPS-1',
  });
  assert.equal(out.executed, true);
  assert.equal(out.pullRequestId, 77);
  assert.equal(out.commit, 'repair456');
  assert.ok(out.applied.includes('r01'));
  const names = client.calls.map((call) => call[0]);
  assert.deepEqual(names, [
    'getRepository', 'getBranch', 'getRepoFileText', 'commitTextFile', 'getBranch', 'createPullRequest',
  ]);
  const commit = client.calls.find(([name]) => name === 'commitTextFile')[1];
  assert.doesNotMatch(commit.content, /\|\| true/);
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

test('reader exposes linked work without calling it a root cause', async () => {
  const client = fakeClient({
    async getIssue(issueKey) {
      return {
        key: issueKey,
        fields: {
          summary: 'Checkout down',
          issuelinks: [
            {
              type: { name: 'causes', inward: 'is caused by', outward: 'causes' },
              outwardIssue: { key: 'REL-9' },
            },
          ],
        },
      };
    },
    async getIssueRemoteLinks() {
      return [{
        relationship: 'mentioned in',
        object: {
          url: 'https://bitbucket.org/acme/payments/pull-requests/42',
          title: 'Payments PR 42',
        },
      }];
    },
  });
  const links = await new AtlassianReader(client).fetchLinkedWork('OPS-1');
  assert.deepEqual(links.map((l) => [l.kind, l.id]), [
    ['jira-issue', 'REL-9'],
    ['bitbucket', 'https://bitbucket.org/acme/payments/pull-requests/42'],
  ]);
  assert.equal(links[1].causal, false);
});

test('post-incident page builder escapes untrusted fields', () => {
  const page = buildPostIncidentPage({
    issueKey: '<script>alert(1)</script>',
    evaluation: evaluateRules(violatingStateFor('r01')),
    seal: '<b>bad</b>',
    rootCause: '"quoted"',
  });
  assert.doesNotMatch(page.bodyStorage, /<script>alert/);
  assert.match(page.bodyStorage, /&lt;script&gt;alert/);
  assert.match(page.bodyStorage, /&quot;quoted&quot;/);
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

test('forge client creates a Confluence page through the v2 route', async () => {
  const seen = [];
  const fakeApi = {
    asApp: () => ({
      requestConfluence: async (path, options) => {
        seen.push([path, JSON.parse(options.body)]);
        return { status: 200, json: async () => ({ id: '123', title: 'Report' }) };
      },
    }),
    route: (strings, ...values) => strings.reduce((acc, s, i) => acc + s + (values[i] ?? ''), ''),
  };
  const client = makeForgeClient(() => fakeApi);
  const page = await client.createConfluencePage('456', {
    title: 'Report', bodyStorage: '<p>Body</p>',
  });
  assert.equal(page.id, '123');
  assert.equal(seen[0][0], '/wiki/api/v2/pages');
  assert.deepEqual(seen[0][1], {
    spaceId: '456',
    status: 'current',
    title: 'Report',
    body: { representation: 'storage', value: '<p>Body</p>' },
  });
});

test('bitbucket companion client commits text with URL-encoded src form', async () => {
  const seen = [];
  const fakeApi = {
    asApp: () => ({
      requestBitbucket: async (path, options) => {
        seen.push([path, options]);
        return { status: 201, text: async () => '' };
      },
    }),
    route: (strings, ...values) => strings.reduce((acc, s, i) => acc + s + (values[i] ?? ''), ''),
  };
  const client = makeBitbucketClient(() => fakeApi);
  const out = await client.commitTextFile({
    workspaceId: 'ws', repoId: 'repo', branch: 'argus/repair', parent: 'abc123',
    path: 'bitbucket-pipelines.yml', content: 'image: node:20\n', message: 'fix(ci): repair',
  });
  assert.equal(out.status, 201);
  assert.equal(seen[0][0], '/2.0/repositories/ws/repo/src');
  assert.equal(seen[0][1].method, 'POST');
  assert.match(seen[0][1].body, /branch=argus%2Frepair/);
  assert.match(seen[0][1].body, /parents=abc123/);
  assert.match(seen[0][1].body, /bitbucket-pipelines\.yml=image%3A\+node%3A20%0A|bitbucket-pipelines\.yml=image%3Anode/);
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
