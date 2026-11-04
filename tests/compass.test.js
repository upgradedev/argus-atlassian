'use strict';

// Compass data-provider contract tests. Expected payload shape is the
// output of Atlassian's documented DataProviderResponse.build(): an
// externalSourceId plus metric definitions carrying initialValue fields.
// We build that plain object locally instead of taking the toolkit's
// older @forge/api major as a transitive runtime dependency.
// Run: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  parseBitbucketRepositoryUrl,
  buildCompassDataProviderResult,
  createCompassDataProvider,
  compassDataProviderCallback,
  FAKE_GREEN_VIOLATIONS_METRIC,
  RULES_PASSING_METRIC,
} = require('../src/adapters/compass.js');
const { evaluateRules, CLEAN_STATE, violatingStateFor } = require('../src/argus/index.js');

test('only canonical Bitbucket repository URLs map to an external source', () => {
  assert.deepEqual(
    parseBitbucketRepositoryUrl('https://bitbucket.org/acme/payments/src/main/'),
    {
      workspace: 'acme',
      repoSlug: 'payments',
      externalSourceId: 'bitbucket:acme/payments',
    },
  );
  assert.equal(parseBitbucketRepositoryUrl('https://bitbucket.org/acme'), null);
  assert.equal(parseBitbucketRepositoryUrl('https://example.com/acme/payments'), null);
  assert.equal(parseBitbucketRepositoryUrl('not a url'), null);
});

test('result declares Argus custom metrics with real initial values', () => {
  const out = buildCompassDataProviderResult({
    url: 'https://bitbucket.org/acme/payments',
    evaluation: evaluateRules(violatingStateFor('r01')),
  });
  assert.equal(out.externalSourceId, 'bitbucket:acme/payments');
  assert.equal(out.events, undefined);
  assert.equal(out.metrics.builtIn, undefined);
  assert.deepEqual(out.metrics.custom.map((m) => [m.name, m.initialValue]), [
    [FAKE_GREEN_VIOLATIONS_METRIC, 1],
    [RULES_PASSING_METRIC, 19],
  ]);
});

test('without an evaluation, definitions still register with null values', () => {
  const out = buildCompassDataProviderResult({ url: 'https://bitbucket.org/acme/payments' });
  assert.deepEqual(out.metrics.custom.map((m) => m.initialValue), [null, null]);
});

test('provider fetches default branch YAML and never throws away definitions on API failure', async () => {
  const fetched = [];
  const provider = createCompassDataProvider({
    client: {
      async getRepository(workspace, repo) {
        fetched.push(['repo', workspace, repo]);
        return { uuid: '{repo-uuid}', mainbranch: { name: 'main' } };
      },
    },
    reader: {
      async fetchPipelineEvaluation(workspace, repo, ref) {
        fetched.push(['eval', workspace, repo, ref]);
        return { evaluation: evaluateRules(CLEAN_STATE) };
      },
    },
  });
  const out = await provider({ url: 'https://bitbucket.org/acme/payments' });
  assert.deepEqual(fetched, [
    ['repo', 'acme', 'payments'],
    ['eval', 'acme', '{repo-uuid}', 'main'],
  ]);
  assert.equal(out.metrics.custom[1].initialValue, 20);

  const failing = createCompassDataProvider({
    client: { async getRepository() { throw new Error('down'); } },
    reader: null,
  });
  const fallback = await failing({ url: 'https://bitbucket.org/acme/payments' });
  assert.deepEqual(fallback.metrics.custom.map((m) => m.initialValue), [null, null]);
});

test('callback logs an unsuccessful Compass setup with the documented fields', async () => {
  const errors = [];
  const logger = { error: (...a) => errors.push(a), info: () => {} };
  await compassDataProviderCallback(
    { success: false, url: 'https://bitbucket.org/acme/payments', errorMessage: 'bad scope' },
    logger,
  );
  assert.equal(errors.length, 1);
  assert.match(String(errors[0][0]), /bad scope/);
});
