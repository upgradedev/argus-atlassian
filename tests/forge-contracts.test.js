'use strict';

// Contracts learned from Forge reference docs during UAT on 2026-11-04:
// - Bitbucket merge checks receive workspace/repository UUID objects and a
//   numeric pullrequest.id, and must resolve to exactly success/message.
// - UI resolvers are built with @forge/resolver define/getDefinitions.
// - @forge/kvs exposes get/set/delete through default or named shapes.
// These tests use loader doubles, never a live Forge runtime.

const test = require('node:test');
const assert = require('node:assert/strict');

const { parseMergeCheckEvent, mergeCheckMessage } = require('../src/forge_events.js');
const { makeResolverHandler } = require('../src/resolver.js');
const { makeForgePlanStore } = require('../src/adapters/plan_store.js');
const { evaluateRules, CLEAN_STATE, violatingStateFor } = require('../src/argus/index.js');

const FORGE_RUNTIME = { __forge_fetch__: async () => ({}) };

test('actual Bitbucket merge-check payload parses by object, not string hunting', () => {
  const parsed = parseMergeCheckEvent({
    workspace: { uuid: '{workspace-uuid}' },
    repository: { uuid: '{repo-uuid}' },
    pullrequest: { id: 123 },
    trigger: { type: 'on-code-pushed' },
  });
  assert.deepEqual(parsed, {
    workspaceId: '{workspace-uuid}',
    repoId: '{repo-uuid}',
    pullRequestId: '123',
  });
});

test('merge-check messages are bounded and name the failed rules', () => {
  const clean = mergeCheckMessage(evaluateRules(CLEAN_STATE));
  assert.match(clean, /All 20 Elenchos rules passed/);
  const dirty = mergeCheckMessage(evaluateRules({}));
  assert.ok(dirty.length <= 240);
  assert.match(dirty, /r01/);
  const one = mergeCheckMessage(evaluateRules(violatingStateFor('r01')));
  assert.equal(one, 'Argus: 1 of 20 Elenchos rules failed (r01).');
});

test('resolver falls back to the same invoke protocol without @forge/resolver', async () => {
  const handler = makeResolverHandler({
    getValue: async (req) => ({ value: req.payload.value }),
  }, () => { throw new Error('missing'); });
  assert.deepEqual(
    await handler({ call: { functionKey: 'getValue', payload: { value: 7 } }, context: {} }),
    { value: 7 },
  );
  await assert.rejects(
    handler({ call: { functionKey: 'missing' }, payload: {} }),
    /unknown resolver function/,
  );
});

test('resolver uses new Resolver, define, and getDefinitions when the package exists', async () => {
  const defined = [];
  class FakeResolver {
    define(key, fn) { defined.push([key, fn]); return this; }
    getDefinitions() {
      return async (req) => defined.find(([key]) => key === req.call.functionKey)[1](req);
    }
  }
  const handler = makeResolverHandler(
    { ping: async () => 'pong' },
    () => FakeResolver,
    FORGE_RUNTIME,
  );
  assert.deepEqual(defined.map(([key]) => key), ['ping']);
  assert.equal(await handler({ call: { functionKey: 'ping' } }), 'pong');
});

test('forge plan store unwraps named, default, and plain KVS module shapes', async () => {
  const values = new Map();
  const kvs = {
    get: async (key) => values.get(key),
    set: async (key, value) => values.set(key, value),
    delete: async (key) => values.delete(key),
  };
  for (const shape of [{ kvs }, { default: { kvs } }, kvs]) {
    const store = makeForgePlanStore(() => shape, FORGE_RUNTIME);
    assert.ok(store);
    await store.set('x', { n: 1 });
    assert.deepEqual(await store.get('x'), { n: 1 });
  }
  assert.equal(makeForgePlanStore(() => { throw new Error('missing'); }, FORGE_RUNTIME), null);
});

test('installed Forge packages without a Forge runtime use local fallbacks', async () => {
  class FakeResolver {
    define() { return this; }
    getDefinitions() { throw new Error('real resolver must not be used'); }
  }
  const handler = makeResolverHandler(
    { ping: async () => 'pong' },
    () => FakeResolver,
    {},
  );
  assert.equal(await handler({ call: { functionKey: 'ping', payload: {} }, context: {} }), 'pong');
  const kvs = { get: async () => undefined, set: async () => {} };
  assert.equal(makeForgePlanStore(() => ({ kvs }), {}), null);
});
