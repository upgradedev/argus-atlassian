'use strict';

// Plan persistence behind one tiny async key-value interface.
// In the Forge runtime this is backed by @forge/kvs and the manifest
// storage:app scope. An installed @forge/kvs package outside that
// runtime (CI after npm ci) is not storage: its calls need the Forge
// runtime global. In tests and outside Forge it is an in-memory Map.
// The distinction matters and callers report it: memory persistence only
// lasts for this process and is never called durable.

function defaultLoader() {
  // eslint-disable-next-line global-require
  return require('@forge/kvs');
}

function unwrapKvs(moduleValue) {
  const candidates = [
    moduleValue?.kvs,
    moduleValue?.default?.kvs,
    moduleValue?.default,
    moduleValue,
  ];
  return candidates.find((candidate) => (
    candidate
    && typeof candidate.get === 'function'
    && typeof candidate.set === 'function'
  )) ?? null;
}

function makeForgePlanStore(loader = defaultLoader, runtimeGlobal = globalThis) {
  if (typeof runtimeGlobal?.__forge_fetch__ !== 'function') return null;
  let loaded;
  try {
    loaded = loader();
  } catch {
    return null;
  }
  const kvs = unwrapKvs(loaded);
  if (!kvs) return null;
  return Object.freeze({
    mode: 'forge-kvs',
    async get(key) {
      const value = await kvs.get(key);
      return value === null ? undefined : value;
    },
    async set(key, value) {
      await kvs.set(key, value);
    },
    async delete(key) {
      if (typeof kvs.delete === 'function') await kvs.delete(key);
    },
  });
}

class InMemoryPlanStore {
  constructor() {
    // Clone through JSON so tests cannot mutate stored envelopes by
    // reference, which would hide bugs the real KVS boundary exposes.
    this.mode = 'memory-ephemeral';
    this.values = new Map();
  }

  async get(key) {
    const value = this.values.get(key);
    return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
  }

  async set(key, value) {
    this.values.set(key, JSON.parse(JSON.stringify(value)));
  }

  async delete(key) {
    this.values.delete(key);
  }
}

module.exports = { makeForgePlanStore, InMemoryPlanStore };
