'use strict';

// Forge UI resolver construction. In a Forge runtime this is the real
// @forge/resolver Resolver, because bridge invoke requires functions
// registered through define() and exposed with getDefinitions().
// Outside Forge, the fallback implements the same call.functionKey
// dispatch so unit tests exercise the protocol instead of a bare lambda.

function defaultLoader() {
  // eslint-disable-next-line global-require
  return require('@forge/resolver');
}

function unwrapResolver(moduleValue) {
  const candidates = [
    moduleValue?.default,
    moduleValue?.Resolver,
    moduleValue,
  ];
  return candidates.find((candidate) => typeof candidate === 'function') ?? null;
}

function makeResolverHandler(definitions, loader = defaultLoader) {
  let ResolverClass = null;
  try {
    ResolverClass = unwrapResolver(loader());
  } catch {
    ResolverClass = null;
  }

  if (ResolverClass) {
    const resolver = new ResolverClass();
    for (const [key, fn] of Object.entries(definitions)) resolver.define(key, fn);
    return resolver.getDefinitions();
  }

  return async function fallbackResolver(req) {
    const key = req?.call?.functionKey ?? 'getArgusStatus';
    const fn = definitions[key];
    if (!fn) throw new Error(`unknown resolver function ${key}`);
    // Match the real package boundary: bridge invoke arrives as
    // call.payload, while definition callbacks receive payload/context.
    return fn({
      payload: req?.call?.payload ?? req?.payload ?? {},
      context: req?.context ?? {},
    });
  };
}

module.exports = { makeResolverHandler };
