'use strict';

// Canonical JSON + SHA-256, byte-identical to the Python core.
// Python: json.dumps(payload, sort_keys=True, separators=(",", ":"))
// with ensure_ascii at its default (True), then hashlib.sha256 of UTF-8.
// node:crypto is the Node standard library, not a vendor SDK (AGENTS.md A5).
// tests/argus-core.test.js pins Python-produced digests so any drift fails.

const { createHash } = require('node:crypto');

function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value !== null && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = sortDeep(value[key]);
    return out;
  }
  return value;
}

function canonicalStringify(value) {
  const json = JSON.stringify(sortDeep(value));
  // Match Python ensure_ascii: escape every non-ASCII code unit as XXXX.
  let out = '';
  for (let i = 0; i < json.length; i += 1) {
    const code = json.charCodeAt(i);
    out += code < 0x80 ? json[i] : `\\u${code.toString(16).padStart(4, '0')}`;
  }
  return out;
}

function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function digestPayload(payload) {
  return sha256Hex(canonicalStringify(payload));
}

module.exports = { canonicalStringify, sha256Hex, digestPayload };
