'use strict';

// STANDARDS.md A5 + STATE.md section 6 rule 1: the pure domain imports no
// Forge, Atlassian, cloud, or LLM SDK. The one allowed platform import is
// node:crypto (Node standard library). The detector is proven against
// violating and clean samples inside this file, like the Python gate.
//
// Run: node --test tests/

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const BANNED = ['@forge/', '@atlassian/', 'boto3', 'aws-sdk', 'strands', 'openai', 'anthropic'];
const REQUIRE_RE = /require\(\s*'([^']+)'\s*\)/g;

function bannedImportsIn(source) {
  const hits = [];
  for (const match of source.matchAll(REQUIRE_RE)) {
    const spec = match[1];
    if (spec.startsWith('.') || spec.startsWith('node:')) continue;
    hits.push(spec);
  }
  for (const word of BANNED) {
    if (source.includes(word) && !hits.includes(word)) hits.push(word);
  }
  return hits;
}

function jsFilesUnder(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...jsFilesUnder(full));
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

test('detector flags violating imports and passes clean ones', () => {
  assert.deepEqual(bannedImportsIn("const api = require('@forge/api');"), ['@forge/api', '@forge/']);
  assert.deepEqual(bannedImportsIn("const c = require('node:crypto');"), []);
  assert.deepEqual(bannedImportsIn("const e = require('./errors.js');"), []);
});

test('src/argus tree imports no banned SDK', () => {
  const root = path.join(__dirname, '..', 'src', 'argus');
  const files = jsFilesUnder(root);
  assert.ok(files.length >= 10, `expected the ported tree, found ${files.length} js files`);
  for (const file of files) {
    const hits = bannedImportsIn(fs.readFileSync(file, 'utf8'));
    assert.deepEqual(hits, [], `${path.relative(root, file)} imports ${hits.join(', ')}`);
  }
});
