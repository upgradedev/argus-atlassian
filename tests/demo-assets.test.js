'use strict';

// Forge Custom UI runs under a strict content security policy by default.
// Inline scripts and styles in the panel resource are blocked. These tests
// keep the generated page deployable in Forge as well as on GitHub Pages:
// assets are sibling files, no inline script/style, and all three output
// directories are byte-identical so they cannot drift.
// Run: node --test

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOTS = ['demo', 'docs', path.join('static', 'argus-ui', 'build')];
const FILES = ['index.html', 'app.css', 'app.js'];

function read(root, file) {
  return fs.readFileSync(path.join(__dirname, '..', root, file), 'utf8');
}

test('generated HTML has no inline script or style blocks', () => {
  for (const root of ROOTS) {
    const html = read(root, 'index.html');
    assert.doesNotMatch(html, /<style(?:\s|>)/i, root);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, root);
    assert.match(html, /<link rel="stylesheet" href="app\.css">/, root);
    assert.match(html, /<script src="app\.js" defer><\/script>/, root);
    assert.match(html, /aria-live="polite"/, root);
  }
});

test('generated outputs are identical in demo, docs, and the Forge resource', () => {
  for (const file of FILES) {
    const expected = read(ROOTS[0], file);
    for (const root of ROOTS.slice(1)) {
      assert.equal(read(root, file), expected, `${file} differs in ${root}`);
    }
  }
});

test('generated browser bundle parses and carries all twenty rule ids', () => {
  const js = read('demo', 'app.js');
  assert.doesNotThrow(() => new Function(js)); // parse only, never execute here
  for (let i = 1; i <= 20; i += 1) {
    assert.ok(js.includes(`r${String(i).padStart(2, '0')}`));
  }
});
