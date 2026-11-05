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
const vm = require('node:vm');

const {
  ChangeOp,
  OpKind,
  ProvenanceNode,
  ProvenanceThread,
  TypedChangeIR,
  buildReceipt,
  repairFactsForRule,
  ruleById,
} = require('../src/argus/index.js');

const ROOTS = ['demo', 'docs', path.join('static', 'argus-ui', 'build')];
const FILES = ['index.html', 'app.css', 'app.js', 'argus-icon.svg'];

function read(root, file) {
  return fs.readFileSync(path.join(__dirname, '..', root, file), 'utf8');
}

test('generated HTML has no inline script or style blocks', () => {
  for (const root of ROOTS) {
    const html = read(root, 'index.html');
    assert.doesNotMatch(html, /<style(?:\s|>)/i, root);
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, root);
    assert.match(html, /<link rel="icon" href="argus-icon\.svg"/, root);
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

test('browser bundle executes end-to-end with byte-identical SHA-256 digests, standby failover, and Braille receipt', () => {
  const js = read('demo', 'app.js');
  const elements = new Map();
  function makeEl(id = '') {
    const listeners = new Map();
    const children = [];
    let htmlVal = '';
    return {
      id,
      value: '',
      textContent: '',
      get innerHTML() { return htmlVal; },
      set innerHTML(v) { htmlVal = v; if (!v) children.length = 0; },
      className: '',
      children,
      append(...nodes) { children.push(...nodes); },
      appendChild(node) {
        children.push(node);
        if (!this.value && node.value) this.value = node.value;
      },
      addEventListener(type, fn) { listeners.set(type, fn); },
      dispatch(type) {
        const fn = listeners.get(type);
        if (fn) fn({ preventDefault() {} });
      },
    };
  }
  const ids = [
    'yaml', 'summary', 'rows', 'run', 'repair', 'seed-reset', 'repair-summary',
    'passing', 'rule-select', 'approval-digest', 'sync-digest', 'elapsed-seconds',
    'govern-form', 'govern-status', 'standby-verdict', 'receipt-spoken',
    'receipt-braille', 'receipt-plain', 'prov-chain', 'prov-root', 'prov-seal',
    'change-id', 'change-digest', 'lens-director', 'lens-secops', 'lens-standby',
    'runtime-status', 'evidence-summary', 'shield-summary',
  ];
  for (const id of ids) elements.set(id, makeEl(id));
  elements.get('yaml').value = [
    'image: node:latest',
    'pipelines:',
    '  default:',
    '    - step:',
    '        name: Ship it',
    '        script:',
    '          - npm install',
    '          - npm test -- --passWithNoTests || true',
    '          - echo green || exit 0',
    '    - step:',
    '        deployment: production',
    '        script:',
    '          - ./deploy-prod.sh',
  ].join('\n');
  elements.get('elapsed-seconds').value = '0';

  const document = {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, makeEl(id));
      return elements.get(id);
    },
    createElement(tag) { return makeEl(tag); },
  };
  let bridgeCalled = false;
  vm.runInNewContext(js, {
    document,
    TextEncoder,
    Uint8Array,
    Uint32Array,
    DataView,
    __argusBridgeInvoke(key) {
      bridgeCalled = key === 'getArgusStatus';
      return { status: 'live-ready', planStorage: 'forge-kvs', rulesAccepted: '20/20' };
    },
  });

  // 0. Verify EvidenceGraph and PolicyShield are rendered and bridge hook is called
  assert.equal(bridgeCalled, true);
  assert.match(elements.get('evidence-summary').textContent, /7\/7 sources present \(complete: yes/);
  assert.match(elements.get('shield-summary').textContent, /Lachesis triage: confirm \(risk: destructive_write/);

  // 1. Verify SHA-256 provenance seal matches Node crypto byte-for-byte
  const nodeThread = new ProvenanceThread();
  nodeThread.add(new ProvenanceNode(
    'commit-9f2c41e', 'commit', 'Mask npm test exit code in bitbucket-pipelines.yml',
    'dev-alex', '2026-11-05T03:20:00Z',
  ));
  nodeThread.add(new ProvenanceNode(
    'deploy-prod-482', 'deploy', 'Bitbucket Pipeline #482 reported green',
    'bitbucket-pipelines', '2026-11-05T03:25:00Z', 'commit-9f2c41e',
  ));
  nodeThread.add(new ProvenanceNode(
    'DEMO-11', 'incident', 'JSM P1 checkout outage after green release',
    'jsm-trigger', '2026-11-05T03:32:24Z', 'deploy-prod-482',
  ));
  assert.equal(elements.get('prov-seal').textContent, nodeThread.seal('DEMO-11'));

  // 2. Verify Typed Change IR digest & Merkle receipt match Node crypto byte-for-byte
  const r01 = ruleById('r01');
  const nodeChange = new TypedChangeIR(
    'proposal-DEMO-11-r01-1',
    `Repair proposal for ${r01.id}: ${r01.title}`,
    repairFactsForRule('r01').map(
      (f) => new ChangeOp(OpKind.SET_CONFIG, 'bitbucket-pipelines.yml', f.field, f.value),
    ),
    { evidenceClaims: ['DEMO-11:r01'], preventionRule: 'r01' },
  );
  assert.equal(elements.get('change-digest').textContent, nodeChange.digest());
  const nodeReceipt = buildReceipt(nodeChange.digest(), 'dimitris.lagos', 'approved', '2026-11-05T11:30:00Z');
  assert.equal(elements.get('receipt-spoken').textContent, nodeReceipt.spokenText());
  assert.equal(elements.get('receipt-braille').textContent, nodeReceipt.brailleText());
  assert.equal(elements.get('receipt-plain').textContent, nodeReceipt.plainText());

  // 3. Verify fail-closed digest tamper detection and recovery
  elements.get('approval-digest').value = '0'.repeat(64);
  elements.get('govern-form').dispatch('submit');
  assert.match(elements.get('govern-status').textContent, /Write blocked by digest guard/);
  assert.equal(elements.get('receipt-braille').textContent, '');
  elements.get('sync-digest').dispatch('click');
  assert.match(elements.get('govern-status').textContent, /Digest verified/);

  // 4. Verify Standby On-Call failover after 900s SLA window
  elements.get('elapsed-seconds').value = '960';
  elements.get('elapsed-seconds').dispatch('change');
  assert.match(elements.get('standby-verdict').textContent, /Eleni Papadopoulou/);
  assert.match(elements.get('standby-verdict').textContent, /Escalated: yes/);

  // 5. Verify deterministic YAML repair, KPI scalars, stage breakdown, diff preview, and empty input guidance (Persona 06 K3)
  assert.equal(elements.get('passing').textContent, '7/20 rules passing');
  assert.equal(elements.get('kpi-gate-rate').textContent, '35%');
  assert.equal(elements.get('kpi-open-findings').textContent, '13 Failing');
  assert.match(elements.get('yaml-diff-preview').textContent, /--- a\/bitbucket-pipelines\.yml/);
  elements.get('repair').dispatch('click');
  assert.equal(elements.get('passing').textContent, '12/20 rules passing');
  assert.equal(elements.get('kpi-gate-rate').textContent, '60%');
  assert.equal(elements.get('kpi-open-findings').textContent, '8 Failing');
  elements.get('tamper-digest').dispatch('click');
  assert.match(elements.get('govern-status').textContent, /Write blocked by digest guard/);
  elements.get('sync-digest').dispatch('click');
  assert.match(elements.get('govern-status').textContent, /Digest verified/);
  elements.get('filter-fail').dispatch('click');
  assert.equal(elements.get('rows').children.length, 8);
  elements.get('filter-all').dispatch('click');
  assert.equal(elements.get('rows').children.length, 20);
  elements.get('yaml').value = '   ';
  elements.get('repair').dispatch('click');
  assert.match(elements.get('repair-summary').textContent, /The pipeline editor is empty/);
  elements.get('seed-reset').dispatch('click');
  assert.equal(elements.get('passing').textContent, '7/20 rules passing');
});
