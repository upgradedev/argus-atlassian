'use strict';

// Builds the Argus demo page used in three places, each as
// index.html + app.css + app.js (Forge Custom UI CSP blocks inline code):
//   demo/                  (canonical generated demo)
//   docs/                  (GitHub Pages judge mirror)
//   static/argus-ui/build/ (Forge Custom UI resource)
// The page bundles the REAL domain modules (errors, digest, canary,
// change_ir, provenance, receipts, standby, ports, pipeline_facts,
// rules, pipeline_repair) with a tiny CommonJS + SHA-256 shim, so the
// browser runs the exact same code the Node tests prove. There is no
// second implementation to drift. Regenerate after any domain change:
//
//   node scripts/build_demo.js
//
// The outputs are generated files. Edit this script or the domain,
// never the outputs by hand.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const DOMAIN_FILES = [
  'errors.js',
  'digest.js',
  'canary.js',
  'change_ir.js',
  'evidence.js',
  'provenance.js',
  'receipts.js',
  'standby.js',
  'policy_shield.js',
  'ports.js',
  'pipeline_facts.js',
  'rules.js',
  'pipeline_repair.js',
];

const CRYPTO_SHIM = `
__register('crypto', function (module, exports) {
  function sha256Hex(text) {
    const bytes = new TextEncoder().encode(String(text));
    const K = [
      0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
      0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
      0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
      0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
      0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
      0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
      0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
      0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    ];
    let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
    let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
    const bitLen = bytes.length * 8;
    const padLen = (((bytes.length + 8) >> 6) + 1) << 6;
    const buf = new Uint8Array(padLen);
    buf.set(bytes);
    buf[bytes.length] = 0x80;
    const view = new DataView(buf.buffer);
    view.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    view.setUint32(padLen - 4, bitLen >>> 0, false);
    const W = new Uint32Array(64);
    const rotr = function (x, n) { return (x >>> n) | (x << (32 - n)); };
    for (let off = 0; off < padLen; off += 64) {
      for (let i = 0; i < 16; i += 1) W[i] = view.getUint32(off + i * 4, false);
      for (let i = 16; i < 64; i += 1) {
        const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
        const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
      }
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
      for (let i = 0; i < 64; i += 1) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0;
        d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + h) >>> 0;
    }
    return [h0, h1, h2, h3, h4, h5, h6, h7].map(function (x) {
      return x.toString(16).padStart(8, '0');
    }).join('');
  }
  exports.createHash = function () {
    let acc = '';
    return {
      update: function (chunk) { acc += String(chunk); return this; },
      digest: function () { return sha256Hex(acc); }
    };
  };
});
`.trim();

function bundle() {
  const parts = [
    'const __modules = {}; const __cache = {};',
    'function __register(name, fn) { __modules[name] = fn; }',
    'function __require(name) {',
    '  const key = name.replace(/^node:/, "").split("/").pop();',
    '  if (__cache[key]) return __cache[key].exports;',
    '  const module = { exports: {} }; __cache[key] = module;',
    '  __modules[key](module, module.exports, __require);',
    '  return module.exports;',
    '}',
    CRYPTO_SHIM,
  ];
  for (const file of DOMAIN_FILES) {
    const source = fs.readFileSync(path.join(ROOT, 'src/argus/domain', file), 'utf8');
    parts.push(`__register('${file}', function (module, exports, require) {\n${source}\n});`);
  }
  parts.push("const ArgusRules = __require('./rules.js');");
  parts.push("const ArgusFacts = __require('./pipeline_facts.js');");
  parts.push("const ArgusRepair = __require('./pipeline_repair.js');");
  parts.push("const ArgusChange = __require('./change_ir.js');");
  parts.push("const ArgusEvidence = __require('./evidence.js');");
  parts.push("const ArgusProvenance = __require('./provenance.js');");
  parts.push("const ArgusReceipts = __require('./receipts.js');");
  parts.push("const ArgusStandby = __require('./standby.js');");
  parts.push("const ArgusShield = __require('./policy_shield.js');");
  parts.push("const ArgusPorts = __require('./ports.js');");
  return parts.join('\n');
}

const SAMPLE_YAML = [
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

const CSS = `
:root { color-scheme: light; }
* { box-sizing: border-box; }
body { margin: 0; background: #ffffff; color: #172b4d;
  font-family: -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.45; }
.skip { position: absolute; left: -9999px; top: 0; background: #0052cc; color: #fff; padding: 8px 12px; }
.skip:focus { left: 8px; top: 8px; }
main { max-width: 920px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 28px; line-height: 1.15; margin: 0 0 8px; letter-spacing: 0; }
h2 { font-size: 20px; line-height: 1.25; margin: 28px 0 8px; }
.lead { font-size: 16px; max-width: 62ch; margin: 0 0 6px; }
.status { font-size: 13px; color: #42526e; margin: 0 0 20px; }
label { font-weight: 600; display: block; margin: 16px 0 6px; }
textarea, input[type="text"], select { width: 100%; padding: 9px 10px; border: 1px solid #7a869a;
  border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px; background: #ffffff; color: #172b4d; }
textarea { min-height: 220px; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 10px; }
button { background: #0052cc; color: #fff; border: 0; border-radius: 4px;
  padding: 10px 16px; font-size: 15px; font-weight: 600; cursor: pointer; }
button.secondary { background: #ffffff; color: #0052cc; border: 1px solid #0052cc; }
button:focus-visible, textarea:focus-visible, input:focus-visible, select:focus-visible {
  outline: 3px solid #4c9aff; outline-offset: 2px;
}
.repair { font-size: 14px; margin: 8px 0 0; }
.summary { margin: 22px 0 10px; font-size: 17px; font-weight: 700; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border: 1px solid #dfe1e6; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #f4f5f7; }
.pass { color: #006644; font-weight: 700; }
.fail { color: #bf2600; font-weight: 700; }
.card { border: 1px solid #dfe1e6; border-radius: 4px; padding: 14px; margin: 14px 0; background: #fafbfc; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px; overflow-wrap: anywhere; word-break: break-word; }
.braille { font-size: 18px; line-height: 1.5; overflow-wrap: anywhere; word-break: break-word; }
dl { margin: 8px 0; }
dt { font-weight: 700; margin-top: 8px; }
dd { margin: 2px 0 0 0; overflow-wrap: anywhere; }
.note { font-size: 13px; color: #42526e; max-width: 68ch; }
@media (prefers-reduced-motion: reduce) { * { transition: none; animation: none; } }
`;

const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" role="img" aria-labelledby="title">
<title id="title">Argus watchful eye</title>
<path fill="#0052cc" d="M12 3C6.9 3 2.7 6.5 1.1 11c-.2.6-.2 1.4 0 2C2.7 17.5 6.9 21 12 21s9.3-3.5 10.9-8c.2-.6.2-1.4 0-2C21.3 6.5 17.1 3 12 3Z"/>
<circle cx="12" cy="12" r="5.2" fill="#ffffff"/>
<circle cx="12" cy="12" r="3" fill="#006644"/>
<circle cx="6.4" cy="7.6" r="1" fill="#ffffff"/>
<circle cx="17.6" cy="7.6" r="1" fill="#ffffff"/>
</svg>
`;

const UI_JS = `
(function () {
  const sampleYaml = ${JSON.stringify(SAMPLE_YAML)};
  const input = document.getElementById('yaml');
  const summary = document.getElementById('summary');
  const tbody = document.getElementById('rows');
  const form = document.getElementById('run');
  const repair = document.getElementById('repair');
  const seedReset = document.getElementById('seed-reset');
  const repairSummary = document.getElementById('repair-summary');
  const ruleSelect = document.getElementById('rule-select');
  const digestInput = document.getElementById('approval-digest');
  const syncDigestBtn = document.getElementById('sync-digest');
  const elapsedSelect = document.getElementById('elapsed-seconds');
  const governForm = document.getElementById('govern-form');
  const governStatus = document.getElementById('govern-status');
  const standbyVerdict = document.getElementById('standby-verdict');
  const receiptSpoken = document.getElementById('receipt-spoken');
  const receiptBraille = document.getElementById('receipt-braille');
  const receiptPlain = document.getElementById('receipt-plain');
  const runtimeStatus = document.getElementById('runtime-status');
  const evidenceSummary = document.getElementById('evidence-summary');
  const shieldSummary = document.getElementById('shield-summary');
  const shield = new ArgusShield.PolicyShield();

  const thread = new ArgusProvenance.ProvenanceThread();
  thread.add(new ArgusProvenance.ProvenanceNode(
    'commit-9f2c41e', 'commit', 'Mask npm test exit code in bitbucket-pipelines.yml',
    'dev-alex', '2026-11-05T03:20:00Z'
  ));
  thread.add(new ArgusProvenance.ProvenanceNode(
    'deploy-prod-482', 'deploy', 'Bitbucket Pipeline #482 reported green',
    'bitbucket-pipelines', '2026-11-05T03:25:00Z', 'commit-9f2c41e'
  ));
  thread.add(new ArgusProvenance.ProvenanceNode(
    'DEMO-11', 'incident', 'JSM P1 checkout outage after green release',
    'jsm-trigger', '2026-11-05T03:32:24Z', 'deploy-prod-482'
  ));
  document.getElementById('prov-chain').textContent =
    thread.walkBack('DEMO-11').map(function (n) { return n.nodeId + ' (' + n.kind + ')'; }).join(' -> ');
  document.getElementById('prov-root').textContent = thread.rootCause('DEMO-11').nodeId;
  document.getElementById('prov-seal').textContent = thread.seal('DEMO-11');

  ArgusRules.RULES.forEach(function (rule) {
    const opt = document.createElement('option');
    opt.value = rule.id;
    opt.textContent = rule.id + ': ' + rule.title;
    ruleSelect.appendChild(opt);
  });

  let currentChange = null;
  function buildProposal(ruleId) {
    const rule = ArgusRules.ruleById(ruleId);
    const claimId = 'DEMO-11:' + rule.id;
    const graph = new ArgusEvidence.EvidenceGraph();
    [
      ['DEMO-11-data', ArgusEvidence.EvidenceSource.DATA, 'JSM P1 incident DEMO-11'],
      ['DEMO-11-identity', ArgusEvidence.EvidenceSource.IDENTITY, 'On-call SRE roster'],
      ['DEMO-11-events', ArgusEvidence.EvidenceSource.EVENTS, 'Issue webhook trigger'],
      ['DEMO-11-pipeline', ArgusEvidence.EvidenceSource.PIPELINE, 'Bitbucket Pipelines YAML'],
      ['DEMO-11-config', ArgusEvidence.EvidenceSource.CONFIG, 'Branch restriction policy'],
      ['DEMO-11-logs', ArgusEvidence.EvidenceSource.LOGS, 'Socratic Canary exit log'],
      ['DEMO-11-edge', ArgusEvidence.EvidenceSource.EDGE, 'Zero-egress boundary'],
    ].forEach(function (entry) {
      graph.add(new ArgusEvidence.EvidenceItem(entry[0], entry[1], entry[2], {
        platformLabel: 'Atlassian Forge', supports: [claimId]
      }));
    });
    const grounded = graph.isGrounded([claimId]);
    evidenceSummary.textContent =
      graph.sourcesPresent().size + '/7 sources present (complete: '
      + (graph.isComplete() ? 'yes' : 'no') + ', grounded claim: ' + claimId + ').';

    const call = new ArgusShield.ToolCall(
      'escalate-standby-responder',
      rule.id,
      ArgusShield.RiskClass.DESTRUCTIVE_WRITE,
      grounded
    );
    const triage = shield.triage(call);
    shield.evaluate(call);
    shieldSummary.textContent =
      'Lachesis triage: ' + triage + ' (risk: ' + call.risk + ', grounded: '
      + (grounded ? 'yes' : 'no') + '). Threefold shield mode: ' + shield.mode(rule.id) + '.';

    const ops = ArgusRules.repairFactsForRule(rule.id).map(function (fact) {
      return new ArgusChange.ChangeOp(
        ArgusChange.OpKind.SET_CONFIG,
        'bitbucket-pipelines.yml',
        fact.field,
        fact.value
      );
    });
    currentChange = new ArgusChange.TypedChangeIR(
      'proposal-DEMO-11-' + rule.id + '-1',
      'Repair proposal for ' + rule.id + ': ' + rule.title,
      ops,
      { evidenceClaims: [claimId], preventionRule: rule.id }
    );
    const d = currentChange.digest();
    document.getElementById('change-id').textContent = currentChange.changeId;
    document.getElementById('change-digest').textContent = d;
    document.getElementById('lens-director').textContent = currentChange.renderForRole('director');
    document.getElementById('lens-secops').textContent = currentChange.renderForRole('secops');
    document.getElementById('lens-standby').textContent = currentChange.renderForRole('standby');
    digestInput.value = d;
  }

  function executeGovernance() {
    if (!currentChange) buildProposal(ruleSelect.value || 'r01');
    const suppliedDigest = digestInput.value.trim();
    try {
      ArgusPorts.verifyBeforeWrite(currentChange, suppliedDigest);
    } catch (err) {
      governStatus.className = 'summary fail';
      governStatus.textContent =
        'Write blocked by digest guard: the entered SHA-256 digest does not match the stored Typed Change IR ('
        + err.message + '). Press Sync digest from proposal to restore the exact 64-character hex digest.';
      standbyVerdict.textContent = 'No JSM assignment executed because digest verification failed closed.';
      receiptSpoken.textContent = 'No approval receipt issued.';
      receiptBraille.textContent = '';
      receiptPlain.textContent = '';
      return;
    }
    const roster = new ArgusStandby.StandbyRoster([
      new ArgusStandby.Engineer('acc-dimitris', 'Dimitris Lagos (Primary SRE)'),
      new ArgusStandby.Engineer('acc-eleni', 'Eleni Papadopoulou (Standby SRE)')
    ]);
    const elapsed = Number(elapsedSelect.value || 0);
    const pageOutcome = roster.whoToPage(elapsed);
    const receipt = ArgusReceipts.buildReceipt(
      currentChange.digest(),
      'dimitris.lagos',
      'approved',
      '2026-11-05T11:30:00Z'
    );
    governStatus.className = 'summary pass';
    governStatus.textContent =
      'Digest verified against ' + currentChange.changeId + '. Merkle receipt sealed.';
    standbyVerdict.textContent =
      'Paged responder: ' + pageOutcome.paged.name + ' [' + pageOutcome.paged.engineerId + ']. '
      + 'Escalated: ' + (pageOutcome.escalated ? 'yes' : 'no') + ' (' + pageOutcome.reason + ').';
    receiptSpoken.textContent = receipt.spokenText();
    receiptBraille.textContent = receipt.brailleText();
    receiptPlain.textContent = receipt.plainText();
  }

  function render() {
    if (!input.value.trim()) {
      repairSummary.textContent =
        'The pipeline editor is empty. Paste a bitbucket-pipelines.yml file or press Reset to sample P1 incident (DEMO-11).';
    }
    const facts = ArgusFacts.extractPipelineFacts(input.value);
    const out = ArgusRules.evaluateRules(facts);
    const passing = out.results.filter(function (r) { return r.clean; }).length;
    summary.textContent = out.clean
      ? 'Verdict: exit 0. All 20 Elenchos rules pass on these facts.'
      : 'Verdict: exit 1. ' + out.violations.length + ' of 20 Elenchos rules fail: '
        + out.violations.join(', ') + '.';
    tbody.innerHTML = '';
    out.results.forEach(function (r) {
      const tr = document.createElement('tr');
      const id = document.createElement('td'); id.textContent = r.id;
      const title = document.createElement('td'); title.textContent = r.title;
      const state = document.createElement('td');
      state.textContent = r.clean ? 'PASS' : 'FAIL';
      state.className = r.clean ? 'pass' : 'fail';
      tr.append(id, title, state);
      tbody.appendChild(tr);
    });
    document.getElementById('passing').textContent = passing + '/20 rules passing';
  }

  form.addEventListener('submit', function (e) { e.preventDefault(); render(); });
  repair.addEventListener('click', function () {
    if (!input.value.trim()) {
      repairSummary.textContent =
        'The pipeline editor is empty. Press Reset to sample P1 incident (DEMO-11) before applying repairs.';
      return;
    }
    const result = ArgusRepair.repairPipelineYaml(input.value);
    input.value = result.yaml;
    repairSummary.textContent = result.applied.length
      ? 'Applied and re-verified: ' + result.applied.join(', ') + '. '
        + 'Still needs a human decision: ' + (result.unsupported.join(', ') || 'none') + '.'
      : 'No safe deterministic repair applies. Still needs a human decision: '
        + (result.unsupported.join(', ') || 'none') + '.';
    render();
  });
  seedReset.addEventListener('click', function () {
    input.value = sampleYaml;
    repairSummary.textContent = 'Loaded synthetic JSM P1 incident DEMO-11 and fake-green Bitbucket pipeline.';
    ruleSelect.value = 'r01';
    buildProposal('r01');
    executeGovernance();
    render();
  });
  ruleSelect.addEventListener('change', function () {
    buildProposal(ruleSelect.value);
    executeGovernance();
  });
  syncDigestBtn.addEventListener('click', function () {
    if (currentChange) digestInput.value = currentChange.digest();
    executeGovernance();
  });
  elapsedSelect.addEventListener('change', executeGovernance);
  governForm.addEventListener('submit', function (e) {
    e.preventDefault();
    executeGovernance();
  });
  input.addEventListener('input', render);

  buildProposal('r01');
  executeGovernance();
  render();

  if (typeof globalThis.__argusBridgeInvoke === 'function') {
    Promise.resolve(globalThis.__argusBridgeInvoke('getArgusStatus', {}))
      .then(function (res) {
        if (res && runtimeStatus) {
          runtimeStatus.textContent =
            'Status: connected to Forge resolver (' + (res.status || 'ready')
            + ', storage: ' + (res.planStorage || 'forge-kvs')
            + ', rules accepted: ' + (res.rulesAccepted || '20/20') + ').';
        }
      })
      .catch(function () {});
  }
})();
`;

function escapeHtml(text) {
  return text.replaceAll('&', '&amp;').replaceAll('<', '&lt;');
}

function page() {
  return `<!DOCTYPE html>
<!-- Generated by scripts/build_demo.js. Do not edit by hand. -->
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus Socratic Canary: is your green pipeline real?</title>
<link rel="icon" href="argus-icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="app.css">
</head>
<body>
<a class="skip" href="#main">Skip to the demo</a>
<main id="main" role="main" aria-label="Argus Socratic Canary demo">
  <h1>Is your green pipeline real?</h1>
  <p class="lead">Argus links JSM incidents to linked Bitbucket work, fires a synthetic
  canary to expose fake-green gates, and returns a re-verified repair patch. This page runs
  the same twenty Elenchos rules as the Forge app, in your browser, on text you control.</p>
  <p id="runtime-status" class="status" role="status" aria-live="polite">Status: demo build. It evaluates the Bitbucket Pipelines YAML below
  directly in your browser. It does not connect to your Atlassian site and sends nothing anywhere.</p>
  <form id="run">
    <label for="yaml">bitbucket-pipelines.yml (edit it, the verdict updates as you type)</label>
    <textarea id="yaml" name="yaml" spellcheck="false">${escapeHtml(SAMPLE_YAML)}</textarea>
    <div class="actions">
      <button type="submit">Run the kill-test</button>
      <button id="repair" class="secondary" type="button">Apply safe deterministic repairs</button>
      <button id="seed-reset" class="secondary" type="button">Reset to sample P1 incident (DEMO-11)</button>
    </div>
  </form>
  <p id="repair-summary" class="repair" role="status" aria-live="polite"></p>
  <p id="summary" class="summary" role="status" aria-live="polite"></p>
  <p id="passing"></p>
  <table aria-label="Elenchos rule results">
    <thead><tr><th scope="col">Rule</th><th scope="col">Checks</th><th scope="col">Result</th></tr></thead>
    <tbody id="rows"></tbody>
  </table>
  <p class="note">Exit 1 means at least one rule failed on these facts. Exit 0 means all
  twenty passed on the facts the extractor could see. One fact, required merge check
  enforcement (r13), lives in Bitbucket branch restrictions, not in this file, so here
  it stays flagged until the app reads it from the API. Each rule earned its id by
  separating a violating fixture (exit 1) from a clean one (exit 0) in the Socratic
  Kill-Test. A check that cannot separate the two is thrown out before a human sees it.</p>

  <section aria-labelledby="gov-heading">
    <h2 id="gov-heading">Incident provenance, Typed Change IR, and Merkle approval receipt</h2>
    <div class="card" aria-label="Provenance thread for incident DEMO-11">
      <dl>
        <dt>Provenance walk (JSM incident back to commit)</dt>
        <dd id="prov-chain" class="mono"></dd>
        <dt>Root cause node</dt>
        <dd id="prov-root" class="mono"></dd>
        <dt>SHA-256 provenance seal</dt>
        <dd id="prov-seal" class="mono"></dd>
        <dt>SupportTrace 7-source evidence graph</dt>
        <dd id="evidence-summary"></dd>
        <dt>Threefold and Lachesis pre-tool policy shield</dt>
        <dd id="shield-summary"></dd>
      </dl>
    </div>

    <form id="govern-form">
      <label for="rule-select">Select Elenchos rule for Typed Change IR proposal</label>
      <select id="rule-select" name="ruleId"></select>

      <div class="card" aria-label="Typed Change IR role lenses">
        <dl>
          <dt>Proposal ID</dt>
          <dd id="change-id" class="mono"></dd>
          <dt>Content-addressed SHA-256 digest</dt>
          <dd id="change-digest" class="mono"></dd>
          <dt>Engineering Director / CISO lens</dt>
          <dd id="lens-director"></dd>
          <dt>SecOps / SRE Lead lens</dt>
          <dd id="lens-secops"></dd>
          <dt>JSM Standby On-Call Engineer lens</dt>
          <dd id="lens-standby"></dd>
        </dl>
      </div>

      <label for="approval-digest">Approval SHA-256 digest (edit a character to test fail-closed digest verification)</label>
      <input id="approval-digest" name="approvalDigest" type="text" spellcheck="false">

      <label for="elapsed-seconds">JSM on-call elapsed time (900-second SLA window)</label>
      <select id="elapsed-seconds" name="elapsedSeconds">
        <option value="0">0 seconds: Primary SRE Dimitris Lagos inside 900s SLA window</option>
        <option value="960">960 seconds: SLA missed, automatic failover to Standby SRE Eleni Papadopoulou</option>
      </select>

      <div class="actions">
        <button id="approve-btn" type="submit">Verify digest, page responder, and seal receipt</button>
        <button id="sync-digest" class="secondary" type="button">Sync digest from proposal</button>
      </div>
    </form>

    <p id="govern-status" class="summary" role="status" aria-live="polite"></p>
    <div class="card" aria-label="Standby failover and Merkle-sealed receipt">
      <dl>
        <dt>JSM Standby On-Call failover verdict</dt>
        <dd id="standby-verdict" role="status" aria-live="polite"></dd>
        <dt>Spoken approval receipt (screen reader and voice)</dt>
        <dd id="receipt-spoken" role="status" aria-live="polite"></dd>
        <dt>Grade-1 Braille approval receipt</dt>
        <dd id="receipt-braille" class="braille" aria-label="Grade 1 Braille receipt"></dd>
        <dt>Plain receipt and Merkle root</dt>
        <dd id="receipt-plain" class="mono"></dd>
      </dl>
    </div>
  </section>
</main>
<script src="app.js" defer></script>
</body>
</html>
`;
}

const outputDirs = [
  path.join(ROOT, 'demo'),
  path.join(ROOT, 'docs'),
  path.join(ROOT, 'static', 'argus-ui', 'build'),
];
const files = {
  'argus-icon.svg': ICON_SVG,
  'index.html': page(),
  'app.css': `/* Generated by scripts/build_demo.js. Do not edit by hand. */\n${CSS.trim()}\n`,
  'app.js': `'use strict';\n/* Generated by scripts/build_demo.js. Do not edit by hand. */\n${bundle()}\n${UI_JS.trim()}\n`,
};
for (const dir of outputDirs) {
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, content] of Object.entries(files)) {
    const out = path.join(dir, name);
    fs.writeFileSync(out, content, 'utf8');
    process.stdout.write(`wrote ${path.relative(ROOT, out)} (${content.length} chars)\n`);
  }
}
