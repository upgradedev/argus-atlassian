'use strict';

// Builds the Argus demo page used in three places, each as
// index.html + app.css + app.js (Forge Custom UI CSP blocks inline code):
//   demo/                  (canonical generated demo)
//   docs/                  (GitHub Pages judge mirror)
//   static/argus-ui/build/ (Forge Custom UI resource)
// The page bundles the REAL domain modules (errors, canary, rules,
// pipeline_facts) with a tiny CommonJS shim, so the browser runs the
// same code the Node tests prove. There is no second implementation
// to drift. Regenerate after any domain change:
//
//   node scripts/build_demo.js
//
// The outputs are generated files. Edit this script or the domain,
// never the outputs by hand.

const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const DOMAIN_FILES = [
  'errors.js', 'canary.js', 'pipeline_facts.js', 'rules.js', 'pipeline_repair.js',
];

function bundle() {
  const parts = [
    'const __modules = {}; const __cache = {};',
    'function __register(name, fn) { __modules[name] = fn; }',
    'function __require(name) {',
    '  const key = name.split("/").pop();',
    '  if (__cache[key]) return __cache[key].exports;',
    '  const module = { exports: {} }; __cache[key] = module;',
    '  __modules[key](module, module.exports, __require);',
    '  return module.exports;',
    '}',
  ];
  for (const file of DOMAIN_FILES) {
    const source = fs.readFileSync(path.join(ROOT, 'src/argus/domain', file), 'utf8');
    parts.push(`__register('${file}', function (module, exports, require) {\n${source}\n});`);
  }
  parts.push("const ArgusRules = __require('./rules.js');");
  parts.push("const ArgusFacts = __require('./pipeline_facts.js');");
  parts.push("const ArgusRepair = __require('./pipeline_repair.js');");
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
.lead { font-size: 16px; max-width: 62ch; margin: 0 0 6px; }
.status { font-size: 13px; color: #42526e; margin: 0 0 20px; }
label { font-weight: 600; display: block; margin: 18px 0 6px; }
textarea { width: 100%; min-height: 240px; padding: 10px; border: 1px solid #7a869a;
  border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 13px; }
button { margin-top: 10px; background: #0052cc; color: #fff; border: 0; border-radius: 4px;
  padding: 10px 16px; font-size: 15px; font-weight: 600; cursor: pointer; }
button.secondary { background: #ffffff; color: #0052cc; border: 1px solid #0052cc; margin-left: 8px; }
button:focus-visible, textarea:focus-visible { outline: 3px solid #4c9aff; outline-offset: 2px; }
.repair { font-size: 14px; margin: 8px 0 0; }
.summary { margin: 22px 0 10px; font-size: 17px; font-weight: 700; }
table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { border: 1px solid #dfe1e6; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #f4f5f7; }
.pass { color: #006644; font-weight: 700; }
.fail { color: #bf2600; font-weight: 700; }
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
  const input = document.getElementById('yaml');
  const summary = document.getElementById('summary');
  const tbody = document.getElementById('rows');
  const form = document.getElementById('run');
  const repair = document.getElementById('repair');
  const repairSummary = document.getElementById('repair-summary');
  function render() {
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
    const result = ArgusRepair.repairPipelineYaml(input.value);
    input.value = result.yaml;
    repairSummary.textContent = result.applied.length
      ? 'Applied and re-verified: ' + result.applied.join(', ') + '. '
        + 'Still needs a human decision: ' + (result.unsupported.join(', ') || 'none') + '.'
      : 'No safe deterministic repair applies. Still needs a human decision: '
        + (result.unsupported.join(', ') || 'none') + '.';
    render();
  });
  input.addEventListener('input', render);
  render();
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
  <p class="lead">Argus links JSM incidents to Bitbucket pipelines, fires a synthetic
  canary to expose fake-green gates, and opens the verified repair PR. This page runs
  the same twenty Elenchos rules as the Forge app, in your browser, on text you control.</p>
  <p class="status">Status: demo build. It evaluates the YAML below only. It does not
  connect to your Atlassian site and sends nothing anywhere.</p>
  <form id="run">
    <label for="yaml">bitbucket-pipelines.yml (edit it, the verdict updates as you type)</label>
    <textarea id="yaml" name="yaml" spellcheck="false">${escapeHtml(SAMPLE_YAML)}</textarea>
    <button type="submit">Run the kill-test</button>
    <button id="repair" class="secondary" type="button">Apply safe deterministic repairs</button>
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
