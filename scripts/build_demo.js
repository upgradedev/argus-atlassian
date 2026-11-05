'use strict';

// Builds the Argus Enterprise DevSecOps Command Center used in three places,
// each as index.html + app.css + app.js (Forge Custom UI CSP blocks inline code):
//   demo/                  (canonical generated demo)
//   docs/                  (GitHub Pages judge mirror)
//   static/argus-ui/build/ (Forge Custom UI resource)
// The page bundles the REAL domain modules (errors, digest, canary,
// change_ir, evidence, provenance, receipts, standby, policy_shield, ports,
// pipeline_facts, rules, pipeline_repair) with a CommonJS + SHA-256 shim, so
// the browser runs the exact same code the Node tests prove.
//
//   node scripts/build_demo.js

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
:root {
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 24px; --s-6: 32px;
  --r-sm: 8px; --r-md: 11px; --r-lg: 14px; --r-xl: 20px; --r-pill: 999px;
  --fast: 120ms; --med: 200ms; --ease: cubic-bezier(.2, .7, .2, 1);

  --font-sans: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  --font-display: 'Sora', var(--font-sans);
  --font-mono: 'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

  /* Midnight Tech + Signal DevOps palette */
  --canvas: #0a0e1a;
  --bg: #0b1120;
  --bg-2: #050810;
  --panel: rgba(17, 26, 46, 0.78);
  --panel-solid: #111a2e;
  --surface-2: rgba(255, 255, 255, 0.035);
  --surface-3: rgba(255, 255, 255, 0.075);
  --term-bg: #060912;

  --edge: rgba(45, 64, 102, 0.52);
  --edge-strong: rgba(79, 124, 224, 0.45);
  --edge-hair: rgba(45, 64, 102, 0.28);

  --ink: #e6ebf5;
  --muted: #97a3bd;
  --faint: #7886a6;

  --accent: #3b6fe0;
  --accent-soft: #7aa5ff;
  --cyan: #2fbaf0;
  --violet: #7c3aed;

  --aegis: #10b981;
  --block: #ef4444;
  --warn: #f59e0b;

  --grad-primary: linear-gradient(135deg, #3b6fe0 0%, #2fbaf0 100%);
  --grad-success: linear-gradient(135deg, #059669 0%, #10b981 100%);
  --elev-1: 0 4px 20px -2px rgba(0, 0, 0, 0.48);
  --elev-2: 0 16px 48px -12px rgba(0, 0, 0, 0.75);
  --lit: inset 0 1px 0 rgba(255, 255, 255, 0.06);
  --ring: 0 0 0 2px var(--canvas), 0 0 0 4px var(--cyan);

  color-scheme: dark;
}

:root[data-theme='light'] {
  --canvas: #f8fafc;
  --bg: #f1f5f9;
  --bg-2: #e2e8f0;
  --panel: rgba(255, 255, 255, 0.92);
  --panel-solid: #ffffff;
  --surface-2: rgba(15, 23, 42, 0.04);
  --surface-3: rgba(15, 23, 42, 0.08);
  --term-bg: #0f172a;

  --edge: rgba(148, 163, 184, 0.42);
  --edge-strong: rgba(59, 111, 224, 0.45);
  --edge-hair: rgba(148, 163, 184, 0.25);

  --ink: #0f172a;
  --muted: #334155;
  --faint: #475569;

  --accent: #2563eb;
  --accent-soft: #1d4ed8;
  --cyan: #0284c7;
  --aegis: #047857;
  --block: #b91c1c;
  --warn: #b45309;

  --elev-1: 0 4px 16px -2px rgba(15, 23, 42, 0.08);
  --elev-2: 0 12px 32px -8px rgba(15, 23, 42, 0.14);
  --lit: inset 0 1px 0 rgba(255, 255, 255, 0.8);

  color-scheme: light;
}

*, *::before, *::after { box-sizing: border-box; }

body::before {
  content: '';
  position: fixed;
  inset: 0;
  pointer-events: none;
  background-image:
    linear-gradient(to right, rgba(47, 186, 240, 0.06) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(47, 186, 240, 0.06) 1px, transparent 1px);
  background-size: 48px 48px;
  mask-image: radial-gradient(ellipse 85% 65% at 50% 10%, #000 35%, transparent 100%);
  z-index: -1;
}

body {
  margin: 0;
  color: var(--ink);
  font: 400 13.5px/1.55 var(--font-sans);
  letter-spacing: -0.006em;
  -webkit-font-smoothing: antialiased;
  background:
    radial-gradient(circle at 14% 0%, rgba(59, 111, 224, 0.16) 0%, transparent 42%),
    radial-gradient(circle at 86% 10%, rgba(16, 185, 129, 0.10) 0%, transparent 40%),
    linear-gradient(180deg, var(--bg) 0%, var(--bg-2) 100%);
  background-attachment: fixed;
  min-height: 100vh;
}

.skip {
  position: absolute; left: -9999px; top: 0; z-index: 200;
  background: var(--accent); color: #ffffff; padding: 8px 14px;
  border-radius: 0 0 var(--r-sm) 0; font-weight: 700; text-decoration: none;
}
.skip:focus { left: 8px; top: 8px; }

/* App Shell */
.app-shell {
  display: grid;
  grid-template-columns: 240px minmax(0, 1fr);
  min-height: 100vh;
}

/* Sidebar */
.sidebar {
  display: flex;
  flex-direction: column;
  gap: var(--s-3);
  padding: var(--s-4) var(--s-3);
  border-right: 1px solid var(--edge);
  background: var(--panel);
  backdrop-filter: blur(20px);
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}

.sidebar-brand {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 4px 8px 14px;
  border-bottom: 1px solid var(--edge);
}

.brand-logo {
  width: 34px; height: 34px;
  border-radius: 9px;
  background: var(--grad-primary);
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 18px rgba(47, 186, 240, 0.35);
  flex-shrink: 0;
}

.brand-text { display: flex; flex-direction: column; min-width: 0; }
.brand-title {
  font-family: var(--font-display);
  font-size: 16px; font-weight: 800; letter-spacing: 0.08em;
  color: var(--ink); line-height: 1.15;
}
.brand-sub {
  font-family: var(--font-mono);
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  letter-spacing: 0.05em; color: var(--cyan);
}

.nav-section-label {
  margin: 8px 0 4px;
  padding: 0 10px;
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--faint);
}

.nav-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
}

.nav-btn {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  text-align: left;
  padding: 8px 11px;
  border-radius: var(--r-sm);
  border: 1px solid transparent;
  background: transparent;
  color: var(--muted);
  font: 500 13px var(--font-sans);
  cursor: pointer;
  transition: all var(--fast) var(--ease);
}
.nav-btn:hover {
  background: var(--surface-2);
  color: var(--ink);
  border-color: var(--edge);
}
.nav-btn.active {
  background: rgba(59, 111, 224, 0.16);
  color: var(--ink);
  border-color: var(--edge-strong);
  font-weight: 600;
}

.nav-badge {
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 700;
  padding: 1px 7px;
  border-radius: var(--r-pill);
  background: var(--surface-3);
  color: var(--cyan);
  border: 1px solid var(--edge);
}
.nav-badge.alert {
  color: var(--block);
  border-color: rgba(239, 68, 68, 0.4);
  background: rgba(239, 68, 68, 0.12);
}
.nav-badge.ok {
  color: var(--aegis);
  border-color: rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.12);
}

.sidebar-telemetry {
  margin-top: auto;
  padding: 12px;
  border-radius: var(--r-md);
  border: 1px solid var(--edge);
  background: var(--surface-2);
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 11.5px;
}
.telem-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.telem-key { color: var(--muted); }
.telem-val { font-family: var(--font-mono); font-size: 11px; font-weight: 600; color: var(--ink); }

/* Right Column Content */
.shell-body {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

/* Sticky Topbar */
.topbar {
  position: sticky;
  top: 0;
  z-index: 40;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--s-3);
  flex-wrap: wrap;
  padding: 12px 24px;
  border-bottom: 1px solid var(--edge);
  background: var(--panel);
  backdrop-filter: saturate(1.4) blur(14px);
  box-shadow: var(--lit);
}

.topbar-left {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.pill {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 11px;
  border-radius: var(--r-pill);
  font-size: 11.5px;
  font-weight: 600;
  border: 1px solid var(--edge);
  background: var(--surface-2);
  color: var(--ink);
}
.pill-live {
  color: var(--aegis);
  border-color: rgba(16, 185, 129, 0.4);
  background: rgba(16, 185, 129, 0.12);
}
.pill-incident {
  color: var(--block);
  border-color: rgba(239, 68, 68, 0.45);
  background: rgba(239, 68, 68, 0.14);
}
.pill-warn {
  color: var(--warn);
  border-color: rgba(245, 158, 11, 0.45);
  background: rgba(245, 158, 11, 0.14);
}
.pill-mono {
  font-family: var(--font-mono);
  font-size: 11px;
}

.pulse-dot {
  width: 7px; height: 7px;
  border-radius: 50%;
  background: currentColor;
  box-shadow: 0 0 8px currentColor;
}

/* Main Workspace */
main {
  padding: 22px 26px 56px;
  max-width: 1480px;
  width: 100%;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  gap: 22px;
}

/* Hero Banner */
.hero-card {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--edge-strong);
  border-radius: var(--r-lg);
  padding: 20px 24px;
  background: var(--panel);
  box-shadow: var(--elev-1), var(--lit);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.hero-card::before {
  content: '';
  position: absolute;
  inset: 0 0 auto 0;
  height: 3px;
  background: var(--grad-primary);
}
.hero-top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
h1 {
  font-family: var(--font-display);
  font-size: 24px;
  font-weight: 800;
  letter-spacing: -0.02em;
  margin: 0;
  color: var(--ink);
}
h2 {
  font-family: var(--font-display);
  font-size: 16px;
  font-weight: 700;
  letter-spacing: -0.01em;
  margin: 0;
  color: var(--ink);
}
h3 {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin: 0 0 10px;
}
.lead {
  font-size: 14px;
  color: var(--ink);
  max-width: 88ch;
  margin: 0;
  line-height: 1.55;
}
.status {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--cyan);
  margin: 0;
  padding: 6px 10px;
  border-radius: var(--r-sm);
  background: var(--surface-2);
  border: 1px solid var(--edge);
}

/* KPI Ribbon (Metabase + ARKON Command Metrics) */
.kpi-ribbon {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 14px;
}
.kpi-card {
  position: relative;
  overflow: hidden;
  border: 1px solid var(--edge);
  border-radius: var(--r-lg);
  padding: 15px 16px;
  background: var(--panel);
  box-shadow: var(--elev-1), var(--lit);
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.kpi-card::before {
  content: '';
  position: absolute;
  inset: 0 0 auto 0;
  height: 2px;
  background: var(--grad-primary);
}
.kpi-card.band-critical::before { background: var(--block); }
.kpi-card.band-elite::before { background: var(--aegis); }
.kpi-card.band-warn::before { background: var(--warn); }

.kpi-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.kpi-label {
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--muted);
}
.kpi-band {
  font-family: var(--font-mono);
  font-size: 9.5px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 1px 6px;
  border-radius: var(--r-pill);
  border: 1px solid var(--edge);
}
.kpi-band.crit { color: var(--block); border-color: rgba(239, 68, 68, 0.4); background: rgba(239, 68, 68, 0.12); }
.kpi-band.ok { color: var(--aegis); border-color: rgba(16, 185, 129, 0.4); background: rgba(16, 185, 129, 0.12); }
.kpi-band.warn { color: var(--warn); border-color: rgba(245, 158, 11, 0.4); background: rgba(245, 158, 11, 0.12); }

.kpi-value {
  font-family: var(--font-display);
  font-size: 24px;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: var(--ink);
  font-variant-numeric: tabular-nums;
  line-height: 1.15;
}
.kpi-sub {
  font-size: 11.5px;
  color: var(--muted);
}
.kpi-bar-track {
  height: 6px;
  border-radius: var(--r-pill);
  background: var(--surface-3);
  overflow: hidden;
  margin-top: 2px;
}
.kpi-bar-fill {
  height: 100%;
  border-radius: var(--r-pill);
  background: var(--grad-primary);
  transition: width var(--med) var(--ease);
}
.kpi-bar-fill.ok { background: var(--aegis); }
.kpi-bar-fill.crit { background: var(--block); }
.kpi-bar-fill.warn { background: var(--warn); }

/* Zone Panels */
.zone-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.zone-section.hidden { display: none; }

.grid-2col {
  display: grid;
  grid-template-columns: 1.15fr 0.85fr;
  gap: 16px;
  align-items: start;
}

.workbench-grid {
  display: grid;
  grid-template-columns: 1.05fr 0.95fr;
  gap: 16px;
  align-items: start;
}

.panel {
  border: 1px solid var(--edge);
  border-radius: var(--r-lg);
  padding: 18px 20px;
  background: var(--panel);
  backdrop-filter: blur(20px);
  box-shadow: var(--elev-1), var(--lit);
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  flex-wrap: wrap;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--edge);
}

/* Metabase Stage Breakdown Bars */
.stage-rows {
  display: flex;
  flex-direction: column;
  gap: 11px;
}
.stage-row {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 9px 12px;
  border-radius: var(--r-md);
  background: var(--surface-2);
  border: 1px solid var(--edge-hair);
}
.stage-row-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  font-size: 12.5px;
}
.stage-name { font-weight: 600; color: var(--ink); }
.stage-counts { font-family: var(--font-mono); font-size: 11.5px; color: var(--muted); }
.stage-track {
  height: 8px;
  border-radius: var(--r-pill);
  background: rgba(239, 68, 68, 0.28);
  overflow: hidden;
  display: flex;
}
.stage-fill-pass {
  height: 100%;
  background: var(--aegis);
  transition: width var(--med) var(--ease);
}
.w-0 { width: 0%; }
.w-20 { width: 20%; }
.w-35 { width: 35%; }
.w-40 { width: 40%; }
.w-60 { width: 60%; }
.w-80 { width: 80%; }
.w-100 { width: 100%; }

/* ARKON Execution Stage Ladder */
.run-ladder {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
}
.ladder-rung {
  position: relative;
  display: flex;
  gap: 12px;
  padding: 0 0 12px 0;
}
.ladder-rung::before {
  content: '';
  position: absolute;
  left: 6px;
  top: 16px;
  bottom: 0;
  width: 2px;
  background: var(--edge);
}
.ladder-rung:last-child::before { display: none; }
.ladder-rung:last-child { padding-bottom: 0; }
.ladder-node {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  margin-top: 2px;
  flex-shrink: 0;
  border: 2px solid var(--muted);
  background: var(--canvas);
  z-index: 1;
}
.ladder-rung.done .ladder-node { border-color: var(--aegis); background: var(--aegis); box-shadow: 0 0 8px var(--aegis); }
.ladder-rung.active .ladder-node { border-color: var(--cyan); background: var(--cyan); box-shadow: 0 0 8px var(--cyan); }
.ladder-rung.alert .ladder-node { border-color: var(--block); background: var(--block); box-shadow: 0 0 8px var(--block); }
.ladder-body { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.ladder-title-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.ladder-title { font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--ink); }
.ladder-tag {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  text-transform: uppercase;
  padding: 1px 6px;
  border-radius: var(--r-sm);
  background: var(--surface-3);
  color: var(--cyan);
}
.ladder-desc { font-size: 11.5px; color: var(--muted); margin: 0; }

/* Signal DevOps Terminal Window */
.terminal-chrome {
  border: 1px solid var(--edge-strong);
  border-radius: var(--r-md);
  overflow: hidden;
  background: var(--term-bg);
  box-shadow: inset 0 0 24px rgba(0, 0, 0, 0.65);
}
.terminal-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 12px;
  background: rgba(255, 255, 255, 0.04);
  border-bottom: 1px solid var(--edge);
}
.terminal-dots { display: flex; gap: 6px; }
.term-dot { width: 10px; height: 10px; border-radius: 50%; }
.term-dot.r { background: #ef4444; }
.term-dot.y { background: #f59e0b; }
.term-dot.g { background: #10b981; }
.terminal-title {
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--muted);
}

label {
  font-weight: 600;
  font-size: 12.5px;
  color: var(--ink);
  display: block;
  margin: 6px 0 4px;
}

textarea, input[type="text"], select {
  width: 100%;
  padding: 10px 12px;
  border: 1px solid var(--edge-strong);
  border-radius: var(--r-sm);
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.55;
  background: var(--surface-2);
  color: var(--ink);
}
#yaml {
  min-height: 235px;
  border: none;
  border-radius: 0;
  background: var(--term-bg);
  color: #e2e8f0;
  padding: 14px;
  resize: vertical;
}

/* Buttons */
.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}

button {
  background: var(--grad-primary);
  color: #ffffff;
  border: 1px solid rgba(122, 165, 255, 0.4);
  border-radius: var(--r-sm);
  padding: 8px 14px;
  font: 600 13px var(--font-sans);
  cursor: pointer;
  transition: filter var(--fast) var(--ease), transform var(--fast) var(--ease);
}
button:hover { filter: brightness(1.08); }
button:active { transform: translateY(1px); }

button.secondary {
  background: var(--surface-2);
  color: var(--ink);
  border: 1px solid var(--edge-strong);
}
button.secondary:hover {
  background: var(--surface-3);
}
button.danger-btn {
  background: rgba(239, 68, 68, 0.14);
  color: var(--block);
  border: 1px solid rgba(239, 68, 68, 0.45);
}

button:focus-visible, textarea:focus-visible, input:focus-visible, select:focus-visible {
  outline: none;
  box-shadow: var(--ring);
}

/* Diff Viewer */
.diff-box {
  background: var(--term-bg);
  border: 1px solid var(--edge);
  border-radius: var(--r-md);
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 11.5px;
  line-height: 1.5;
  max-height: 190px;
  overflow-y: auto;
  white-space: pre-wrap;
  color: #cbd5e1;
}
.diff-line-add { color: #34d399; background: rgba(16, 185, 129, 0.12); display: block; padding: 0 4px; }
.diff-line-del { color: #f87171; background: rgba(239, 68, 68, 0.12); display: block; padding: 0 4px; }
.diff-line-hdr { color: #38bdf8; font-weight: 700; display: block; }

/* Filter Chips */
.chip-row {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.filter-chip {
  padding: 4px 11px;
  border-radius: var(--r-pill);
  border: 1px solid var(--edge);
  background: var(--surface-2);
  color: var(--muted);
  font-size: 11.5px;
  font-weight: 600;
  cursor: pointer;
}
.filter-chip.active {
  background: var(--accent);
  color: #ffffff;
  border-color: var(--accent);
}

/* Status Banners */
.repair {
  font-size: 12.5px;
  color: var(--cyan);
  margin: 4px 0 0;
  padding: 8px 11px;
  border-radius: var(--r-sm);
  background: var(--surface-2);
  border-left: 3px solid var(--cyan);
}
.summary {
  margin: 6px 0;
  padding: 10px 12px;
  border-radius: var(--r-sm);
  font-size: 13.5px;
  font-weight: 700;
  background: var(--surface-2);
  border: 1px solid var(--edge);
}

/* Rules Table */
.table-scroll {
  overflow-x: auto;
  max-height: 460px;
  overflow-y: auto;
  border: 1px solid var(--edge);
  border-radius: var(--r-md);
}
table {
  border-collapse: collapse;
  width: 100%;
  font-size: 12.5px;
}
th, td {
  border-bottom: 1px solid var(--edge-hair);
  padding: 8px 10px;
  text-align: left;
  vertical-align: middle;
}
th {
  position: sticky;
  top: 0;
  background: var(--panel-solid);
  color: var(--muted);
  font-size: 10.5px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  border-bottom: 1px solid var(--edge);
  z-index: 2;
}
tbody tr:hover {
  background: var(--surface-2);
}
.pass {
  color: var(--aegis);
  font-family: var(--font-mono);
  font-weight: 700;
}
.fail {
  color: var(--block);
  font-family: var(--font-mono);
  font-weight: 700;
}

/* Provenance & Evidence Cards */
.prov-nodes-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
}
.prov-node-card {
  padding: 11px 12px;
  border-radius: var(--r-md);
  border: 1px solid var(--edge);
  background: var(--surface-2);
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.prov-node-type {
  font-family: var(--font-mono);
  font-size: 10px;
  text-transform: uppercase;
  color: var(--cyan);
  font-weight: 700;
}
.prov-node-id {
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 700;
  color: var(--ink);
}
.prov-node-meta {
  font-size: 11.5px;
  color: var(--muted);
}

.evidence-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 4px;
}
.ev-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 9px;
  border-radius: var(--r-pill);
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 600;
  color: var(--aegis);
  background: rgba(16, 185, 129, 0.12);
  border: 1px solid rgba(16, 185, 129, 0.35);
}

/* Cards & Definition Lists */
.card {
  border: 1px solid var(--edge);
  border-radius: var(--r-md);
  padding: 14px;
  background: var(--surface-2);
}
.mono {
  font-family: var(--font-mono);
  font-size: 12px;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.braille {
  font-size: 20px;
  line-height: 1.5;
  letter-spacing: 0.04em;
  color: var(--cyan);
  overflow-wrap: anywhere;
  word-break: break-word;
}
dl { margin: 0; display: flex; flex-direction: column; gap: 8px; }
dt {
  font-size: 10.5px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.07em;
  color: var(--muted);
  margin: 0;
}
dd {
  margin: 2px 0 0 0;
  font-size: 13px;
  color: var(--ink);
  overflow-wrap: anywhere;
}

.lens-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 10px;
  margin-top: 8px;
}
.lens-card {
  padding: 11px 12px;
  border-radius: var(--r-md);
  border: 1px solid var(--edge);
  background: var(--panel);
}
.lens-card.active-lens {
  border-color: var(--cyan);
  box-shadow: 0 0 0 1px var(--cyan);
}

.note {
  font-size: 12px;
  color: var(--muted);
  margin: 0;
  line-height: 1.55;
}

@media (max-width: 1120px) {
  .app-shell { grid-template-columns: 1fr; }
  .sidebar { position: static; height: auto; border-right: none; border-bottom: 1px solid var(--edge); }
  .kpi-ribbon { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .grid-2col, .workbench-grid, .lens-grid, .prov-nodes-grid { grid-template-columns: 1fr; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
}
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
  const repairableSet = { r01: true, r05: true, r15: true, r16: true, r20: true };
  const stageGroups = [
    {
      id: 'stage-supply',
      name: 'Stage 1: Container & Runner Supply Chain',
      rules: ['r01', 'r11', 'r14', 'r17', 'r20']
    },
    {
      id: 'stage-integrity',
      name: 'Stage 2: Test & Exit-Code Integrity',
      rules: ['r02', 'r03', 'r06', 'r12', 'r15']
    },
    {
      id: 'stage-secrets',
      name: 'Stage 3: Secrets, OIDC & Clone Hygiene',
      rules: ['r04', 'r08', 'r13', 'r18', 'r19']
    },
    {
      id: 'stage-gates',
      name: 'Stage 4: Release & Security Gates',
      rules: ['r05', 'r07', 'r09', 'r10', 'r16']
    }
  ];

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
  const tamperDigestBtn = document.getElementById('tamper-digest');
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
  const diffPreview = document.getElementById('yaml-diff-preview');
  const themeToggle = document.getElementById('theme-toggle');
  const shield = new ArgusShield.PolicyShield();

  let activeFilter = 'all';

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
    const kpiSla = document.getElementById('kpi-sla-timer');
    const kpiSlaSub = document.getElementById('kpi-sla-sub');
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
    if (kpiSla) kpiSla.textContent = elapsed + 's / 900s';
    if (kpiSlaSub) {
      kpiSlaSub.textContent = pageOutcome.escalated
        ? 'SLA breached -> Standby SRE paged'
        : 'Within SLA -> Primary SRE active';
    }
  }

  function renderDiff(currentYaml) {
    if (!diffPreview) return;
    if (!currentYaml.trim()) {
      diffPreview.textContent = 'No YAML content to diff.';
      return;
    }
    const repaired = ArgusRepair.repairPipelineYaml(currentYaml);
    const origLines = currentYaml.split('\\n');
    const nextLines = repaired.yaml.split('\\n');
    const lines = [];
    lines.push('--- a/bitbucket-pipelines.yml (current)');
    lines.push('+++ b/bitbucket-pipelines.yml (deterministic repair preview)');
    const maxLen = Math.max(origLines.length, nextLines.length);
    let diffCount = 0;
    for (let i = 0; i < maxLen; i += 1) {
      const a = origLines[i];
      const b = nextLines[i];
      if (a === b) {
        if (a !== undefined) lines.push('  ' + a);
      } else {
        if (a !== undefined) { lines.push('- ' + a); diffCount += 1; }
        if (b !== undefined) { lines.push('+ ' + b); diffCount += 1; }
      }
    }
    if (diffCount === 0) {
      lines.push('# All deterministic YAML repairs (r01, r05, r15, r16, r20) are already applied.');
    }
    diffPreview.textContent = lines.join('\\n');
  }

  function render() {
    if (!input.value.trim()) {
      repairSummary.textContent =
        'The pipeline editor is empty. Paste a bitbucket-pipelines.yml file or press Reset to sample P1 incident (DEMO-11).';
    }
    const facts = ArgusFacts.extractPipelineFacts(input.value);
    const out = ArgusRules.evaluateRules(facts);
    const passing = out.results.filter(function (r) { return r.clean; }).length;
    const failing = out.results.length - passing;
    const pct = Math.round((passing / out.results.length) * 100);

    summary.textContent = out.clean
      ? 'Verdict: exit 0. All 20 Elenchos rules pass on these facts.'
      : 'Verdict: exit 1. ' + out.violations.length + ' of 20 Elenchos rules fail: '
        + out.violations.join(', ') + '.';

    const byId = {};
    out.results.forEach(function (r) { byId[r.id] = r; });

    tbody.innerHTML = '';
    out.results.forEach(function (r) {
      if (activeFilter === 'fail' && r.clean) return;
      if (activeFilter === 'pass' && !r.clean) return;
      if (activeFilter === 'repair' && !repairableSet[r.id]) return;

      const tr = document.createElement('tr');
      const id = document.createElement('td');
      id.textContent = r.id;
      id.className = 'mono';
      const title = document.createElement('td');
      title.textContent = r.title + (repairableSet[r.id] ? ' [auto-repair]' : '');
      const state = document.createElement('td');
      state.textContent = r.clean ? 'PASS' : 'FAIL';
      state.className = r.clean ? 'pass' : 'fail';
      tr.append(id, title, state);
      tr.addEventListener('click', function () {
        ruleSelect.value = r.id;
        buildProposal(r.id);
        executeGovernance();
      });
      tbody.appendChild(tr);
    });

    document.getElementById('passing').textContent = passing + '/20 rules passing';

    const kpiRate = document.getElementById('kpi-gate-rate');
    if (kpiRate) kpiRate.textContent = pct + '%';
    const kpiGateBar = document.getElementById('kpi-gate-bar');
    if (kpiGateBar) {
      const snapPct = pct >= 100 ? 100 : pct >= 80 ? 80 : pct >= 60 ? 60 : pct >= 40 ? 40 : pct >= 35 ? 35 : pct >= 20 ? 20 : 0;
      kpiGateBar.className = 'kpi-bar-fill ' + (pct >= 80 ? 'ok' : pct >= 50 ? 'warn' : 'crit') + ' w-' + snapPct;
    }
    const kpiOpen = document.getElementById('kpi-open-findings');
    if (kpiOpen) kpiOpen.textContent = failing + ' Failing';
    const navFailBadge = document.getElementById('nav-fail-badge');
    if (navFailBadge) navFailBadge.textContent = failing + ' fail';

    stageGroups.forEach(function (sg) {
      const passCount = sg.rules.filter(function (rid) { return byId[rid] && byId[rid].clean; }).length;
      const countEl = document.getElementById(sg.id + '-count');
      if (countEl) {
        countEl.textContent = passCount + '/' + sg.rules.length + ' passing';
      }
      const barEl = document.getElementById(sg.id + '-bar');
      if (barEl) {
        const stagePct = Math.round((passCount / sg.rules.length) * 100);
        barEl.className = 'stage-fill-pass w-' + stagePct;
      }
    });

    renderDiff(input.value);
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
  if (tamperDigestBtn) {
    tamperDigestBtn.addEventListener('click', function () {
      digestInput.value = '0000000000000000000000000000000000000000000000000000000000000000';
      executeGovernance();
    });
  }
  elapsedSelect.addEventListener('change', executeGovernance);
  governForm.addEventListener('submit', function (e) {
    e.preventDefault();
    executeGovernance();
  });
  input.addEventListener('input', render);

  [
    ['filter-all', 'all'],
    ['filter-fail', 'fail'],
    ['filter-pass', 'pass'],
    ['filter-repair', 'repair']
  ].forEach(function (pair) {
    const btn = document.getElementById(pair[0]);
    if (btn) {
      btn.addEventListener('click', function () {
        activeFilter = pair[1];
        ['filter-all', 'filter-fail', 'filter-pass', 'filter-repair'].forEach(function (id) {
          const el = document.getElementById(id);
          if (el) el.className = id === pair[0] ? 'filter-chip active' : 'filter-chip';
        });
        render();
      });
    }
  });

  const zones = ['zone-posture', 'zone-workbench', 'zone-provenance', 'zone-governance'];
  [
    ['nav-all', 'all'],
    ['nav-posture', 'zone-posture'],
    ['nav-workbench', 'zone-workbench'],
    ['nav-provenance', 'zone-provenance'],
    ['nav-governance', 'zone-governance']
  ].forEach(function (pair) {
    const btn = document.getElementById(pair[0]);
    if (btn) {
      btn.addEventListener('click', function () {
        ['nav-all', 'nav-posture', 'nav-workbench', 'nav-provenance', 'nav-governance'].forEach(function (id) {
          const el = document.getElementById(id);
          if (el) el.className = id === pair[0] ? 'nav-btn active' : 'nav-btn';
        });
        zones.forEach(function (zid) {
          const z = document.getElementById(zid);
          if (z) {
            z.className = (pair[1] === 'all' || pair[1] === zid) ? 'zone-section' : 'zone-section hidden';
          }
        });
      });
    }
  });

  if (themeToggle) {
    themeToggle.addEventListener('click', function () {
      if (typeof document.documentElement !== 'undefined' && document.documentElement.getAttribute) {
        const cur = document.documentElement.getAttribute('data-theme') || 'dark';
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        themeToggle.textContent = next === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme';
      }
    });
  }

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
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Argus Socratic Canary: is your green pipeline real?</title>
<link rel="icon" href="argus-icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="app.css">
</head>
<body>
<a class="skip" href="#main">Skip to the demo</a>
<div class="app-shell">
  <aside class="sidebar" aria-label="Argus navigation">
    <div class="sidebar-brand">
      <div class="brand-logo" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <path d="M12 3L2 21H22L12 3Z" stroke="#ffffff" stroke-width="2" stroke-linejoin="round"/>
          <circle cx="12" cy="14" r="3" fill="#10b981"/>
        </svg>
      </div>
      <div class="brand-text">
        <span class="brand-title">ARGUS</span>
        <span class="brand-sub">upgradegr · Forge</span>
      </div>
    </div>

    <div class="nav-section-label">Command Views</div>
    <nav class="nav-list" aria-label="Workspace sections">
      <button id="nav-all" class="nav-btn active" type="button">
        <span>Command Center (All)</span>
        <span class="nav-badge ok">Live</span>
      </button>
      <button id="nav-posture" class="nav-btn" type="button">
        <span>DevSecOps Posture</span>
        <span class="nav-badge">4 stages</span>
      </button>
      <button id="nav-workbench" class="nav-btn" type="button">
        <span>Pipeline &amp; Canary</span>
        <span id="nav-fail-badge" class="nav-badge alert">13 fail</span>
      </button>
      <button id="nav-provenance" class="nav-btn" type="button">
        <span>Provenance &amp; Shield</span>
        <span class="nav-badge ok">7/7</span>
      </button>
      <button id="nav-governance" class="nav-btn" type="button">
        <span>Change Gate &amp; Receipts</span>
        <span class="nav-badge">SHA-256</span>
      </button>
    </nav>

    <div class="sidebar-telemetry" aria-label="Atlassian Forge runtime telemetry">
      <div class="telem-row">
        <span class="telem-key">Tenant</span>
        <span class="telem-val">upgradegr.atlassian.net</span>
      </div>
      <div class="telem-row">
        <span class="telem-key">Active Incident</span>
        <span class="telem-val">DEMO-11 (P1)</span>
      </div>
      <div class="telem-row">
        <span class="telem-key">State Store</span>
        <span class="telem-val">Forge KVS</span>
      </div>
      <div class="telem-row">
        <span class="telem-key">Network Egress</span>
        <span class="telem-val">0 External Domains</span>
      </div>
    </div>
  </aside>

  <div class="shell-body">
    <header class="topbar" role="banner">
      <div class="topbar-left">
        <span class="pill pill-incident"><span class="pulse-dot"></span>JSM P1 · DEMO-11</span>
        <span class="pill pill-mono">repo: upgradegr/payments-service</span>
        <span class="pill pill-warn">Pipeline #482 · Fake-Green Detected</span>
      </div>
      <div class="topbar-right">
        <span class="pill pill-live"><span class="pulse-dot"></span>Runs on Atlassian · Zero-Egress</span>
        <button id="theme-toggle" class="secondary" type="button">Switch to Light Theme</button>
      </div>
    </header>

    <main id="main" role="main" aria-label="Argus Socratic Canary demo">
      <section class="hero-card" aria-label="Executive mission summary">
        <div class="hero-top">
          <div>
            <h1>Is your green pipeline real?</h1>
            <p class="lead">Argus links JSM incidents to linked Bitbucket work, fires a synthetic
            canary to expose fake-green gates, and returns a re-verified repair patch. This command center
            runs the same twenty Elenchos rules as the Forge app, in your browser, on text you control.</p>
          </div>
        </div>
        <p id="runtime-status" class="status" role="status" aria-live="polite">Status: demo build. It evaluates the Bitbucket Pipelines YAML below
        directly in your browser. It does not connect to your Atlassian site and sends nothing anywhere.</p>
      </section>

      <!-- ZONE 1: Metabase DevSecOps Posture & Stage Analytics -->
      <section id="zone-posture" class="zone-section" aria-label="DevSecOps posture metrics and stage breakdown">
        <div class="kpi-ribbon">
          <div class="kpi-card band-critical">
            <div class="kpi-head">
              <span class="kpi-label">Security Gate Pass Rate</span>
              <span class="kpi-band crit">Gate Blocked</span>
            </div>
            <div id="kpi-gate-rate" class="kpi-value">35%</div>
            <div class="kpi-sub">Goal: 100% across 20 Elenchos rules</div>
            <div class="kpi-bar-track"><div id="kpi-gate-bar" class="kpi-bar-fill crit w-35"></div></div>
          </div>

          <div class="kpi-card band-critical">
            <div class="kpi-head">
              <span class="kpi-label">Open Pipeline Findings</span>
              <span class="kpi-band crit">Exit 1</span>
            </div>
            <div id="kpi-open-findings" class="kpi-value">13 Failing</div>
            <div id="passing" class="kpi-sub">7/20 rules passing</div>
          </div>

          <div class="kpi-card band-elite">
            <div class="kpi-head">
              <span class="kpi-label">SupportTrace Evidence</span>
              <span class="kpi-band ok">Grounded</span>
            </div>
            <div class="kpi-value">7/7 Sources</div>
            <div class="kpi-sub">Data · Identity · Events · Pipeline · Config · Logs · Edge</div>
          </div>

          <div class="kpi-card band-elite">
            <div class="kpi-head">
              <span class="kpi-label">Kill-Test Benchmark</span>
              <span class="kpi-band ok">Verified</span>
            </div>
            <div class="kpi-value">20/20 Rules</div>
            <div class="kpi-sub">Badge-only check thrown out 20/20</div>
          </div>

          <div class="kpi-card band-warn">
            <div class="kpi-head">
              <span class="kpi-label">On-Call Ack SLA</span>
              <span class="kpi-band warn">900s Window</span>
            </div>
            <div id="kpi-sla-timer" class="kpi-value">0s / 900s</div>
            <div id="kpi-sla-sub" class="kpi-sub">Within SLA -&gt; Primary SRE active</div>
          </div>
        </div>

        <div class="grid-2col">
          <div class="panel" aria-label="Findings by pipeline stage">
            <div class="panel-head">
              <h2>Findings by Pipeline Stage &amp; Control Domain</h2>
              <span class="pill pill-mono">Normalized CI + SAST + Governance</span>
            </div>
            <div class="stage-rows">
              <div class="stage-row">
                <div class="stage-row-top">
                  <span class="stage-name">Stage 1: Container &amp; Runner Supply Chain (r01, r11, r14, r17, r20)</span>
                  <span id="stage-supply-count" class="stage-counts">2/5 passing</span>
                </div>
                <div class="stage-track"><div id="stage-supply-bar" class="stage-fill-pass w-40"></div></div>
                <div class="note">Checks immutable image digests, Docker privilege, cache key pinning, pipe tags, and memory bounds.</div>
              </div>
              <div class="stage-row">
                <div class="stage-row-top">
                  <span class="stage-name">Stage 2: Test &amp; Exit-Code Integrity (r02, r03, r06, r12, r15)</span>
                  <span id="stage-integrity-count" class="stage-counts">1/5 passing</span>
                </div>
                <div class="stage-track"><div id="stage-integrity-bar" class="stage-fill-pass w-20"></div></div>
                <div class="note">Catches masked exit codes (|| true, || exit 0), --passWithNoTests, set +e, and unbounded step timeouts.</div>
              </div>
              <div class="stage-row">
                <div class="stage-row-top">
                  <span class="stage-name">Stage 3: Secrets, OIDC &amp; Clone Hygiene (r04, r08, r13, r18, r19)</span>
                  <span id="stage-secrets-count" class="stage-counts">2/5 passing</span>
                </div>
                <div class="stage-track"><div id="stage-secrets-bar" class="stage-fill-pass w-40"></div></div>
                <div class="note">Verifies OIDC role tokens, secret log masking, shallow git clone depth, artifact expiry, and branch checks.</div>
              </div>
              <div class="stage-row">
                <div class="stage-row-top">
                  <span class="stage-name">Stage 4: Release &amp; Security Gates (r05, r07, r09, r10, r16)</span>
                  <span id="stage-gates-count" class="stage-counts">2/5 passing</span>
                </div>
                <div class="stage-track"><div id="stage-gates-bar" class="stage-fill-pass w-40"></div></div>
                <div class="note">Enforces production deployment locks, SAST/SCA gates, parallel step isolation, and PR branch triggers.</div>
              </div>
            </div>
          </div>

          <div class="panel" aria-label="Autonomous incident execution spine">
            <div class="panel-head">
              <h2>Execution Spine · JSM Incident DEMO-11</h2>
              <span class="pill pill-live">Deterministic Core</span>
            </div>
            <ol class="run-ladder">
              <li class="ladder-rung done">
                <span class="ladder-node"></span>
                <div class="ladder-body">
                  <div class="ladder-title-row">
                    <span class="ladder-title">1. Bitbucket Pipeline #482 Ingested</span>
                    <span class="ladder-tag">commit-9f2c41e</span>
                  </div>
                  <p class="ladder-desc">Detected green deployment badge followed 7 minutes later by JSM P1 incident DEMO-11.</p>
                </div>
              </li>
              <li class="ladder-rung alert">
                <span class="ladder-node"></span>
                <div class="ladder-body">
                  <div class="ladder-title-row">
                    <span class="ladder-title">2. Elenchos 20-Rule Socratic Canary</span>
                    <span class="ladder-tag">exit 1</span>
                  </div>
                  <p class="ladder-desc">Exposed masked test failures (--passWithNoTests || true) and floating node:latest image.</p>
                </div>
              </li>
              <li class="ladder-rung done">
                <span class="ladder-node"></span>
                <div class="ladder-body">
                  <div class="ladder-title-row">
                    <span class="ladder-title">3. SupportTrace 7-Source Evidence Seal</span>
                    <span class="ladder-tag">7/7 grounded</span>
                  </div>
                  <p class="ladder-desc">Sealed provenance chain from DEMO-11 back to commit-9f2c41e with SHA-256 Merkle root.</p>
                </div>
              </li>
              <li class="ladder-rung active">
                <span class="ladder-node"></span>
                <div class="ladder-body">
                  <div class="ladder-title-row">
                    <span class="ladder-title">4. PolicyShield Lachesis &amp; Typed Change IR</span>
                    <span class="ladder-tag">confirm</span>
                  </div>
                  <p class="ladder-desc">Synthesized content-addressed repair patch and bound write approval to 64-char SHA-256 digest.</p>
                </div>
              </li>
              <li class="ladder-rung done">
                <span class="ladder-node"></span>
                <div class="ladder-body">
                  <div class="ladder-title-row">
                    <span class="ladder-title">5. Standby On-Call Routing &amp; Braille Receipt</span>
                    <span class="ladder-tag">Merkle + Braille</span>
                  </div>
                  <p class="ladder-desc">Enforced 900s SLA failover window and issued spoken + Grade-1 Braille audit receipt.</p>
                </div>
              </li>
            </ol>
          </div>
        </div>
      </section>

      <!-- ZONE 2: Signal DevOps Terminal Workbench & 20-Rule Matrix -->
      <section id="zone-workbench" class="zone-section" aria-label="Pipeline editor, deterministic repair diff, and rule results">
        <div class="workbench-grid">
          <div class="panel">
            <div class="panel-head">
              <h2>Bitbucket Pipeline Canary Workbench</h2>
              <span class="pill pill-mono">bitbucket-pipelines.yml</span>
            </div>
            <form id="run">
              <label for="yaml">bitbucket-pipelines.yml (edit live; verdict and diff update as you type)</label>
              <div class="terminal-chrome">
                <div class="terminal-bar">
                  <div class="terminal-dots" aria-hidden="true">
                    <span class="term-dot r"></span>
                    <span class="term-dot y"></span>
                    <span class="term-dot g"></span>
                  </div>
                  <span class="terminal-title">upgradegr/payments-service · branch: main</span>
                </div>
                <textarea id="yaml" name="yaml" spellcheck="false">${escapeHtml(SAMPLE_YAML)}</textarea>
              </div>
              <div class="actions">
                <button type="submit">Run the kill-test</button>
                <button id="repair" class="secondary" type="button">Apply safe deterministic repairs</button>
                <button id="seed-reset" class="secondary" type="button">Reset to sample P1 incident (DEMO-11)</button>
              </div>
            </form>
            <p id="repair-summary" class="repair" role="status" aria-live="polite"></p>
            <p id="summary" class="summary" role="status" aria-live="polite"></p>

            <div>
              <h3>Deterministic Repair Patch Preview (Unified Diff)</h3>
              <pre id="yaml-diff-preview" class="diff-box" aria-label="Deterministic YAML repair diff preview"></pre>
            </div>
          </div>

          <div class="panel">
            <div class="panel-head">
              <h2>Elenchos 20-Rule Evaluation Matrix</h2>
              <div class="chip-row" role="group" aria-label="Filter Elenchos rules">
                <button id="filter-all" class="filter-chip active" type="button">All (20)</button>
                <button id="filter-fail" class="filter-chip" type="button">Failing</button>
                <button id="filter-pass" class="filter-chip" type="button">Passing</button>
                <button id="filter-repair" class="filter-chip" type="button">Auto-Repair (5)</button>
              </div>
            </div>
            <div class="table-scroll">
              <table aria-label="Elenchos rule results">
                <thead>
                  <tr>
                    <th scope="col">Rule</th>
                    <th scope="col">Checks</th>
                    <th scope="col">Result</th>
                  </tr>
                </thead>
                <tbody id="rows"></tbody>
              </table>
            </div>
            <p class="note">Exit 1 means at least one rule failed on these facts. Exit 0 means all
            twenty passed on the facts the extractor could see. One fact, required merge check
            enforcement (r13), lives in Bitbucket branch restrictions, not in this file, so here
            it stays flagged until the app reads it from the API. Each rule earned its id by
            separating a violating fixture (exit 1) from a clean one (exit 0) in the Socratic
            Kill-Test. A check that cannot separate the two is thrown out before a human sees it.</p>
          </div>
        </div>
      </section>

      <!-- ZONE 3: Provenance Thread, 7-Source SupportTrace & PolicyShield -->
      <section id="zone-provenance" class="zone-section" aria-label="Incident provenance and evidence graph">
        <div class="panel" aria-label="Provenance thread for incident DEMO-11">
          <div class="panel-head">
            <h2>Incident Provenance Graph, 7-Source Evidence &amp; PolicyShield Guardrail</h2>
            <span class="pill pill-live">SHA-256 Sealed Chain</span>
          </div>

          <div class="prov-nodes-grid" aria-label="Provenance nodes from commit to incident">
            <div class="prov-node-card">
              <span class="prov-node-type">1. Offending Commit (Root Cause)</span>
              <span class="prov-node-id">commit-9f2c41e</span>
              <span class="prov-node-meta">Actor: dev-alex · 2026-11-05T03:20:00Z</span>
              <span class="prov-node-meta">Mask npm test exit code in bitbucket-pipelines.yml</span>
            </div>
            <div class="prov-node-card">
              <span class="prov-node-type">2. Fake-Green Pipeline Run</span>
              <span class="prov-node-id">deploy-prod-482</span>
              <span class="prov-node-meta">Actor: bitbucket-pipelines · 2026-11-05T03:25:00Z</span>
              <span class="prov-node-meta">Bitbucket Pipeline #482 reported green</span>
            </div>
            <div class="prov-node-card">
              <span class="prov-node-type">3. JSM Production Outage</span>
              <span class="prov-node-id">DEMO-11</span>
              <span class="prov-node-meta">Actor: jsm-trigger · 2026-11-05T03:32:24Z</span>
              <span class="prov-node-meta">JSM P1 checkout outage after green release</span>
            </div>
          </div>

          <div class="evidence-pills" aria-label="Seven SupportTrace evidence sources">
            <span class="ev-pill">1. DATA: JSM DEMO-11</span>
            <span class="ev-pill">2. IDENTITY: SRE Roster</span>
            <span class="ev-pill">3. EVENTS: Issue Webhook</span>
            <span class="ev-pill">4. PIPELINE: Bitbucket YAML</span>
            <span class="ev-pill">5. CONFIG: Branch Policy</span>
            <span class="ev-pill">6. LOGS: Canary Exit Log</span>
            <span class="ev-pill">7. EDGE: Zero-Egress Boundary</span>
          </div>

          <div class="card">
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
        </div>
      </section>

      <!-- ZONE 4: Typed Change IR, Fail-Closed Digest Gate, Standby SLA & Braille Receipt -->
      <section id="zone-governance" class="zone-section" aria-labelledby="gov-heading">
        <div class="panel">
          <div class="panel-head">
            <h2 id="gov-heading">Typed Change IR, JSM Change Gate &amp; Cryptographic Receipt Vault</h2>
            <span class="pill pill-mono">Ed25519 + SHA-256 Merkle</span>
          </div>

          <div class="grid-2col">
            <form id="govern-form">
              <label for="rule-select">Select Elenchos rule for Typed Change IR proposal</label>
              <select id="rule-select" name="ruleId"></select>

              <div class="card" aria-label="Typed Change IR role lenses">
                <dl>
                  <dt>Proposal ID</dt>
                  <dd id="change-id" class="mono"></dd>
                  <dt>Content-addressed SHA-256 digest</dt>
                  <dd id="change-digest" class="mono"></dd>
                </dl>
                <div class="lens-grid">
                  <div class="lens-card">
                    <dl>
                      <dt>Engineering Director / CISO lens</dt>
                      <dd id="lens-director"></dd>
                    </dl>
                  </div>
                  <div class="lens-card">
                    <dl>
                      <dt>SecOps / SRE Lead lens</dt>
                      <dd id="lens-secops"></dd>
                    </dl>
                  </div>
                  <div class="lens-card">
                    <dl>
                      <dt>JSM Standby On-Call Engineer lens</dt>
                      <dd id="lens-standby"></dd>
                    </dl>
                  </div>
                </div>
              </div>

              <label for="approval-digest">Approval SHA-256 digest (edit a character or click Simulate Tamper to test fail-closed verification)</label>
              <input id="approval-digest" name="approvalDigest" type="text" spellcheck="false">

              <label for="elapsed-seconds">JSM on-call elapsed time (900-second SLA window)</label>
              <select id="elapsed-seconds" name="elapsedSeconds">
                <option value="0">0 seconds: Primary SRE Dimitris Lagos inside 900s SLA window</option>
                <option value="960">960 seconds: SLA missed, automatic failover to Standby SRE Eleni Papadopoulou</option>
              </select>

              <div class="actions">
                <button id="approve-btn" type="submit">Verify digest, page responder, and seal receipt</button>
                <button id="sync-digest" class="secondary" type="button">Sync digest from proposal</button>
                <button id="tamper-digest" class="danger-btn" type="button">Simulate Tamper Attack (0000...)</button>
              </div>
            </form>

            <div class="card" aria-label="Standby failover and Merkle-sealed receipt">
              <h3>JSM On-Call Verdict &amp; Triple-Encoded Receipt</h3>
              <p id="govern-status" class="summary" role="status" aria-live="polite"></p>
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
          </div>
        </div>
      </section>
    </main>
  </div>
</div>
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
