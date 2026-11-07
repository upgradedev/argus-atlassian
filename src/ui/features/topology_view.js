'use strict';

// View 2: Dark Factory Infrastructure Topology, DevSecOps Posture & 7-Source Provenance.
// Includes the 5-card Executive KPI Ribbon, 4-stage pipeline health bars,
// live Atlassian Dark Factory node topology with global action triggers,
// and the SHA-256 sealed SupportTrace 7-source provenance graph.

function renderTopologyView() {
  return `
      <!-- VIEW 2A: DevSecOps Posture, Dark Factory Topology & Stage Analytics -->
      <section id="zone-posture" class="zone-section" aria-label="DevSecOps posture metrics, dark factory topology, and stage breakdown">
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
            <div id="kpi-evidence-count" class="kpi-value">7/7 Sources</div>
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

        <div class="panel" aria-label="Dark factory live node topology">
          <div class="panel-head">
            <h2>View 2 · Dark Factory &amp; Atlassian Node Topology</h2>
            <div class="actions">
              <button id="action-isolate-node" class="danger-btn" type="button">Isolate Compromised Node</button>
              <button id="action-auto-patch" type="button">Approve Auto-Patch (5 Rules)</button>
              <button id="action-scale-failover" class="secondary" type="button">Scale Cluster / Failover SRE</button>
            </div>
          </div>
          <div class="topology-nodes" aria-label="Headless autonomous service topology">
            <div class="topo-node node-cyan">
              <span class="topo-title">1. Bitbucket Commit</span>
              <span id="topo-commit-id" class="topo-metric">sha: commit-9f2c41e</span>
              <span class="topo-metric">branch: main · depth: 1</span>
            </div>
            <div id="topo-pipeline-node" class="topo-node node-crit">
              <span class="topo-title">2. Pipeline Runner #482</span>
              <span id="topo-pipeline-status" class="topo-metric">verdict: exit 1 (13 fail)</span>
              <span class="topo-metric">mem: 4096 MB · timeout: 10m</span>
            </div>
            <div class="topo-node node-crit">
              <span class="topo-title">3. JSM Incident Gate</span>
              <span id="topo-incident-id" class="topo-metric">key: DEMO-11 (P1)</span>
              <span id="topo-incident-status" class="topo-metric">status: Open · SLA: 900s</span>
            </div>
            <div class="topo-node node-ok">
              <span class="topo-title">4. SupportTrace Graph</span>
              <span id="topo-evidence-status" class="topo-metric">sources: 7/7 grounded</span>
              <span class="topo-metric">egress: 0 external hosts</span>
            </div>
            <div class="topo-node node-warn">
              <span class="topo-title">5. Forge KVS Vault</span>
              <span id="topo-kvs-status" class="topo-metric">store: proposal-DEMO-11</span>
              <span class="topo-metric">guard: SHA-256 verifyBeforeWrite</span>
            </div>
            <div class="topo-node node-ok">
              <span class="topo-title">6. On-Call SRE Node</span>
              <span id="topo-sre-status" class="topo-metric">active: Dimitris Lagos</span>
              <span class="topo-metric">receipt: Spoken + Braille</span>
            </div>
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

      <!-- VIEW 2B: Provenance Thread, 7-Source SupportTrace & PolicyShield -->
      <section id="zone-provenance" class="zone-section" aria-label="Incident provenance and evidence graph">
        <div class="panel" aria-label="Provenance thread for incident DEMO-11">
          <div class="panel-head">
            <h2>Incident Provenance Graph, 7-Source Evidence &amp; PolicyShield Guardrail</h2>
            <span class="pill pill-live">SHA-256 Sealed Chain</span>
          </div>

          <div class="prov-nodes-grid" aria-label="Provenance nodes from commit to incident">
            <div class="prov-node-card">
              <span class="prov-node-type">1. Offending Commit (Root Cause)</span>
              <span id="prov-node-1-id" class="prov-node-id">commit-9f2c41e</span>
              <span class="prov-node-meta">Actor: dev-alex · 2026-11-05T03:20:00Z</span>
              <span class="prov-node-meta">Mask npm test exit code in bitbucket-pipelines.yml</span>
            </div>
            <div class="prov-node-card">
              <span class="prov-node-type">2. Fake-Green Pipeline Run</span>
              <span id="prov-node-2-id" class="prov-node-id">deploy-prod-482</span>
              <span class="prov-node-meta">Actor: bitbucket-pipelines · 2026-11-05T03:25:00Z</span>
              <span class="prov-node-meta">Bitbucket Pipeline #482 reported green</span>
            </div>
            <div class="prov-node-card">
              <span class="prov-node-type">3. JSM Production Outage</span>
              <span id="prov-node-3-id" class="prov-node-id">DEMO-11</span>
              <span id="prov-node-3-actor" class="prov-node-meta">Actor: jsm-trigger · 2026-11-05T03:32:24Z</span>
              <span id="prov-node-3-summary" class="prov-node-meta">JSM P1 checkout outage after green release</span>
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
      </section>`.trim();
}

module.exports = { renderTopologyView };
