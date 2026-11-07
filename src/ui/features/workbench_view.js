'use strict';

// View 3: DevSecOps Deep-Dive, Code Diff Overlay, Slide-Out Rule Inspector Drawer,
// and Cryptographic Governance Vault (Typed Change IR + Standby Failover + Braille Receipt).

function escapeHtml(text) {
  return String(text).replaceAll('&', '&amp;').replaceAll('<', '&lt;');
}

function renderWorkbenchView(sampleYaml) {
  return `
      <!-- VIEW 3A: DevSecOps Deep-Dive, Code Diff & 20-Rule Matrix -->
      <section id="zone-workbench" class="zone-section" aria-label="Pipeline editor, deterministic repair diff, and rule results">
        <div class="workbench-grid">
          <div class="panel">
            <div class="panel-head">
              <h2>View 3 · Bitbucket Pipeline Canary Workbench</h2>
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
                <textarea id="yaml" name="yaml" spellcheck="false">${escapeHtml(sampleYaml)}</textarea>
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

            <!-- Slide-Out Security Event & Rule Inspector Drawer -->
            <div id="rule-inspector-drawer" class="inspector-drawer" aria-label="Security event details and agent override drawer">
              <div class="panel-head">
                <h3 id="drawer-rule-title">Inspector · r01: Masked test exit code</h3>
                <span id="drawer-rule-badge" class="pill pill-cyan">TypedChangeIR Ready</span>
              </div>
              <div class="inspector-grid">
                <div>
                  <dt>Detected Vulnerability / Pipeline Fact</dt>
                  <dd id="drawer-fact-detail" class="mono">test.masked_exit = true (bitbucket-pipelines.yml)</dd>
                </div>
                <div>
                  <dt>Autonomous Agent Proposed Fix (TypedChangeIR)</dt>
                  <dd id="drawer-rule-ops" class="mono">SET_CONFIG bitbucket-pipelines.yml: test.masked_exit=false</dd>
                </div>
              </div>
              <div class="actions">
                <button id="drawer-patch-btn" type="button">Approve &amp; Apply Deterministic Fix</button>
                <button id="drawer-override-btn" class="danger-btn" type="button">Override Agent (Tamper Digest Block)</button>
              </div>
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

      <!-- VIEW 3B: Typed Change IR, Fail-Closed Digest Gate, Standby SLA & Braille Receipt -->
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
      </section>`.trim();
}

module.exports = { renderWorkbenchView, escapeHtml };
