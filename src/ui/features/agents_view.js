'use strict';

// View 1: The Autonomous Agentic Loop (Split-Pane Screen).
// Left pane: Active card grid of the 4 Argus Autonomous Agents & Daemons with
// static UUIDs, circular pulse indicators, and live Current Goal telemetry.
// Right pane: Streaming monospace Agent Thought & Execution Log Terminal
// rendering real-time JSON execution steps from the domain engine and Forge resolver.

function renderAgentsView() {
  return `
      <!-- VIEW 1: The Autonomous Agentic Loop (Agents + Live Monospace Stream Terminal) -->
      <section id="zone-agents" class="zone-section" aria-label="Autonomous agentic loop and live execution terminal">
        <div class="grid-2col">
          <div class="panel" aria-label="Running autonomous Argus agents">
            <div class="panel-head">
              <h2>View 1 · Autonomous Agentic DevOps Loop</h2>
              <span class="pill pill-cyan"><span class="pulse-dot"></span>4 Active Daemons</span>
            </div>
            <div class="agent-grid">
              <div class="agent-card state-exec" data-agent-uuid="agt-rovo-01">
                <div class="agent-card-top">
                  <span class="agent-name">argus-incident-governor</span>
                  <span id="agent-status-rovo" class="pill pill-cyan"><span class="pulse-dot"></span>ACTIVE</span>
                </div>
                <span class="agent-uuid">uuid: agt-rovo-01 · surface: rovo:agent + rovo:mcp</span>
                <p id="agent-goal-rovo" class="agent-goal">Current Goal: Walking provenance thread DEMO-11 -&gt; deploy-prod-482 -&gt; commit-9f2c41e.</p>
              </div>

              <div class="agent-card state-alert" data-agent-uuid="agt-canary-02">
                <div class="agent-card-top">
                  <span class="agent-name">elenchos-canary-verifier</span>
                  <span id="agent-status-canary" class="pill pill-incident"><span class="pulse-dot"></span>EXIT 1</span>
                </div>
                <span class="agent-uuid">uuid: agt-canary-02 · surface: rovo:skill (r01-r20)</span>
                <p id="agent-goal-canary" class="agent-goal">Current Goal: 13/20 fake-green pipeline rules failing; 5 deterministic YAML repairs synthesized.</p>
              </div>

              <div class="agent-card state-warn" data-agent-uuid="agt-shield-03">
                <div class="agent-card-top">
                  <span class="agent-name">lachesis-policy-shield</span>
                  <span id="agent-status-shield" class="pill pill-warn"><span class="pulse-dot"></span>CONFIRM</span>
                </div>
                <span class="agent-uuid">uuid: agt-shield-03 · surface: PolicyShield + Threefold</span>
                <p id="agent-goal-shield" class="agent-goal">Current Goal: Enforcing SHA-256 TypedChangeIR digest guard before any Jira/Bitbucket write.</p>
              </div>

              <div class="agent-card state-ok" data-agent-uuid="agt-standby-04">
                <div class="agent-card-top">
                  <span class="agent-name">volcan-standby-daemon</span>
                  <span id="agent-status-standby" class="pill pill-live"><span class="pulse-dot"></span>SEALED</span>
                </div>
                <span class="agent-uuid">uuid: agt-standby-04 · surface: StandbyRoster + Aletheia</span>
                <p id="agent-goal-standby" class="agent-goal">Current Goal: Monitoring 900s JSM on-call SLA window and emitting Spoken + Braille Merkle receipts.</p>
              </div>
            </div>
          </div>

          <div class="panel" aria-label="Agent thought and execution log terminal">
            <div class="panel-head">
              <h2>Agent Thought &amp; Execution Log Terminal</h2>
              <span id="bridge-mode-pill" class="pill pill-mono">stream: deterministic + forge-bridge</span>
            </div>
            <div id="agent-log-terminal" class="stream-terminal" role="log" aria-live="polite" aria-label="Live JSON agent execution stream"></div>
          </div>
        </div>
      </section>`.trim();
}

module.exports = { renderAgentsView };
