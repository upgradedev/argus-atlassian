'use strict';

// Client-side runtime controller for the Argus Dark Terminal Command Center.
// Runs all 13 deterministic domain modules in-browser AND wires live Atlassian
// Forge Custom UI bridge calls (globalThis.__bridge.callBridge) to the backend
// resolver (getArgusStatus, traceIncidentProvenance, proposeTypedChange,
// escalateStandbyResponder, evaluatePipeline) when hosted inside Jira / JSM.

function buildRuntimeControllerSource(sampleYaml) {
  return `
(function () {
  const sampleYaml = ${JSON.stringify(sampleYaml)};
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
  const logTerminal = document.getElementById('agent-log-terminal');
  const shield = new ArgusShield.PolicyShield();

  let activeFilter = 'all';
  let logSeq = 0;
  let liveIssueKey = 'DEMO-11';
  let liveAccountId = '';
  let liveAssigneeAccountId = '';
  let liveChangeId = '';

  function hasForgeBridge() {
    return Boolean(
      typeof globalThis.__bridge !== 'undefined'
      && globalThis.__bridge
      && typeof globalThis.__bridge.callBridge === 'function'
    );
  }

  function invokeForgeResolver(functionKey, payload) {
    if (!hasForgeBridge()) return Promise.resolve(null);
    return Promise.resolve(
      globalThis.__bridge.callBridge('invoke', {
        functionKey: functionKey,
        payload: payload || {}
      })
    );
  }

  function appendAgentLog(agent, action, level, details) {
    if (!logTerminal) return;
    logSeq += 1;
    const row = document.createElement('div');
    const cls = level === 'ok' ? 'log-ok' : level === 'warn' ? 'log-warn' : level === 'err' ? 'log-err' : 'log-cyan';
    row.className = 'log-row ' + cls;
    const payload = Object.assign({
      seq: logSeq,
      agent: agent,
      action: action
    }, details || {});
    row.textContent = JSON.stringify(payload);
    logTerminal.appendChild(row);
    if (logTerminal.children && logTerminal.children.length > 24) {
      if (typeof logTerminal.removeChild === 'function') {
        logTerminal.removeChild(logTerminal.children[0]);
      }
    }
  }

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
  appendAgentLog('argus-incident-governor', 'seal-provenance-thread', 'ok', {
    issueKey: 'DEMO-11',
    rootCause: thread.rootCause('DEMO-11').nodeId,
    sealPrefix: thread.seal('DEMO-11').slice(0, 16)
  });

  ArgusRules.RULES.forEach(function (rule) {
    const opt = document.createElement('option');
    opt.value = rule.id;
    opt.textContent = rule.id + ': ' + rule.title;
    ruleSelect.appendChild(opt);
  });

  function updateInspectorDrawer(rule, change) {
    const titleEl = document.getElementById('drawer-rule-title');
    const factEl = document.getElementById('drawer-fact-detail');
    const opsEl = document.getElementById('drawer-rule-ops');
    const badgeEl = document.getElementById('drawer-rule-badge');
    if (titleEl) titleEl.textContent = 'Inspector · ' + rule.id + ': ' + rule.title;
    const repairFacts = ArgusRules.repairFactsForRule(rule.id);
    if (factEl) {
      factEl.textContent = repairFacts.map(function (f) {
        return f.field + ' != ' + f.value + ' (violating state)';
      }).join('; ');
    }
    if (opsEl && change) {
      opsEl.textContent = change.ops.map(function (op) {
        return op.kind + ' ' + op.target + ': ' + op.field + '=' + op.value;
      }).join('; ');
    }
    if (badgeEl) {
      badgeEl.textContent = repairableSet[rule.id] ? 'Auto-Repair Ready' : 'TypedChangeIR Proposal';
    }
  }

  let currentChange = null;
  function syncRemoteProposal(rule, ops, claimId) {
    if (!hasForgeBridge()) return;
    const kvsNode = document.getElementById('topo-kvs-status');
    invokeForgeResolver('proposeTypedChange', {
      issueKey: liveIssueKey,
      ruleId: rule.id,
      proposedBy: liveAccountId || 'dimitris.lagos'
    }).then(function (res) {
      if (res && res.stored && res.changeId) {
        currentChange = new ArgusChange.TypedChangeIR(
          res.changeId,
          'Repair proposal for ' + rule.id + ': ' + rule.title,
          ops,
          { evidenceClaims: [claimId], preventionRule: rule.id }
        );
        liveChangeId = currentChange.changeId;
        const d = res.digest || currentChange.digest();
        document.getElementById('change-id').textContent = currentChange.changeId;
        document.getElementById('change-digest').textContent = d;
        digestInput.value = d;
        if (res.director) document.getElementById('lens-director').textContent = res.director;
        if (res.secops) document.getElementById('lens-secops').textContent = res.secops;
        if (res.standby) document.getElementById('lens-standby').textContent = res.standby;
        if (kvsNode) kvsNode.textContent = 'store: ' + res.changeId + ' (' + (res.storage || 'forge-kvs') + ')';
        appendAgentLog('argus-incident-governor', 'forge-kvs-propose-stored', 'ok', {
          changeId: res.changeId,
          storage: res.storage || 'forge-kvs',
          digestPrefix: String(d).slice(0, 16)
        });
      }
    }).catch(function () {});
  }

  function buildProposal(ruleId, skipRemote) {
    const rule = ArgusRules.ruleById(ruleId);
    const claimId = liveIssueKey + ':' + rule.id;
    const graph = new ArgusEvidence.EvidenceGraph();
    [
      [liveIssueKey + '-data', ArgusEvidence.EvidenceSource.DATA, 'JSM P1 incident ' + liveIssueKey],
      [liveIssueKey + '-identity', ArgusEvidence.EvidenceSource.IDENTITY, 'On-call SRE roster'],
      [liveIssueKey + '-events', ArgusEvidence.EvidenceSource.EVENTS, 'Issue webhook trigger'],
      [liveIssueKey + '-pipeline', ArgusEvidence.EvidenceSource.PIPELINE, 'Bitbucket Pipelines YAML'],
      [liveIssueKey + '-config', ArgusEvidence.EvidenceSource.CONFIG, 'Branch restriction policy'],
      [liveIssueKey + '-logs', ArgusEvidence.EvidenceSource.LOGS, 'Socratic Canary exit log'],
      [liveIssueKey + '-edge', ArgusEvidence.EvidenceSource.EDGE, 'Zero-egress boundary'],
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
      'proposal-' + liveIssueKey + '-' + rule.id + '-1',
      'Repair proposal for ' + rule.id + ': ' + rule.title,
      ops,
      { evidenceClaims: [claimId], preventionRule: rule.id }
    );
    liveChangeId = currentChange.changeId;
    const d = currentChange.digest();
    document.getElementById('change-id').textContent = currentChange.changeId;
    document.getElementById('change-digest').textContent = d;
    document.getElementById('lens-director').textContent = currentChange.renderForRole('director');
    document.getElementById('lens-secops').textContent = currentChange.renderForRole('secops');
    document.getElementById('lens-standby').textContent = currentChange.renderForRole('standby');
    digestInput.value = d;
    updateInspectorDrawer(rule, currentChange);

    const kvsNode = document.getElementById('topo-kvs-status');
    if (kvsNode) kvsNode.textContent = 'store: ' + currentChange.changeId;
    const shieldGoal = document.getElementById('agent-goal-shield');
    if (shieldGoal) {
      shieldGoal.textContent = 'Current Goal: Guarding ' + currentChange.changeId + ' (digest ' + d.slice(0, 12) + '...).';
    }
    appendAgentLog('lachesis-policy-shield', 'compile-typed-change-ir', 'cyan', {
      changeId: currentChange.changeId,
      ruleId: rule.id,
      triage: triage,
      digestPrefix: d.slice(0, 16)
    });

    if (!skipRemote) {
      syncRemoteProposal(rule, ops, claimId);
    }
  }

  function executeGovernance(triggerLiveWrite) {
    if (!currentChange) buildProposal(ruleSelect.value || 'r01');
    const suppliedDigest = digestInput.value.trim();
    const kpiSla = document.getElementById('kpi-sla-timer');
    const kpiSlaSub = document.getElementById('kpi-sla-sub');
    const standbyBadge = document.getElementById('agent-status-standby');
    const standbyGoal = document.getElementById('agent-goal-standby');
    const topoSre = document.getElementById('topo-sre-status');
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
      if (standbyBadge) {
        standbyBadge.className = 'pill pill-incident';
        standbyBadge.textContent = 'BLOCKED';
      }
      if (standbyGoal) {
        standbyGoal.textContent = 'Current Goal: Write refused by verifyBeforeWrite digest mismatch guard.';
      }
      appendAgentLog('lachesis-policy-shield', 'verify-before-write', 'err', {
        changeId: currentChange.changeId,
        verdict: 'refused-digest-mismatch'
      });
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
    if (standbyBadge) {
      standbyBadge.className = 'pill pill-live';
      standbyBadge.textContent = pageOutcome.escalated ? 'FAILOVER' : 'SEALED';
    }
    if (standbyGoal) {
      standbyGoal.textContent = 'Current Goal: Paged ' + pageOutcome.paged.name + ' (Merkle root ' + receipt.root.slice(0, 12) + '...).';
    }
    if (topoSre) {
      topoSre.textContent = 'active: ' + pageOutcome.paged.name;
    }
    appendAgentLog('volcan-standby-daemon', 'seal-merkle-receipt', 'ok', {
      changeId: currentChange.changeId,
      paged: pageOutcome.paged.engineerId,
      escalated: pageOutcome.escalated,
      merkleRootPrefix: receipt.root.slice(0, 16)
    });

    if (triggerLiveWrite && hasForgeBridge()) {
      const targetAccount = liveAssigneeAccountId || liveAccountId || pageOutcome.paged.engineerId;
      invokeForgeResolver('escalateStandbyResponder', {
        issueKey: liveIssueKey,
        changeId: liveChangeId || currentChange.changeId,
        approvalDigest: suppliedDigest,
        elapsedSeconds: elapsed,
        standbyAccountId: targetAccount,
        approvedBy: liveAccountId || 'dimitris.lagos'
      }).then(function (res) {
        if (!res) return;
        if (res.status === 'executed' || res.status === 'verified-dry-run' || res.status === 'verified') {
          governStatus.className = 'summary pass';
          governStatus.textContent =
            'Digest verified against ' + (res.changeId || currentChange.changeId)
            + ' (' + res.status + '). '
            + (res.assignedTo ? 'Assigned issue ' + (res.issueKey || liveIssueKey) + ' to ' + res.assignedTo + '. ' : '')
            + 'Merkle receipt sealed.';
          if (res.receipt) {
            if (res.receipt.spoken) receiptSpoken.textContent = res.receipt.spoken;
            if (res.receipt.braille) receiptBraille.textContent = res.receipt.braille;
            if (res.receipt.plainText) receiptPlain.textContent = res.receipt.plainText;
          }
          appendAgentLog('volcan-standby-daemon', 'forge-escalate-responder', 'ok', {
            status: res.status,
            issueKey: res.issueKey || liveIssueKey,
            assignedTo: res.assignedTo || targetAccount,
            executed: Boolean(res.executed)
          });
        } else if (res.status === 'refused') {
          appendAgentLog('volcan-standby-daemon', 'forge-escalate-refused', 'warn', {
            reason: res.reason || 'refused'
          });
        }
      }).catch(function () {});
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
        executeGovernance(false);
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

    const canaryStatus = document.getElementById('agent-status-canary');
    if (canaryStatus) {
      canaryStatus.className = out.clean ? 'pill pill-live' : 'pill pill-incident';
      canaryStatus.textContent = out.clean ? 'EXIT 0' : 'EXIT 1 (' + failing + ')';
    }
    const canaryGoal = document.getElementById('agent-goal-canary');
    if (canaryGoal) {
      canaryGoal.textContent = out.clean
        ? 'Current Goal: All 20 Elenchos rules passing (exit 0).'
        : 'Current Goal: ' + failing + '/20 fake-green pipeline rules failing; deterministic repair ready.';
    }
    const topoPipeStatus = document.getElementById('topo-pipeline-status');
    if (topoPipeStatus) {
      topoPipeStatus.textContent = out.clean
        ? 'verdict: exit 0 (20/20 pass)'
        : 'verdict: exit 1 (' + failing + ' fail)';
    }
    const topoPipeNode = document.getElementById('topo-pipeline-node');
    if (topoPipeNode) {
      topoPipeNode.className = out.clean ? 'topo-node node-ok' : 'topo-node node-crit';
    }

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
    appendAgentLog('elenchos-canary-verifier', 'evaluate-pipeline-facts', out.clean ? 'ok' : 'warn', {
      passing: passing,
      failing: failing,
      verdict: out.clean ? 'exit-0' : 'exit-1'
    });
  }

  function applyDeterministicRepairs() {
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
    appendAgentLog('elenchos-canary-verifier', 'apply-deterministic-repairs', 'ok', {
      applied: result.applied,
      remaining: result.unsupported.length
    });
    render();
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    render();
    if (hasForgeBridge()) {
      invokeForgeResolver('evaluatePipeline', { pipelineYaml: input.value })
        .then(function (res) {
          if (res && res.evaluation) {
            appendAgentLog('elenchos-canary-verifier', 'forge-evaluate-pipeline', 'ok', {
              status: res.status,
              violations: res.evaluation.violations.length
            });
          }
        })
        .catch(function () {});
    }
  });
  repair.addEventListener('click', applyDeterministicRepairs);
  seedReset.addEventListener('click', function () {
    input.value = sampleYaml;
    repairSummary.textContent = 'Loaded synthetic JSM P1 incident ' + liveIssueKey + ' and fake-green Bitbucket pipeline.';
    ruleSelect.value = 'r01';
    buildProposal('r01');
    executeGovernance(false);
    render();
  });
  ruleSelect.addEventListener('change', function () {
    buildProposal(ruleSelect.value);
    executeGovernance(false);
  });
  syncDigestBtn.addEventListener('click', function () {
    if (currentChange) digestInput.value = currentChange.digest();
    executeGovernance(false);
  });
  if (tamperDigestBtn) {
    tamperDigestBtn.addEventListener('click', function () {
      digestInput.value = '0000000000000000000000000000000000000000000000000000000000000000';
      executeGovernance(false);
    });
  }
  const drawerPatchBtn = document.getElementById('drawer-patch-btn');
  if (drawerPatchBtn) {
    drawerPatchBtn.addEventListener('click', applyDeterministicRepairs);
  }
  const drawerOverrideBtn = document.getElementById('drawer-override-btn');
  if (drawerOverrideBtn) {
    drawerOverrideBtn.addEventListener('click', function () {
      digestInput.value = '0000000000000000000000000000000000000000000000000000000000000000';
      executeGovernance(false);
    });
  }
  const isolateNodeBtn = document.getElementById('action-isolate-node');
  if (isolateNodeBtn) {
    isolateNodeBtn.addEventListener('click', function () {
      activeFilter = 'fail';
      render();
    });
  }
  const autoPatchBtn = document.getElementById('action-auto-patch');
  if (autoPatchBtn) {
    autoPatchBtn.addEventListener('click', applyDeterministicRepairs);
  }
  const scaleFailoverBtn = document.getElementById('action-scale-failover');
  if (scaleFailoverBtn) {
    scaleFailoverBtn.addEventListener('click', function () {
      elapsedSelect.value = '960';
      executeGovernance(true);
    });
  }

  elapsedSelect.addEventListener('change', function () {
    executeGovernance(false);
  });
  governForm.addEventListener('submit', function (e) {
    e.preventDefault();
    executeGovernance(true);
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

  const zones = ['zone-agents', 'zone-posture', 'zone-workbench', 'zone-provenance', 'zone-governance'];
  [
    ['nav-all', 'all'],
    ['nav-agents', 'zone-agents'],
    ['nav-posture', 'zone-posture'],
    ['nav-workbench', 'zone-workbench'],
    ['nav-provenance', 'zone-provenance'],
    ['nav-governance', 'zone-governance']
  ].forEach(function (pair) {
    const btn = document.getElementById(pair[0]);
    if (btn) {
      btn.addEventListener('click', function () {
        ['nav-all', 'nav-agents', 'nav-posture', 'nav-workbench', 'nav-provenance', 'nav-governance'].forEach(function (id) {
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

  buildProposal('r01', true);
  executeGovernance(false);
  render();

  // 1. Legacy test/status hook (__argusBridgeInvoke)
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

  // 2. Full Live Atlassian Forge Custom UI Bridge (globalThis.__bridge.callBridge)
  if (hasForgeBridge()) {
    Promise.resolve(globalThis.__bridge.callBridge('getContext'))
      .then(function (ctx) {
        if (ctx && typeof ctx === 'object') {
          if (ctx.accountId) liveAccountId = String(ctx.accountId);
          const extKey = ctx.extension && ctx.extension.issue && ctx.extension.issue.key;
          if (extKey) liveIssueKey = String(extKey);
          if (ctx.siteUrl) {
            const tenantEl = document.getElementById('telem-tenant');
            if (tenantEl) tenantEl.textContent = String(ctx.siteUrl).replace(/^https?:\\/\\//, '');
          }
        }
        return invokeForgeResolver('getArgusStatus', {});
      })
      .then(function (statusRes) {
        if (statusRes && runtimeStatus) {
          runtimeStatus.textContent =
            'Status: connected to live Forge resolver (' + (statusRes.status || 'live-ready')
            + ', storage: ' + (statusRes.planStorage || 'forge-kvs')
            + ', rules accepted: ' + (statusRes.rulesAccepted || '20/20')
            + ', issue: ' + liveIssueKey + ').';
          const storeEl = document.getElementById('telem-store');
          if (storeEl && statusRes.planStorage) storeEl.textContent = statusRes.planStorage;
          const modePill = document.getElementById('bridge-mode-pill');
          if (modePill) modePill.textContent = 'stream: live-forge-resolver (' + (statusRes.status || 'live') + ')';
          appendAgentLog('argus-incident-governor', 'forge-status-connected', 'ok', {
            status: statusRes.status,
            storage: statusRes.planStorage,
            issueKey: liveIssueKey
          });
        }
        return invokeForgeResolver('traceIncidentProvenance', { issueKey: liveIssueKey });
      })
      .then(function (provRes) {
        if (provRes && (provRes.status === 'partial-live' || provRes.status === 'live')) {
          const ev = provRes.evidence || {};
          if (ev['issue.assignee']) liveAssigneeAccountId = ev['issue.assignee'];
          const topIncident = document.getElementById('topbar-incident-pill');
          if (topIncident) {
            topIncident.textContent = 'JSM · ' + (provRes.issueKey || liveIssueKey)
              + (ev['issue.status'] ? ' (' + ev['issue.status'] + ')' : '');
          }
          const telemInc = document.getElementById('telem-incident');
          if (telemInc) telemInc.textContent = (provRes.issueKey || liveIssueKey) + (ev['issue.priority'] ? ' (' + ev['issue.priority'] + ')' : '');
          const node3Id = document.getElementById('prov-node-3-id');
          if (node3Id) node3Id.textContent = provRes.issueKey || liveIssueKey;
          const node3Actor = document.getElementById('prov-node-3-actor');
          if (node3Actor) {
            node3Actor.textContent = 'Assignee: ' + (ev['issue.assignee'] || 'unassigned')
              + (ev['issue.updated'] ? ' · ' + ev['issue.updated'] : '');
          }
          const node3Sum = document.getElementById('prov-node-3-summary');
          if (node3Sum && ev['issue.summary']) node3Sum.textContent = ev['issue.summary'];
          const topoIncId = document.getElementById('topo-incident-id');
          if (topoIncId) topoIncId.textContent = 'key: ' + (provRes.issueKey || liveIssueKey);
          const topoIncStatus = document.getElementById('topo-incident-status');
          if (topoIncStatus && ev['issue.status']) {
            topoIncStatus.textContent = 'status: ' + ev['issue.status'] + ' · SLA: 900s';
          }
          if (Array.isArray(provRes.walkBack) && provRes.walkBack.length) {
            document.getElementById('prov-chain').textContent = provRes.walkBack.join(' -> ');
          }
          if (provRes.seal) {
            document.getElementById('prov-seal').textContent = provRes.seal;
          }
          const rovoGoal = document.getElementById('agent-goal-rovo');
          if (rovoGoal) {
            rovoGoal.textContent = 'Current Goal: Live Jira issue ' + (provRes.issueKey || liveIssueKey)
              + ' traced (' + (ev['issue.summary'] || 'connected') + ').';
          }
          appendAgentLog('argus-incident-governor', 'forge-trace-provenance', 'ok', {
            status: provRes.status,
            issueKey: provRes.issueKey || liveIssueKey,
            summary: ev['issue.summary'] || '',
            sealPrefix: String(provRes.seal || '').slice(0, 16)
          });
        }
        buildProposal(ruleSelect.value || 'r01');
      })
      .catch(function () {});
  }
})();
`;
}

module.exports = { buildRuntimeControllerSource };
