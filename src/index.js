'use strict';

// Thin Forge adapter. This is the ONLY layer that imports Forge SDKs, and
// it does so lazily through adapters/forge_client.js: where @forge/api is
// not installed (this dev machine, unit tests) the client is null and the
// handlers fall back to a clearly labelled synthetic seed (TRAPS.md T1).
// Where the payload itself carries pipeline YAML, the real Elenchos rules
// r01-r20 evaluate it directly. A response says which of the three it is:
// live, evaluated-input, or seed-demo. Nothing blurs them.
//
// Every export name below is referenced by a `function` module in
// manifest.yml. scripts/check_manifest.py proves the two lists match.

const {
  ArgusError,
  CanaryFixture,
  ProvenanceNode,
  ProvenanceThread,
  evaluateRules,
  extractPipelineFacts,
  repairPipelineYaml,
  ruleById,
  validateAllRules,
} = require('./argus/index.js');
const { InMemoryEvaluator } = require('./argus/adapters/in_memory.js');
const {
  AtlassianReader,
  AtlassianWriter,
} = require('./adapters/atlassian.js');
const { makeForgeClient } = require('./adapters/forge_client.js');
const { makeForgePlanStore, InMemoryPlanStore } = require('./adapters/plan_store.js');
const { createGovernance } = require('./governance.js');
const { parseIssueKey } = require('./forge_events.js');
const { makeResolverHandler } = require('./resolver.js');

const forgeClient = makeForgeClient();
const reader = forgeClient ? new AtlassianReader(forgeClient) : null;
const writer = forgeClient ? new AtlassianWriter(forgeClient) : null;
const planStore = makeForgePlanStore() ?? new InMemoryPlanStore();
const governance = createGovernance({
  store: planStore,
  writer,
  storageMode: planStore.mode,
});

const NOT_CONNECTED = 'not-connected: @forge/api unavailable in this runtime';

// Production observability without payload leakage: status words and
// counts only, and only inside the real Forge runtime so local tests
// stay quiet. Forge logs are the UAT evidence surface for triggers.
function logOutcome(handler, outcome) {
  if (typeof globalThis.__forge_fetch__ === 'function') {
    console.info(`argus ${handler} ${outcome}`);
  }
}

function findField(value, field, depth = 0) {
  if (depth > 3 || value === null || typeof value !== 'object') return '';
  if (typeof value[field] === 'string') return value[field];
  for (const child of Object.values(value)) {
    const found = findField(child, field, depth + 1);
    if (found) return found;
  }
  return '';
}

function findValue(value, field, depth = 0) {
  if (depth > 3 || value === null || typeof value !== 'object') return undefined;
  if (value[field] !== undefined) return value[field];
  for (const child of Object.values(value)) {
    const found = findValue(child, field, depth + 1);
    if (found !== undefined) return found;
  }
  return undefined;
}

function issueKeyFrom(args) {
  return findField(args, 'issueKey') || parseIssueKey(...args);
}

function seedCanary() {
  // Synthetic seed only. The badge says green in both states; the check
  // ignores the badge and reads the test exit code, so it separates the
  // fake-green fixture (exit 1) from the clean one (exit 0).
  const violating = new CanaryFixture(
    'seed-violating', { 'pipeline.badge': 'green', 'tests.exit': '1' }, false,
  );
  const clean = new CanaryFixture(
    'seed-clean', { 'pipeline.badge': 'green', 'tests.exit': '0' }, true,
  );
  const evaluator = new InMemoryEvaluator(violating, clean);
  const result = evaluator.runCanary('seed-demo-check', (s) => s['tests.exit'] === '0');
  return {
    syntheticSeed: true,
    candidateId: result.candidateId,
    violatingExit: result.violatingExit,
    cleanExit: result.cleanExit,
    accepted: result.accepted,
    reason: result.reason,
  };
}

function refused(err) {
  return { status: 'refused', error: err.name, reason: err.message, executed: false };
}

function evaluationSummary(evaluation) {
  return {
    clean: evaluation.clean,
    violations: [...evaluation.violations],
    results: evaluation.results.map((r) => ({ id: r.id, title: r.title, clean: r.clean })),
  };
}

async function getArgusStatus() {
  const validation = validateAllRules();
  return {
    status: reader ? 'live-ready' : 'seed-demo',
    liveEvidence: reader ? 'connected' : NOT_CONNECTED,
    planStorage: planStore.mode,
    rulesAccepted: `${validation.accepted}/${validation.total}`,
    canary: seedCanary(),
  };
}

async function evaluatePipeline(req = {}) {
  const payload = req.payload ?? req;
  const yaml = typeof payload.pipelineYaml === 'string' ? payload.pipelineYaml : '';
  const facts = extractPipelineFacts(yaml);
  return {
    status: yaml ? 'evaluated-input' : 'evaluated-empty-input',
    facts,
    evaluation: evaluationSummary(evaluateRules(facts)),
    repair: yaml ? repairPipelineYaml(yaml) : null,
  };
}

async function getProposalStatus(req = {}) {
  const payload = req.payload ?? req;
  const issueKey = payload.issueKey ?? req.context?.extension?.issue?.key ?? '';
  const changeId = payload.changeId ?? '';
  return governance.getProposal({ issueKey, changeId });
}

async function onIssueEvent(...args) {
  const issueKey = issueKeyFrom(args);
  if (reader && issueKey) {
    const evidence = await reader.fetchEvidence(issueKey);
    logOutcome('onIssueEvent', `live ${issueKey}`);
    return { status: 'live', issueKey, evidence, links: [] };
  }
  logOutcome('onIssueEvent', 'seed-demo');
  return { status: 'seed-demo', liveEvidence: NOT_CONNECTED, links: [] };
}

async function runCanaryKillTest(...args) {
  const issueKey = issueKeyFrom(args);
  const yaml = findField(args, 'pipelineYaml');
  if (yaml) {
    const facts = extractPipelineFacts(yaml);
    const evaluation = evaluateRules(facts);
    logOutcome('runCanaryKillTest', `evaluated-input violations=${evaluation.violations.length}`);
    return {
      status: 'evaluated-input',
      issueKey,
      facts,
      evaluation: evaluationSummary(evaluation),
      repair: repairPipelineYaml(yaml),
      canary: seedCanary(),
    };
  }
  return {
    status: 'seed-demo',
    issueKey,
    liveEvidence: NOT_CONNECTED,
    canary: seedCanary(),
  };
}

async function traceIncidentProvenance(...args) {
  const issueKey = issueKeyFrom(args);
  if (reader && issueKey) {
    try {
      const evidence = await reader.fetchEvidence(issueKey);
      const linkedWork = await reader.fetchLinkedWork(issueKey);
      const thread = new ProvenanceThread();
      thread.add(new ProvenanceNode(
        issueKey, 'incident',
        evidence['issue.summary'] || issueKey,
        evidence['issue.assignee'] || 'unassigned',
        evidence['issue.updated'] || '',
      ));
      logOutcome('traceIncidentProvenance', `partial-live ${issueKey}`);
      return {
        status: 'partial-live',
        issueKey,
        evidence,
        linkedWork,
        walkBack: thread.walkBack(issueKey).map((n) => n.nodeId),
        rootCause: '',
        seal: thread.seal(issueKey),
        note: 'incident and linked work are live; links are association, not causality',
      };
    } catch (err) {
      return {
        status: 'seed-demo', issueKey, liveEvidence: NOT_CONNECTED,
        liveError: err.message, walkBack: [], rootCause: '', seal: '',
      };
    }
  }
  // Synthetic thread so the seal machinery is evaluable on an empty site.
  const thread = new ProvenanceThread();
  thread.add(new ProvenanceNode('seed-commit', 'commit', 'seed commit', 'seed', '2026-11-03T00:00:00Z'));
  thread.add(new ProvenanceNode('seed-pipeline', 'deploy', 'seed pipeline run', 'seed', '2026-11-03T01:00:00Z', 'seed-commit'));
  thread.add(new ProvenanceNode('seed-incident', 'incident', 'seed incident', 'seed', '2026-11-03T02:00:00Z', 'seed-pipeline'));
  return {
    status: 'seed-demo',
    syntheticSeed: true,
    issueKey,
    liveEvidence: NOT_CONNECTED,
    walkBack: thread.walkBack('seed-incident').map((n) => n.nodeId),
    rootCause: thread.rootCause('seed-incident').nodeId,
    seal: thread.seal('seed-incident'),
  };
}

async function proposeTypedChange(...args) {
  try {
    const issueKey = issueKeyFrom(args);
    const ruleId = findField(args, 'ruleId');
    if (!issueKey) {
      return { status: 'refused', reason: 'issueKey input is required', executed: false };
    }
    if (!ruleId) {
      return { status: 'refused', reason: 'ruleId input is required', executed: false };
    }
    const rule = ruleById(ruleId); // unknown rule ids refuse here
    const proposal = await governance.propose({
      issueKey,
      ruleId,
      proposedBy: findField(args, 'proposedBy') || findField(args, 'accountId'),
    });
    logOutcome('proposeTypedChange', `${proposal.changeId}`);
    return {
      status: planStore.mode === 'forge-kvs' ? 'proposal-stored' : 'proposal-only',
      stored: true,
      storage: planStore.mode,
      rule: { id: rule.id, title: rule.title },
      executed: false,
      changeId: proposal.changeId,
      digest: proposal.digest,
      director: proposal.director,
      secops: proposal.secops,
      standby: proposal.standby,
    };
  } catch (err) {
    if (err instanceof ArgusError) return refused(err);
    throw err;
  }
}

async function escalateStandbyResponder(...args) {
  // Governed write. Governance verifies the human digest against the
  // stored Typed Change IR before the writer can run. In Forge the store
  // is KVS; in local tests it is an ephemeral Map and results name that.
  const result = await governance.approveAndEscalate({
    issueKey: issueKeyFrom(args),
    changeId: findField(args, 'changeId'),
    approvalDigest: findField(args, 'approvalDigest'),
    standbyAccountId: findField(args, 'standbyAccountId'),
    roster: findValue(args, 'roster') ?? findValue(args, 'engineers') ?? null,
    elapsedSeconds: Number(findValue(args, 'elapsedSeconds') ?? 0),
    approvedBy: findField(args, 'approvedBy') || findField(args, 'accountId'),
  });
  logOutcome('escalateStandbyResponder', `${result.status} executed=${result.executed === true}`);
  return result;
}

exports.resolver = makeResolverHandler({
  getArgusStatus,
  evaluatePipeline,
  getProposalStatus,
});
exports.onIssueEvent = onIssueEvent;
exports.runCanaryKillTest = runCanaryKillTest;
exports.traceIncidentProvenance = traceIncidentProvenance;
exports.proposeTypedChange = proposeTypedChange;
exports.escalateStandbyResponder = escalateStandbyResponder;
