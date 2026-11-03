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
  ChangeOp,
  OpKind,
  TypedChangeIR,
  ProvenanceNode,
  ProvenanceThread,
  Engineer,
  StandbyRoster,
  evaluateRules,
  extractPipelineFacts,
  ruleById,
  validateAllRules,
} = require('./argus/index.js');
const { InMemoryEvaluator } = require('./argus/adapters/in_memory.js');
const { AtlassianReader, buildScorecardPayload } = require('./adapters/atlassian.js');
const { makeForgeClient } = require('./adapters/forge_client.js');

const forgeClient = makeForgeClient();
const reader = forgeClient ? new AtlassianReader(forgeClient) : null;

const NOT_CONNECTED = 'not-connected: @forge/api unavailable in this runtime';

function findField(value, field, depth = 0) {
  if (depth > 3 || value === null || typeof value !== 'object') return '';
  if (typeof value[field] === 'string') return value[field];
  for (const child of Object.values(value)) {
    const found = findField(child, field, depth + 1);
    if (found) return found;
  }
  return '';
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

async function liveEvaluation(args) {
  // Returns null when no live route exists, so callers can fall through to
  // evaluated-input, then seed, in that order. Never fabricates ids.
  if (!reader) return null;
  const workspaceId = findField(args, 'workspaceId') || findField(args, 'uuid');
  const repoId = findField(args, 'repoId') || findField(args, 'repositoryUuid');
  const pullRequestId = findField(args, 'pullRequestId');
  if (!workspaceId || !repoId || !pullRequestId) return null;
  const pr = await forgeClient.getPullRequest(workspaceId, repoId, pullRequestId);
  const commit = pr?.source?.commit?.hash;
  if (!commit) return null;
  return reader.fetchPipelineEvaluation(workspaceId, repoId, commit);
}

async function resolver() {
  const validation = validateAllRules();
  return {
    status: reader ? 'live-ready' : 'seed-demo',
    liveEvidence: reader ? 'connected' : NOT_CONNECTED,
    rulesAccepted: `${validation.accepted}/${validation.total}`,
    canary: seedCanary(),
  };
}

async function socraticCanaryMergeCheck(...args) {
  try {
    const live = await liveEvaluation(args);
    if (live) {
      return {
        status: 'live',
        // The documented merge check response payload shape is applied by
        // the Forge runtime layer; this object is what our panel renders.
        // It is labelled until exercised on the owner dev site.
        responseContract: 'unverified-until-dev-site',
        evaluation: evaluationSummary(live.evaluation),
      };
    }
  } catch (err) {
    return { status: 'seed-demo', liveEvidence: NOT_CONNECTED, liveError: err.message, canary: seedCanary() };
  }
  return { status: 'seed-demo', liveEvidence: NOT_CONNECTED, canary: seedCanary() };
}

async function compassDataProvider(...args) {
  const yaml = findField(args, 'pipelineYaml');
  const evaluation = yaml ? evaluateRules(extractPipelineFacts(yaml)) : evaluateRules({});
  return {
    status: yaml ? 'evaluated-input' : 'seed-demo',
    liveEvidence: reader ? 'connected' : NOT_CONNECTED,
    scorecard: buildScorecardPayload(evaluation),
    metricsEmitted: 0, // becomes real when the Compass adapter send lands
  };
}

async function compassDataProviderCallback() {
  return { status: 'seed-demo', liveEvidence: NOT_CONNECTED, metricsEmitted: 0 };
}

async function onIssueEvent(...args) {
  const issueKey = findField(args, 'issueKey');
  if (reader && issueKey) {
    const evidence = await reader.fetchEvidence(issueKey);
    return { status: 'live', issueKey, evidence, links: [] };
  }
  return { status: 'seed-demo', liveEvidence: NOT_CONNECTED, links: [] };
}

async function runCanaryKillTest(...args) {
  const issueKey = findField(args, 'issueKey');
  const yaml = findField(args, 'pipelineYaml');
  try {
    const live = await liveEvaluation(args);
    if (live) {
      return {
        status: 'live', issueKey,
        evaluation: evaluationSummary(live.evaluation),
        canary: seedCanary(),
      };
    }
  } catch (err) {
    return {
      status: 'seed-demo', issueKey, liveEvidence: NOT_CONNECTED,
      liveError: err.message, canary: seedCanary(),
    };
  }
  if (yaml) {
    const facts = extractPipelineFacts(yaml);
    return {
      status: 'evaluated-input',
      issueKey,
      facts,
      evaluation: evaluationSummary(evaluateRules(facts)),
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
  const issueKey = findField(args, 'issueKey');
  if (reader && issueKey) {
    try {
      const evidence = await reader.fetchEvidence(issueKey);
      const thread = new ProvenanceThread();
      thread.add(new ProvenanceNode(
        issueKey, 'incident',
        evidence['issue.summary'] || issueKey,
        evidence['issue.assignee'] || 'unassigned',
        evidence['issue.updated'] || '',
      ));
      return {
        status: 'partial-live',
        issueKey,
        evidence,
        walkBack: thread.walkBack(issueKey).map((n) => n.nodeId),
        rootCause: '',
        seal: thread.seal(issueKey),
        note: 'only the incident node is live; commit and pipeline links need the Bitbucket link walk',
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
    issueKey: findField(args, 'issueKey'),
    liveEvidence: NOT_CONNECTED,
    walkBack: thread.walkBack('seed-incident').map((n) => n.nodeId),
    rootCause: thread.rootCause('seed-incident').nodeId,
    seal: thread.seal('seed-incident'),
  };
}

async function proposeTypedChange(...args) {
  try {
    const ruleId = findField(args, 'ruleId');
    if (!ruleId) {
      return { status: 'refused', reason: 'ruleId input is required', executed: false };
    }
    const rule = ruleById(ruleId); // unknown rule ids refuse here
    const change = new TypedChangeIR(
      `proposal-${ruleId}`,
      `Repair proposal for ${rule.id}: ${rule.title}`,
      [new ChangeOp(OpKind.NOTIFY, `argus/rule/${ruleId}`)],
      { preventionRule: ruleId },
    );
    return {
      status: 'proposal-only',
      rule: { id: rule.id, title: rule.title },
      executed: false,
      changeId: change.changeId,
      digest: change.digest(),
      director: change.renderForRole('director'),
      standby: change.renderForRole('standby'),
    };
  } catch (err) {
    if (err instanceof ArgusError) return refused(err);
    throw err;
  }
}

async function escalateStandbyResponder(...args) {
  // Governed write. Approved plans are not persisted yet (Forge storage
  // wiring lands with the dev site), so no digest can be verified against a
  // stored plan and this never executes. With no roster it refuses; with a
  // roster it answers who would be paged, dry-run only. The executing path
  // exists and is tested in adapters/atlassian.js (escalateWithApproval).
  try {
    const payload = args.find((a) => a && typeof a === 'object') ?? {};
    const approvalDigest = findField(args, 'approvalDigest');
    if (!/^[0-9a-f]{64}$/.test(approvalDigest)) {
      return {
        status: 'refused', verified: false, executed: false,
        reason: 'approvalDigest must be a lowercase hex SHA-256 digest',
      };
    }
    const rosterInput = payload.roster ?? payload.engineers;
    if (!Array.isArray(rosterInput) || rosterInput.length === 0) {
      return {
        status: 'refused', verified: false, executed: false,
        reason: 'no standby roster is configured and no approved plan is stored',
      };
    }
    const roster = new StandbyRoster(
      rosterInput.map((e) => new Engineer(e.id, e.name, e.reachable !== false)),
    );
    const outcome = roster.whoToPage(Number(payload.elapsedSeconds ?? 0));
    return {
      status: 'dry-run', verified: false, executed: false,
      wouldPage: outcome.paged.engineerId, escalated: outcome.escalated,
      reason: `${outcome.reason}; no write executed (adapter not wired)`,
    };
  } catch (err) {
    if (err instanceof ArgusError) return refused(err);
    throw err;
  }
}

exports.resolver = resolver;
exports.socraticCanaryMergeCheck = socraticCanaryMergeCheck;
exports.compassDataProvider = compassDataProvider;
exports.compassDataProviderCallback = compassDataProviderCallback;
exports.onIssueEvent = onIssueEvent;
exports.runCanaryKillTest = runCanaryKillTest;
exports.traceIncidentProvenance = traceIncidentProvenance;
exports.proposeTypedChange = proposeTypedChange;
exports.escalateStandbyResponder = escalateStandbyResponder;
