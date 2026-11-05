'use strict';

// Bitbucket companion Forge app entry point.
// Atlassian does not allow Bitbucket workspace scopes and Jira site
// scopes in the same Forge installable. This entry shares the same
// deterministic Argus domain core as the site app, but it has its own
// app root under apps/bitbucket/ and installs on a Bitbucket workspace.
// It deliberately lives outside the site app's src/ tree: Forge lint
// scans every source file under an app root, not only referenced
// handlers, so Bitbucket route calls there would demand workspace
// scopes in the site manifest and fail the site lint.

const {
  evaluateRules,
  extractPipelineFacts,
  repairPipelineYaml,
  validateAllRules,
} = require('../../../src/argus/index.js');
const { AtlassianReader } = require('../../../src/adapters/atlassian.js');
const { makeBitbucketClient } = require('./adapters/bitbucket_client.js');
const {
  parseMergeCheckEvent,
  mergeCheckMessage,
} = require('../../../src/forge_events.js');
const { makeResolverHandler } = require('../../../src/resolver.js');

const bitbucketClient = makeBitbucketClient();
const reader = bitbucketClient ? new AtlassianReader(bitbucketClient) : null;

function evaluationSummary(evaluation) {
  return {
    clean: evaluation.clean,
    violations: [...evaluation.violations],
    results: evaluation.results.map((r) => ({ id: r.id, title: r.title, clean: r.clean })),
  };
}

async function liveEvaluation(args) {
  if (!reader || !bitbucketClient) return null;
  const event = parseMergeCheckEvent(...args);
  if (!event) return null;
  const pr = await bitbucketClient.getPullRequest(
    event.workspaceId,
    event.repoId,
    event.pullRequestId,
  );
  const commit = pr?.source?.commit?.hash;
  if (!commit) return null;
  return reader.fetchPipelineEvaluation(event.workspaceId, event.repoId, commit);
}

async function canaryMergeCheck(...args) {
  try {
    const live = await liveEvaluation(args);
    if (live) {
      if (typeof globalThis.__forge_fetch__ === 'function') {
        console.info(
          `argus canaryMergeCheck clean=${live.evaluation.clean} `
          + `violations=${live.evaluation.violations.length}`,
        );
      }
      return {
        success: live.evaluation.clean,
        message: mergeCheckMessage(live.evaluation),
      };
    }
  } catch (err) {
    return {
      success: false,
      message: `Argus could not evaluate this pull request: ${err.message}`.slice(0, 240),
    };
  }
  return {
    success: false,
    message: 'Argus could not evaluate this pull request in this runtime.',
  };
}

async function getArgusStatus() {
  const validation = validateAllRules();
  return {
    status: reader ? 'live-ready' : 'seed-demo',
    liveEvidence: reader
      ? 'connected'
      : 'not-connected: @forge/api unavailable in this runtime',
    rulesAccepted: `${validation.accepted}/${validation.total}`,
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

async function getProposalStatus() {
  return null;
}

exports.resolver = makeResolverHandler({
  getArgusStatus,
  evaluatePipeline,
  getProposalStatus,
});
exports.canaryMergeCheck = canaryMergeCheck;
exports.socraticCanaryMergeCheck = canaryMergeCheck;
