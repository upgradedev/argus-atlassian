'use strict';

// Parsing and response helpers for documented Forge event contracts.
// Event fields are read from their documented objects. We do not hunt
// for same-named strings through unknown payloads here, because the
// first `uuid` in a Bitbucket payload is not a safe identifier guess.

function firstObject(args) {
  const queue = Array.isArray(args) ? [...args] : [args];
  for (const candidate of queue) {
    if (!candidate || typeof candidate !== 'object') continue;
    if (candidate.workspace && candidate.repository && candidate.pullrequest) return candidate;
    for (const child of Object.values(candidate)) {
      if (child && typeof child === 'object') queue.push(child);
    }
  }
  return null;
}

function parseMergeCheckEvent(...args) {
  const event = firstObject(args);
  if (!event) return null;
  const workspaceId = event.workspace?.uuid;
  const repoId = event.repository?.uuid;
  const rawId = event.pullrequest?.id;
  const pullRequestId = rawId === undefined || rawId === null ? '' : String(rawId);
  if (!workspaceId || !repoId || !pullRequestId) return null;
  return Object.freeze({ workspaceId, repoId, pullRequestId });
}

function parseIssueKey(...args) {
  // Action payloads use issueKey; Jira product events nest issue.key.
  // Search only those two documented placements.
  const queue = [...args];
  for (const candidate of queue) {
    if (!candidate || typeof candidate !== 'object') continue;
    if (typeof candidate.issueKey === 'string' && candidate.issueKey) return candidate.issueKey;
    if (typeof candidate.issue?.key === 'string' && candidate.issue.key) return candidate.issue.key;
    for (const child of Object.values(candidate)) {
      if (child && typeof child === 'object') queue.push(child);
    }
  }
  return '';
}

function mergeCheckMessage(evaluation) {
  const violations = [...(evaluation?.violations ?? [])];
  const total = evaluation?.results?.length ?? 20;
  if (violations.length === 0) {
    return `Argus: All ${total} Elenchos rules passed.`;
  }
  return `Argus: ${violations.length} of ${total} Elenchos rules failed (${violations.join(', ')}).`
    .slice(0, 240);
}

module.exports = { parseMergeCheckEvent, parseIssueKey, mergeCheckMessage };
