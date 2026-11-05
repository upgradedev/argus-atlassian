'use strict';

// Atlassian adapters behind the Argus ports (domain/ports.js).
// This layer may know Atlassian API shapes; the domain never does.
// Every adapter takes an injected client, so all of this is testable with
// a fake client and no Forge installation (tests/adapters.test.js). The
// real client comes from adapters/forge_client.js inside a Forge runtime.
//
// Least-privilege roles: AtlassianReader cannot write (its write method
// hits the shared guard). AtlassianWriter runs a write function only after
// verifyBeforeWrite.

const {
  RefusedError,
  evaluateRules,
  extractPipelineFacts,
  guardReaderWriteAttempt,
  repairPipelineYaml,
  verifyBeforeWrite,
} = require('../argus/index.js');

class AdapterHttpError extends Error {
  constructor(status, message) {
    super(message ?? `Atlassian API request failed with status ${status}`);
    this.name = 'AdapterHttpError';
    this.status = status;
  }
}

function str(value) {
  return value === undefined || value === null ? '' : String(value);
}

function escapeHtml(value) {
  return str(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

class AtlassianReader {
  constructor(client) {
    this.client = client;
  }

  async fetchEvidence(incidentId) {
    const issue = await this.client.getIssue(incidentId);
    const fields = issue.fields ?? {};
    return Object.freeze({
      'issue.key': str(issue.key ?? incidentId),
      'issue.summary': str(fields.summary),
      'issue.status': str(fields.status?.name),
      'issue.type': str(fields.issuetype?.name),
      'issue.priority': str(fields.priority?.name),
      'issue.assignee': str(fields.assignee?.accountId),
      'issue.updated': str(fields.updated),
    });
  }

  async fetchLinkedWork(incidentId) {
    // Linked work is evidence of association, not causality. Every item
    // is explicitly causal:false; calling it a root cause still requires
    // the sealed provenance walk, not a hyperlink.
    const issue = await this.client.getIssue(incidentId);
    const links = [];
    for (const link of issue.fields?.issuelinks ?? []) {
      const linked = link.outwardIssue ?? link.inwardIssue;
      if (!linked?.key) continue;
      links.push(Object.freeze({
        kind: 'jira-issue',
        id: linked.key,
        title: str(linked.fields?.summary),
        relationship: str(link.type?.name),
        causal: false,
      }));
    }

    if (typeof this.client.getIssueRemoteLinks === 'function') {
      const remoteLinks = await this.client.getIssueRemoteLinks(incidentId);
      for (const link of remoteLinks ?? []) {
        const url = str(link.object?.url);
        if (!url) continue;
        let kind = 'linked-work';
        try {
          const parsed = new URL(url);
          if (parsed.hostname === 'bitbucket.org') kind = 'bitbucket';
          else if (parsed.pathname.startsWith('/wiki/')) kind = 'confluence';
        } catch {
          kind = 'linked-work';
        }
        links.push(Object.freeze({
          kind,
          id: url,
          title: str(link.object?.title),
          relationship: str(link.relationship),
          causal: false,
        }));
      }
    }
    return Object.freeze(links);
  }

  write() {
    guardReaderWriteAttempt('write');
  }

  async fetchPipelineEvaluation(
    workspaceId,
    repoId,
    commit,
    pipelinePath = 'bitbucket-pipelines.yml',
  ) {
    const yamlText = await this.client.getRepoFileText(workspaceId, repoId, commit, pipelinePath);
    const restrictions = await this.client.getBranchRestrictions(workspaceId, repoId);
    const enforced = (restrictions?.values ?? []).some(
      (entry) => entry.kind === 'require_passing_builds_to_merge',
    );
    const facts = extractPipelineFacts(yamlText, {
      'merge.required_checks_enforced': enforced ? 'true' : 'false',
    });
    return Object.freeze({ facts, evaluation: evaluateRules(facts) });
  }
}

class AtlassianWriter {
  constructor(client) {
    this.client = client;
  }

  async execute(change, approvedDigest, writeFn) {
    verifyBeforeWrite(change, approvedDigest);
    return writeFn(this.client);
  }

  async escalateWithApproval(change, approvedDigest, issueKey, standbyAccountId) {
    return this.execute(change, approvedDigest, async (client) => {
      await client.assignIssue(issueKey, standbyAccountId);
      return Object.freeze({ executed: true, issueKey, assignedTo: standbyAccountId });
    });
  }

  async openRepairPullRequest(change, approvedDigest, {
    workspace,
    repository,
    sourceBranch = '',
    pipelinePath = 'bitbucket-pipelines.yml',
    issueKey = '',
  } = {}) {
    return this.execute(change, approvedDigest, async (client) => {
      for (const method of ['getRepository', 'getBranch', 'getRepoFileText', 'commitTextFile', 'createPullRequest']) {
        if (typeof client[method] !== 'function') {
          throw new RefusedError(`Bitbucket client does not provide ${method}`);
        }
      }
      if (!workspace || !repository) {
        throw new RefusedError('workspace and repository are required for a repair PR');
      }

      const repo = await client.getRepository(workspace, repository);
      const repoRef = repo?.uuid || repository;
      const destinationBranch = sourceBranch || repo?.mainbranch?.name || 'main';
      const base = await client.getBranch(workspace, repoRef, destinationBranch);
      const parent = base?.target?.hash;
      if (!parent) throw new RefusedError(`could not resolve parent commit for ${destinationBranch}`);

      const currentYaml = await client.getRepoFileText(
        workspace, repoRef, parent, pipelinePath,
      );
      const repair = repairPipelineYaml(currentYaml);
      if (!change.preventionRule || !repair.applied.includes(change.preventionRule)) {
        throw new RefusedError(
          `deterministic repair does not clear ${change.preventionRule || 'the stored rule'}`,
        );
      }

      const branch = `argus/${change.changeId}`.replace(/[^A-Za-z0-9._/-]/g, '-');
      await client.commitTextFile({
        workspaceId: workspace,
        repoId: repoRef,
        branch,
        parent,
        path: pipelinePath,
        content: repair.yaml,
        message: `fix(ci): ${change.title}${issueKey ? ` [${issueKey}]` : ''}`,
      });
      const head = await client.getBranch(workspace, repoRef, branch);
      const pullRequest = await client.createPullRequest({
        workspaceId: workspace,
        repoId: repoRef,
        title: `Argus verified repair: ${change.preventionRule}${issueKey ? ` (${issueKey})` : ''}`,
        sourceBranch: branch,
        destinationBranch,
        description: [
          'Opened by Argus after human approval of the exact Typed Change IR.',
          `Change: ${change.changeId}`,
          `Digest: ${change.digest()}`,
          `Applied and re-verified: ${repair.applied.join(', ')}`,
          `Still needs a human decision: ${repair.unsupported.join(', ') || 'none'}`,
        ].join('\n'),
      });

      return Object.freeze({
        executed: true,
        branch,
        destinationBranch,
        parent,
        commit: str(head?.target?.hash),
        pullRequestId: pullRequest?.id ?? null,
        pullRequestUrl: str(pullRequest?.links?.html?.href),
        applied: repair.applied,
        unsupported: repair.unsupported,
      });
    });
  }
}

function buildPostIncidentPage({ issueKey, evaluation, seal = '', rootCause = '' }) {
  const failing = (evaluation?.results ?? []).filter((r) => !r.clean);
  const rows = failing.length === 0
    ? '<p>No Elenchos rule violations. The pipeline facts are clean.</p>'
    : `<ul>${failing.map((r) => `<li><strong>${escapeHtml(r.id)}</strong> ${escapeHtml(r.title)}</li>`).join('')}</ul>`;
  const bodyStorage = [
    `<h1>Post-incident report for ${escapeHtml(issueKey)}</h1>`,
    '<h2>Elenchos violations</h2>',
    rows,
    '<h2>Provenance</h2>',
    `<p>Root cause: ${escapeHtml(rootCause || 'not traced')}.</p>`,
    `<p>Provenance seal: ${escapeHtml(seal || 'not sealed')}.</p>`,
    '<p>Generated by Argus. Numbers come from the deterministic '
      + 'kill-test, not from a model summary.</p>',
  ].join('\n');
  return Object.freeze({
    title: `[Argus] Post-incident report ${issueKey}`,
    bodyStorage,
  });
}

function buildScorecardPayload(evaluation, atIso = '') {
  const passing = (evaluation?.results ?? []).filter((r) => r.clean).length;
  const total = (evaluation?.results ?? []).length;
  return Object.freeze({
    at: atIso,
    metrics: Object.freeze({
      fake_green_violations: total - passing,
      elenchos_rules_passing: passing,
      elenchos_rules_total: total,
    }),
    violations: evaluation?.violations ?? [],
  });
}

module.exports = {
  AdapterHttpError,
  AtlassianReader,
  AtlassianWriter,
  buildPostIncidentPage,
  buildScorecardPayload,
};
