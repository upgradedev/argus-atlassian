'use strict';

// Forge runtime client behind adapters/atlassian.js.
// Built only inside the Forge runtime: makeForgeClient() lazy-loads
// @forge/api and returns null where it is not installed (this dev
// machine, unit tests without a loader). Callers treat null as
// not-connected and fall back to the synthetic seed, never to a guess.
//
// Route shapes verified 2026-11-03 against the Atlassian references:
//   requestJira:      route`/rest/api/3/issue/${issueKey}`
//   requestBitbucket: route`/2.0/repositories/${workspaceId}/${repoId}`
// The route tagged template is mandatory: it blocks path traversal in
// interpolated parameters. assignIssue uses the Jira assignee endpoint
// (PUT /rest/api/3/issue/{key}/assignee with an accountId body), and
// getRepoFileText uses the Bitbucket src endpoint; both are standard
// REST shapes but could not be exercised against a live site from here.
// They are labelled unverified in LOG.md until the owner dev site exists.

const { AdapterHttpError } = require('./atlassian.js');

function defaultLoader() {
  // eslint-disable-next-line global-require
  return require('@forge/api');
}

async function unwrapJson(response, what) {
  if (response.status < 200 || response.status >= 300) {
    throw new AdapterHttpError(response.status, `${what} failed with status ${response.status}`);
  }
  return response.json();
}

async function unwrapText(response, what) {
  if (response.status < 200 || response.status >= 300) {
    throw new AdapterHttpError(response.status, `${what} failed with status ${response.status}`);
  }
  return response.text();
}

function makeForgeClient(loader = defaultLoader) {
  let apiModule;
  try {
    apiModule = loader();
  } catch {
    return null;
  }
  const api = apiModule.default ?? apiModule;
  const { route } = apiModule;
  if (!api || typeof api.asApp !== 'function' || typeof route !== 'function') return null;

  return Object.freeze({
    async getIssue(issueKey) {
      const response = await api.asApp().requestJira(route`/rest/api/3/issue/${issueKey}`);
      return unwrapJson(response, `get issue ${issueKey}`);
    },

    async assignIssue(issueKey, accountId) {
      const response = await api.asApp().requestJira(
        route`/rest/api/3/issue/${issueKey}/assignee`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountId }),
        },
      );
      if (response.status < 200 || response.status >= 300) {
        throw new AdapterHttpError(response.status, `assign ${issueKey} failed`);
      }
      return { status: response.status };
    },

    async getPullRequest(workspaceId, repoId, pullRequestId) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/pullrequests/${pullRequestId}`,
      );
      return unwrapJson(response, `get pull request ${pullRequestId}`);
    },

    async getBranchRestrictions(workspaceId, repoId) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/branch-restrictions`,
      );
      return unwrapJson(response, 'get branch restrictions');
    },

    async getRepoFileText(workspaceId, repoId, commit, path) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/src/${commit}/${path}`,
      );
      return unwrapText(response, `get repo file ${path}`);
    },
  });
}

module.exports = { makeForgeClient };
