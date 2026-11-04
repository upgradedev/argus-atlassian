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

    async getIssueRemoteLinks(issueKey) {
      const response = await api.asApp().requestJira(
        route`/rest/api/3/issue/${issueKey}/remotelink`,
      );
      return unwrapJson(response, `get remote links for ${issueKey}`);
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

    async getRepository(workspaceId, repoId) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}`,
      );
      return unwrapJson(response, `get repository ${workspaceId}/${repoId}`);
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

    async getBranch(workspaceId, repoId, branchName) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/refs/branches/${branchName}`,
      );
      return unwrapJson(response, `get branch ${branchName}`);
    },

    async commitTextFile({ workspaceId, repoId, branch, parent, path, content, message }) {
      // Bitbucket documents application/x-www-form-urlencoded for text
      // files and explicitly says multipart is not supported by Forge.
      const body = new URLSearchParams({
        message,
        branch,
        parents: parent,
        [`/${String(path).replace(/^\//, '')}`]: content,
      });
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/src`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: body.toString(),
        },
      );
      if (response.status < 200 || response.status >= 300) {
        throw new AdapterHttpError(response.status, `commit ${path} failed`);
      }
      return { status: response.status };
    },

    async createPullRequest({
      workspaceId, repoId, title, sourceBranch, destinationBranch, description,
    }) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/pullrequests`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            title,
            description,
            close_source_branch: true,
            source: { branch: { name: sourceBranch } },
            destination: { branch: { name: destinationBranch } },
          }),
        },
      );
      return unwrapJson(response, `create pull request ${title}`);
    },

    async getRepoFileText(workspaceId, repoId, commit, path) {
      const response = await api.asApp().requestBitbucket(
        route`/2.0/repositories/${workspaceId}/${repoId}/src/${commit}/${path}`,
      );
      return unwrapText(response, `get repo file ${path}`);
    },

    async createConfluencePage(spaceId, page) {
      const response = await api.asApp().requestConfluence(route`/wiki/api/v2/pages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          spaceId: String(spaceId),
          status: 'current',
          title: page.title,
          body: { representation: 'storage', value: page.bodyStorage },
        }),
      });
      return unwrapJson(response, `create Confluence page ${page.title}`);
    },
  });
}

module.exports = { makeForgeClient };
