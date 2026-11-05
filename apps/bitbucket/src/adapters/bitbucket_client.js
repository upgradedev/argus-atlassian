'use strict';

// Bitbucket-only Forge client for the companion workspace app.
// Forge cannot mix Bitbucket workspace scopes with Jira site scopes in
// one installable app, so these route calls deliberately live outside
// the site app's handler graph.

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

function makeBitbucketClient(loader = defaultLoader) {
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
  });
}

module.exports = { makeBitbucketClient };
