'use strict';

// Site-app Forge runtime client behind adapters/atlassian.js.
// Built only inside the Forge runtime: makeForgeClient() lazy-loads
// @forge/api and returns null where it is not installed. Package
// presence is not enough: after `npm ci` in CI the package exists but
// the Forge runtime global does not, and claiming a live client there
// would be false. Callers treat null as not-connected.
//
// This client is deliberately Jira and Confluence only. Forge rejects
// a manifest that mixes Bitbucket workspace scopes with Jira site
// scopes, so Bitbucket routes live under apps/bitbucket/ for the
// companion workspace app. The route tagged template blocks
// path traversal in interpolated parameters.

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

function hasForgeRuntime(runtimeGlobal) {
  return typeof runtimeGlobal?.__forge_fetch__ === 'function';
}

function makeForgeClient(loader = defaultLoader, runtimeGlobal = globalThis) {
  if (!hasForgeRuntime(runtimeGlobal)) return null;
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

module.exports = { makeForgeClient, hasForgeRuntime };
