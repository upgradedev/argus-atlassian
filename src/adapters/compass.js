'use strict';

// Compass data-provider payload adapter (parked, not deployed).
// Atlassian's Compass end-of-life plan rejects new Compass modules in
// Forge apps at deploy time (CHANGE-3132), so no manifest references
// this adapter. It remains tested library code for the payload shape.
// The return value mirrors DataProviderResponse.build() from Atlassian's
// Forge GraphQL toolkit, verified against the published builder source
// on 2026-11-04. We build the plain result locally rather than taking
// the toolkit, because its current package still pins @forge/api ^5
// while this app runs @forge/api ^8. The wire shape is the contract;
// the class is only a builder.

const FAKE_GREEN_VIOLATIONS_METRIC = 'Argus fake-green violations';
const RULES_PASSING_METRIC = 'Argus Elenchos rules passing';

function parseBitbucketRepositoryUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return null;
  }
  if (url.hostname !== 'bitbucket.org') return null;
  const parts = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
  if (parts.length < 2) return null;
  const [workspace, repoSlug] = parts;
  if (!workspace || !repoSlug) return null;
  return Object.freeze({
    workspace,
    repoSlug,
    externalSourceId: `bitbucket:${workspace}/${repoSlug}`,
  });
}

function buildCompassDataProviderResult({ url, evaluation = null } = {}) {
  const parsed = parseBitbucketRepositoryUrl(url);
  if (!parsed) return null;
  const violations = evaluation?.violations?.length;
  const passing = evaluation?.results?.filter((r) => r.clean).length;
  return Object.freeze({
    externalSourceId: parsed.externalSourceId,
    events: undefined,
    metrics: Object.freeze({
      builtIn: undefined,
      custom: Object.freeze([
        Object.freeze({
          name: FAKE_GREEN_VIOLATIONS_METRIC,
          description: 'Count of failing Elenchos fake-green gate rules out of 20.',
          format: { suffix: ' violations' },
          initialValue: Number.isInteger(violations) ? violations : null,
        }),
        Object.freeze({
          name: RULES_PASSING_METRIC,
          description: 'Count of passing Elenchos rules out of 20.',
          format: { suffix: '/20' },
          initialValue: Number.isInteger(passing) ? passing : null,
        }),
      ]),
    }),
  });
}

function createCompassDataProvider({ client = null, reader = null } = {}) {
  return async function compassDataProvider(request = {}) {
    const parsed = parseBitbucketRepositoryUrl(request.url);
    if (!parsed) return null;

    let evaluation = null;
    try {
      if (client?.getRepository && reader?.fetchPipelineEvaluation) {
        const repo = await client.getRepository(parsed.workspace, parsed.repoSlug);
        const ref = repo?.mainbranch?.name || 'HEAD';
        const out = await reader.fetchPipelineEvaluation(
          parsed.workspace,
          repo?.uuid || parsed.repoSlug,
          ref,
        );
        evaluation = out.evaluation;
      }
    } catch {
      // Registration is still useful without initial values. Returning
      // definitions with null values is documented behavior.
      evaluation = null;
    }
    return buildCompassDataProviderResult({ url: request.url, evaluation });
  };
}

async function compassDataProviderCallback(input = {}, logger = console) {
  if (input.success === false) {
    logger.error(
      `Argus Compass setup failed for ${input.url ?? 'unknown URL'}: `
      + `${input.errorMessage ?? 'unknown error'}`,
    );
  } else if (input.success === true) {
    logger.info?.(`Argus Compass setup succeeded for ${input.url ?? 'unknown URL'}.`);
  }
}

module.exports = {
  FAKE_GREEN_VIOLATIONS_METRIC,
  RULES_PASSING_METRIC,
  parseBitbucketRepositoryUrl,
  buildCompassDataProviderResult,
  createCompassDataProvider,
  compassDataProviderCallback,
};
