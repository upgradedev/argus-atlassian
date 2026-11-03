'use strict';

// Turn a pipeline definition (bitbucket-pipelines.yml shaped text) into the
// flat facts map the Elenchos rules read. Deliberately a small, documented
// heuristic extractor, not a YAML parser: every fact below names the text
// pattern that produced it, undetectable facts fail closed, and facts only
// a platform API can know (merge.required_checks_enforced) default to
// 'false' until an adapter enriches them. An adapter enrichment always
// wins over a text heuristic.

const LOCKFILES = Object.freeze([
  'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'poetry.lock',
  'Pipfile.lock', 'Cargo.lock', 'go.sum', 'composer.lock', 'Gemfile.lock',
]);

const TEST_CMD = /(npm (run )?test|pytest|go test|cargo test|mvn (test|verify)|gradlew? (test|check)|dotnet test|\bjest\b|\bvitest\b)/i;
const LINT_CMD = /(eslint|ruff|flake8|pylint|golangci-lint|npm run lint|\blint\b)/i;
const SCAN_CMD = /(snyk|codeql|trivy|semgrep|bandit|npm audit|gitleaks|security scan)/i;
const ALLOW_FAILURE = /(allow_failure|continue-on-error)\s*:\s*true/i;
const SECRET_PATTERNS = Object.freeze([
  /AKIA[0-9A-Z]{16}/,
  /BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY/,
  /(password|passwd|api[_-]?key|client[_-]?secret)\s*[:=]\s*['"][^'"]+['"]/i,
]);

const b = (value) => (value ? 'true' : 'false');

function extractPipelineFacts(text, enrichments = {}) {
  const source = String(text ?? '');
  const lines = source.split(/\r?\n/);
  const matching = (re) => lines.filter((line) => re.test(line));
  const firstIndex = (re) => lines.findIndex((line) => re.test(line));

  const testLines = matching(TEST_CMD);
  const lintLines = matching(LINT_CMD);
  const scanLines = matching(SCAN_CMD);

  const coverageThreshold = source.match(
    /(?:cov-fail-under|fail_under|coverageThreshold|threshold)\D{0,12}?(\d+(?:\.\d+)?)/i,
  );
  const coverageMentioned = /coverage|--cov\b/i.test(source);

  const deploymentMatch = source.match(/deployment:\s*([A-Za-z0-9_-]+)/i);
  const deployIndex = firstIndex(/deployment:/i);
  const testIndex = firstIndex(TEST_CMD);

  const imageMatch = source.match(/^\s*image:\s*(\S+)/im);
  const image = imageMatch ? imageMatch[1] : '';

  const scanFailOnMatch = source.match(/(?:fail-on|severity)[= ]([A-Za-z]+)/i);
  const scanMasked = scanLines.some((line) => line.includes('|| true'));

  const facts = {
    // The badge is whatever the platform painted. No Elenchos rule reads
    // it; it exists so the badge-only baseline in the benchmark is honest.
    'pipeline.badge': 'green',

    'test.present': b(testLines.length > 0),
    'test.masked_exit': b(testLines.some((line) => line.includes('|| true'))),
    'test.allow_failure': b(ALLOW_FAILURE.test(source)),
    'test.skipped': b(/-DskipTests|skipTests|SKIP_TESTS|--skip-tests/i.test(source)),
    'test.pass_with_no_tests': b(/passWithNoTests/i.test(source)),

    'coverage.enforced': b(coverageMentioned && coverageThreshold !== null),
    'coverage.threshold': coverageThreshold ? coverageThreshold[1] : '0',

    'lint.present': b(lintLines.length > 0),
    'lint.allow_failure': b(
      lintLines.some((line) => line.includes('|| true')) || ALLOW_FAILURE.test(source),
    ),

    'scan.present': b(scanLines.length > 0),
    'scan.fail_on': scanLines.length === 0 || scanMasked
      ? 'none'
      : (scanFailOnMatch ? scanFailOnMatch[1].toLowerCase() : 'high'),

    'deploy.present': b(deploymentMatch !== null),
    'deploy.requires_tests': b(
      deploymentMatch !== null && testIndex !== -1 && testIndex < deployIndex,
    ),
    'deploy.environment': deploymentMatch ? deploymentMatch[1].toLowerCase() : '',
    'deploy.manual_approval': b(/trigger:\s*manual/i.test(source)),

    // Branch permissions are not in the pipeline file. Fail closed until
    // the Bitbucket adapter supplies this from the branch restrictions API.
    'merge.required_checks_enforced': 'false',

    'secrets.detected_count': SECRET_PATTERNS.some((re) => re.test(source)) ? '1' : '0',

    'deps.lockfile_present': b(
      LOCKFILES.some((name) => source.includes(name)) || /\bnpm ci\b/.test(source),
    ),
    'deps.install_frozen': b(
      /\bnpm ci\b|--frozen-lockfile|--immutable|--require-hashes/.test(source),
    ),

    'cache.enabled': b(/caches:/.test(source)),
    'cache.key_includes_lockfile': b(
      /caches:/.test(source) && LOCKFILES.some((name) => source.includes(name)),
    ),

    'image.pinned': b(
      image !== '' && (image.includes('@sha256:') || (image.includes(':') && !image.endsWith(':latest'))),
    ),
    'job.timeout_set': b(/max-time:|timeout-minutes:|timeout:/i.test(source)),
    'status.force_success': b(/\|\|\s*exit\s+0/.test(source)),
  };

  return Object.freeze({ ...facts, ...enrichments });
}

module.exports = { LOCKFILES, extractPipelineFacts };
