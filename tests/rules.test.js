'use strict';

// Maintained tests for the Elenchos rules r01-r20 and the pipeline facts
// extractor. Every rule must separate its violating fixture (exit 1) from
// the clean state (exit 0) through the Socratic Canary machine, or the
// benchmark cannot claim the rule exists.
// Run: node --test tests/

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  RULES,
  CLEAN_STATE,
  violatingStateFor,
  evaluateRules,
  validateAllRules,
  repairFactsForRule,
  ruleById,
} = require('../src/argus/domain/rules.js');
const { extractPipelineFacts } = require('../src/argus/domain/pipeline_facts.js');
const { SocraticCanaryValidator, CanaryFixture } = require('../src/argus/domain/canary.js');

test('there are exactly 20 rules, r01 through r20, in order', () => {
  assert.equal(RULES.length, 20);
  assert.deepEqual(
    RULES.map((r) => r.id),
    Array.from({ length: 20 }, (_, i) => `r${String(i + 1).padStart(2, '0')}`),
  );
  for (const rule of RULES) {
    assert.ok(rule.title.length > 0, rule.id);
    assert.equal(typeof rule.check, 'function', rule.id);
  }
});

test('clean state passes every rule', () => {
  const out = evaluateRules(CLEAN_STATE);
  assert.equal(out.clean, true);
  assert.deepEqual(out.violations, []);
  assert.equal(out.results.length, 20);
});

test('empty state fails closed, never passes as clean', () => {
  const out = evaluateRules({});
  assert.equal(out.clean, false);
  assert.ok(out.violations.length >= 15, out.violations.join(','));
});

test('each violating fixture trips its own rule and no false clean slips by', () => {
  for (const rule of RULES) {
    const state = violatingStateFor(rule.id);
    assert.equal(rule.check(state), false, `${rule.id} should flag its fixture`);
    const out = evaluateRules(state);
    assert.ok(out.violations.includes(rule.id), `${rule.id} missing from ${out.violations}`);
  }
});

test('every rule separates violating from clean through the canary machine', () => {
  const validator = new SocraticCanaryValidator();
  for (const rule of RULES) {
    const result = validator.validate(
      rule.id,
      rule.check,
      new CanaryFixture(`${rule.id}-violating`, violatingStateFor(rule.id), false),
      new CanaryFixture('clean', CLEAN_STATE, true),
    );
    assert.equal(result.accepted, true, `${rule.id}: ${result.reason}`);
    assert.deepEqual([result.violatingExit, result.cleanExit], [1, 0], rule.id);
  }
});

test('validateAllRules reports 20 of 20 accepted', () => {
  const out = validateAllRules();
  assert.equal(out.accepted, 20);
  assert.equal(out.total, 20);
  assert.deepEqual(out.rejected, []);
});

test('applying every repair fact makes its violating fixture pass that rule', () => {
  for (const rule of RULES) {
    const repaired = { ...violatingStateFor(rule.id) };
    for (const fact of repairFactsForRule(rule.id)) repaired[fact.field] = fact.value;
    assert.equal(rule.check(repaired), true, `${rule.id} repair does not satisfy the rule`);
  }
});

test('naive badge check is thrown out, which is the fake-green point', () => {
  const validator = new SocraticCanaryValidator();
  const badgeOnly = (s) => s['pipeline.badge'] === 'green';
  let thrownOut = 0;
  for (const rule of RULES) {
    const result = validator.validate(
      'badge-only',
      badgeOnly,
      new CanaryFixture('v', violatingStateFor(rule.id), false),
      new CanaryFixture('c', CLEAN_STATE, true),
    );
    if (!result.accepted) thrownOut += 1;
  }
  assert.equal(thrownOut, 20);
});

test('coverage threshold boundary: 79 fails r06, 80 passes', () => {
  const r06 = ruleById('r06');
  assert.equal(r06.check({ ...CLEAN_STATE, 'coverage.threshold': '79' }), false);
  assert.equal(r06.check({ ...CLEAN_STATE, 'coverage.threshold': '80' }), true);
  assert.equal(r06.check({ ...CLEAN_STATE, 'coverage.threshold': 'high' }), false);
});

test('conditional rules: non-production deploy needs no manual approval', () => {
  const r12 = ruleById('r12');
  assert.equal(r12.check({
    ...CLEAN_STATE, 'deploy.environment': 'staging', 'deploy.manual_approval': 'false',
  }), true);
  assert.equal(r12.check({
    ...CLEAN_STATE, 'deploy.environment': 'production', 'deploy.manual_approval': 'false',
  }), false);
});

const CLEAN_YAML = `
image: node:20.11
definitions:
  caches:
    node:
      key:
        files:
          - package-lock.json
      path: node_modules
pipelines:
  pull-requests:
    '**':
      - step:
          name: Lint and test
          max-time: 10
          caches: [node]
          script:
            - npm ci
            - npx eslint .
            - npm test -- --coverage --cov-fail-under=85
            - npx semgrep --fail-on=high
      - step:
          name: Deploy
          deployment: staging
          trigger: manual
          script:
            - ./deploy.sh
`;

const FAKE_GREEN_YAML = `
image: node:latest
pipelines:
  default:
    - step:
        name: Everything passes, trust the badge
        script:
          - npm install
          - npm test -- --passWithNoTests || true
          - echo done || exit 0
      - step:
          name: Ship it
          deployment: production
          script:
            - ./deploy-prod.sh
`;

test('extractor: clean pipelines YAML plus API enrichment yields zero violations', () => {
  const facts = extractPipelineFacts(CLEAN_YAML, {
    'merge.required_checks_enforced': 'true',
  });
  const out = evaluateRules(facts);
  assert.deepEqual(out.violations, [], JSON.stringify(facts));
});

test('extractor: without enrichment, merge checks stay flagged and named', () => {
  const out = evaluateRules(extractPipelineFacts(CLEAN_YAML));
  assert.deepEqual(out.violations, ['r13']);
});

test('extractor: fake-green YAML trips the masked exit and friends', () => {
  const out = evaluateRules(extractPipelineFacts(FAKE_GREEN_YAML));
  for (const id of ['r01', 'r05', 'r06', 'r07', 'r09', 'r12', 'r18', 'r20']) {
    assert.ok(out.violations.includes(id), `${id} missing from ${out.violations}`);
  }
  assert.equal(out.clean, false);
});
