'use strict';

// Elenchos rules r01-r20: deterministic fake-green gate checks.
//
// Each rule is a CheckFn over a flat string-to-string facts map (see
// pipeline_facts.js for how a bitbucket-pipelines.yml becomes facts, and
// the adapters for facts only an API can supply). A check returns true
// when the state is clean. A missing fact fails closed for every rule
// that requires it, except the two explicitly conditional rules (r11
// deploy gating when no deploy exists, r12 approval outside production,
// r17 cache key when the cache is off).
//
// A rule earns its id only by separating fixtures through the Socratic
// Canary machine (canary.js): violating -> exit 1, clean -> exit 0.
// scripts/run_killtest_benchmark.mjs re-proves that on every run.
// Authored 2026-11-03. These rules did not exist in either core before;
// STATE.md J3 named them before they were written.

const { ValidationError } = require('./errors.js');
const { CanaryFixture, SocraticCanaryValidator } = require('./canary.js');

const MIN_COVERAGE_THRESHOLD = 80;

const isTrue = (state, key) => state[key] === 'true';
const isFalse = (state, key) => state[key] === 'false';

function coveragePasses(state) {
  if (!isTrue(state, 'coverage.enforced')) return false;
  const raw = state['coverage.threshold'];
  if (raw === undefined || !/^\d+(\.\d+)?$/.test(raw.trim())) return false;
  return Number(raw) >= MIN_COVERAGE_THRESHOLD;
}

function scanCanFail(state) {
  return ['low', 'medium', 'high'].includes((state['scan.fail_on'] ?? '').toLowerCase());
}

const RULES = Object.freeze([
  { id: 'r01', title: 'Test exit code masked (|| true)', check: (s) => isFalse(s, 'test.masked_exit') },
  { id: 'r02', title: 'Test step allowed to fail', check: (s) => isFalse(s, 'test.allow_failure') },
  { id: 'r03', title: 'Tests skipped', check: (s) => isFalse(s, 'test.skipped') },
  { id: 'r04', title: 'No test step in the pipeline', check: (s) => isTrue(s, 'test.present') },
  { id: 'r05', title: 'Passing with no tests allowed', check: (s) => isFalse(s, 'test.pass_with_no_tests') },
  { id: 'r06', title: 'Coverage gate missing or below 80', check: coveragePasses },
  { id: 'r07', title: 'No lint step in the pipeline', check: (s) => isTrue(s, 'lint.present') },
  { id: 'r08', title: 'Lint step allowed to fail', check: (s) => isFalse(s, 'lint.allow_failure') },
  { id: 'r09', title: 'No security scan step', check: (s) => isTrue(s, 'scan.present') },
  { id: 'r10', title: 'Security scan cannot fail the build', check: scanCanFail },
  {
    id: 'r11', title: 'Deploy not gated on tests',
    check: (s) => isFalse(s, 'deploy.present') || isTrue(s, 'deploy.requires_tests'),
  },
  {
    id: 'r12', title: 'Production deploy without manual approval',
    check: (s) => s['deploy.environment'] !== 'production' || isTrue(s, 'deploy.manual_approval'),
  },
  { id: 'r13', title: 'Required merge checks not enforced', check: (s) => isTrue(s, 'merge.required_checks_enforced') },
  { id: 'r14', title: 'Secret material detected in code', check: (s) => s['secrets.detected_count'] === '0' },
  { id: 'r15', title: 'No dependency lockfile', check: (s) => isTrue(s, 'deps.lockfile_present') },
  { id: 'r16', title: 'Dependency install not frozen', check: (s) => isTrue(s, 'deps.install_frozen') },
  {
    id: 'r17', title: 'Cache key ignores the lockfile',
    check: (s) => isFalse(s, 'cache.enabled') || isTrue(s, 'cache.key_includes_lockfile'),
  },
  { id: 'r18', title: 'Unpinned container image', check: (s) => isTrue(s, 'image.pinned') },
  { id: 'r19', title: 'No job timeout set', check: (s) => isTrue(s, 'job.timeout_set') },
  { id: 'r20', title: 'Success status forced, not from exit codes', check: (s) => isFalse(s, 'status.force_success') },
].map((rule) => Object.freeze(rule)));

const CLEAN_STATE = Object.freeze({
  'pipeline.badge': 'green',
  'test.present': 'true',
  'test.masked_exit': 'false',
  'test.allow_failure': 'false',
  'test.skipped': 'false',
  'test.pass_with_no_tests': 'false',
  'coverage.enforced': 'true',
  'coverage.threshold': '80',
  'lint.present': 'true',
  'lint.allow_failure': 'false',
  'scan.present': 'true',
  'scan.fail_on': 'high',
  'deploy.present': 'true',
  'deploy.requires_tests': 'true',
  'deploy.environment': 'production',
  'deploy.manual_approval': 'true',
  'merge.required_checks_enforced': 'true',
  'secrets.detected_count': '0',
  'deps.lockfile_present': 'true',
  'deps.install_frozen': 'true',
  'cache.enabled': 'true',
  'cache.key_includes_lockfile': 'true',
  'image.pinned': 'true',
  'job.timeout_set': 'true',
  'status.force_success': 'false',
});

const VIOLATIONS = Object.freeze({
  r01: { 'test.masked_exit': 'true' },
  r02: { 'test.allow_failure': 'true' },
  r03: { 'test.skipped': 'true' },
  r04: { 'test.present': 'false' },
  r05: { 'test.pass_with_no_tests': 'true' },
  r06: { 'coverage.threshold': '0' },
  r07: { 'lint.present': 'false' },
  r08: { 'lint.allow_failure': 'true' },
  r09: { 'scan.present': 'false' },
  r10: { 'scan.fail_on': 'none' },
  r11: { 'deploy.requires_tests': 'false' },
  r12: { 'deploy.manual_approval': 'false' },
  r13: { 'merge.required_checks_enforced': 'false' },
  r14: { 'secrets.detected_count': '1' },
  r15: { 'deps.lockfile_present': 'false' },
  r16: { 'deps.install_frozen': 'false' },
  r17: { 'cache.key_includes_lockfile': 'false' },
  r18: { 'image.pinned': 'false' },
  r19: { 'job.timeout_set': 'false' },
  r20: { 'status.force_success': 'true' },
});

function ruleById(ruleId) {
  const rule = RULES.find((r) => r.id === ruleId);
  if (!rule) throw new ValidationError(`unknown Elenchos rule ${ruleId}`);
  return rule;
}

function violatingStateFor(ruleId) {
  ruleById(ruleId);
  return Object.freeze({ ...CLEAN_STATE, ...VIOLATIONS[ruleId] });
}

function evaluateRules(state) {
  const facts = state ?? {};
  const results = RULES.map((rule) => {
    let clean;
    try {
      clean = Boolean(rule.check(facts));
    } catch {
      clean = false; // fail closed, same contract as the canary machine
    }
    return Object.freeze({ id: rule.id, title: rule.title, clean });
  });
  const violations = results.filter((r) => !r.clean).map((r) => r.id);
  return Object.freeze({
    clean: violations.length === 0,
    violations: Object.freeze(violations),
    results: Object.freeze(results),
  });
}

function validateAllRules(validator = new SocraticCanaryValidator()) {
  const clean = new CanaryFixture('clean', CLEAN_STATE, true);
  const results = RULES.map((rule) => validator.validate(
    rule.id,
    rule.check,
    new CanaryFixture(`${rule.id}-violating`, violatingStateFor(rule.id), false),
    clean,
  ));
  const rejected = results.filter((r) => !r.accepted).map((r) => r.candidateId);
  return Object.freeze({
    total: results.length,
    accepted: results.length - rejected.length,
    rejected: Object.freeze(rejected),
    results: Object.freeze(results),
  });
}

module.exports = {
  MIN_COVERAGE_THRESHOLD,
  RULES,
  CLEAN_STATE,
  ruleById,
  violatingStateFor,
  evaluateRules,
  validateAllRules,
};
