'use strict';

// Deterministic textual repairs for the rules where a safe local rewrite
// exists. A repair is counted only when re-evaluating the rewritten YAML
// actually clears that rule. Everything else stays named unsupported.
// Run: node --test

const test = require('node:test');
const assert = require('node:assert/strict');

const { repairPipelineYaml } = require('../src/argus/domain/pipeline_repair.js');
const { evaluateRules } = require('../src/argus/domain/rules.js');
const { extractPipelineFacts } = require('../src/argus/domain/pipeline_facts.js');

const FAKE_GREEN = [
  'image: node:latest',
  'pipelines:',
  '  default:',
  '    - step:',
  '        script:',
  '          - npm install',
  '          - npm test -- --passWithNoTests || true',
  '          - echo done || exit 0',
].join('\n');

const CLEAN = [
  'image: node:20.11',
  'pipelines:',
  '  default:',
  '    - step:',
  '        max-time: 10',
  '        script:',
  '          - npm ci',
  '          - npm test -- --cov-fail-under=85',
].join('\n');

test('repairs clear masked exits, pass-with-no-tests, frozen install, forced success', () => {
  const out = repairPipelineYaml(FAKE_GREEN);
  for (const id of ['r01', 'r05', 'r16', 'r20']) {
    assert.ok(out.applied.includes(id), id);
    assert.ok(!out.remainingViolations.includes(id), id);
  }
  assert.match(out.yaml, /npm ci/);
  assert.doesNotMatch(out.yaml, /passWithNoTests|\|\| true|\|\| exit 0/);
});

test('repair is idempotent and leaves clean YAML byte-identical', () => {
  const clean = repairPipelineYaml(CLEAN);
  assert.equal(clean.yaml, CLEAN);
  assert.deepEqual(clean.applied, []);
  const once = repairPipelineYaml(FAKE_GREEN);
  const twice = repairPipelineYaml(once.yaml);
  assert.equal(twice.yaml, once.yaml);
  assert.deepEqual(twice.applied, []);
});

test('unsupported violations are named, never silently claimed fixed', () => {
  const out = repairPipelineYaml(FAKE_GREEN);
  assert.ok(out.unsupported.includes('r18')); // no safe pin can be invented
  const remaining = evaluateRules(extractPipelineFacts(out.yaml)).violations;
  assert.deepEqual(new Set(out.remainingViolations), new Set(remaining));
});

test('coverage threshold is raised to 80 only when a threshold already exists', () => {
  const low = 'pipelines:\n  default:\n    - step:\n        script:\n          - pytest --cov=app --cov-fail-under=12\n';
  const out = repairPipelineYaml(low);
  assert.ok(out.applied.includes('r06'));
  assert.match(out.yaml, /--cov-fail-under=80/);
});
