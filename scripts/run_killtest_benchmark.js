'use strict';

// Socratic Kill-Test benchmark for the Elenchos rules r01-r20.
// This is the command the README Evidence table cites. Read it honestly:
// it measures fixture separation on Argus's own fixtures (every rule
// separates its violating fixture at exit 1 from the shared clean state
// at exit 0, and a badge-only check is thrown out on every fixture).
// It is not a field measurement on customer pipelines, and the output
// says so. Exit 0 only when every rule is accepted.
//
// Run: node scripts/run_killtest_benchmark.js [--json]

const { performance } = require('node:perf_hooks');
const {
  RULES,
  CLEAN_STATE,
  violatingStateFor,
  validateAllRules,
} = require('../src/argus/domain/rules.js');
const {
  CanaryFixture,
  SocraticCanaryValidator,
} = require('../src/argus/domain/canary.js');

const ITERATIONS = 100;

function median(values) {
  const sorted = [...values].sort((a, z) => a - z);
  return sorted[Math.floor(sorted.length / 2)];
}

function main() {
  const asJson = process.argv.includes('--json');

  const samples = [];
  let outcome;
  for (let i = 0; i < ITERATIONS; i += 1) {
    const start = performance.now();
    outcome = validateAllRules();
    samples.push(performance.now() - start);
  }

  const validator = new SocraticCanaryValidator();
  const clean = new CanaryFixture('clean', CLEAN_STATE, true);
  const badgeOnly = (state) => state['pipeline.badge'] === 'green';
  let badgeThrownOut = 0;
  for (const rule of RULES) {
    const result = validator.validate(
      'badge-only',
      badgeOnly,
      new CanaryFixture(`${rule.id}-violating`, violatingStateFor(rule.id), false),
      clean,
    );
    if (!result.accepted) badgeThrownOut += 1;
  }

  const report = {
    rulesTotal: outcome.total,
    rulesAccepted: outcome.accepted,
    rulesRejected: outcome.rejected,
    badgeOnlyThrownOut: badgeThrownOut,
    medianFullValidationMs: Number(median(samples).toFixed(3)),
    iterations: ITERATIONS,
    scope: 'fixture separation on Argus synthetic fixtures, not a field measurement',
    perRule: outcome.results.map((r) => ({
      id: r.candidateId,
      violatingExit: r.violatingExit,
      cleanExit: r.cleanExit,
      accepted: r.accepted,
    })),
  };

  if (asJson) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    process.stdout.write('Elenchos Socratic Kill-Test benchmark\n');
    for (const row of report.perRule) {
      process.stdout.write(
        `${row.id}  violating=exit ${row.violatingExit}  clean=exit ${row.cleanExit}  `
        + `${row.accepted ? 'accepted' : 'THROWN OUT'}\n`,
      );
    }
    process.stdout.write(
      `rules accepted: ${report.rulesAccepted}/${report.rulesTotal}\n`
      + `badge-only check thrown out: ${report.badgeOnlyThrownOut}/${report.rulesTotal}\n`
      + `median full validation: ${report.medianFullValidationMs} ms `
      + `over ${report.iterations} iterations\n`
      + `scope: ${report.scope}\n`,
    );
  }

  process.exit(outcome.accepted === outcome.total ? 0 : 1);
}

main();
