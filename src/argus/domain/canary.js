'use strict';

// Socratic Canary Validator (Elenchos kill-test).
// The contract is an exit code, not an opinion:
// violating fixture -> exit 1, clean fixture -> exit 0.
// A candidate rule is accepted only when it separates the two fixtures.
// A candidate that passes the violating fixture, or fails the clean one,
// is thrown out before any human sees it.
//
// Elenchos rules r01-r20 (domain/rules.js) are validated through this
// kill-test machine.

const { ValidationError } = require('./errors.js');

const CANARY_MARKER = 'ELENCHOS-CANARY';
const EXIT_CLEAN = 0;
const EXIT_VIOLATING = 1;

class CanaryFixture {
  constructor(name, state, expectClean) {
    if (!name) throw new ValidationError('fixture needs a name');
    this.name = name;
    this.state = Object.freeze({ ...state });
    this.expectClean = expectClean;
    Object.freeze(this);
  }
}

class CanaryResult {
  constructor(candidateId, violatingExit, cleanExit, accepted, reason) {
    this.candidateId = candidateId;
    this.violatingExit = violatingExit;
    this.cleanExit = cleanExit;
    this.accepted = accepted;
    this.reason = reason;
    Object.freeze(this);
  }
}

function runCheck(check, fixture) {
  // Map a boolean check onto the exit-code contract. Fail closed.
  let clean;
  try {
    clean = Boolean(check(fixture.state));
  } catch {
    return EXIT_VIOLATING; // a crashing check proves nothing
  }
  return clean ? EXIT_CLEAN : EXIT_VIOLATING;
}

class SocraticCanaryValidator {
  validate(candidateId, check, violating, clean) {
    if (violating.expectClean || !clean.expectClean) {
      throw new ValidationError(
        'fixtures are swapped: violating must expect dirty, clean must expect clean',
      );
    }
    const violatingExit = runCheck(check, violating);
    const cleanExit = runCheck(check, clean);
    if (violatingExit !== EXIT_VIOLATING) {
      return new CanaryResult(candidateId, violatingExit, cleanExit, false,
        'thrown out: candidate passed the violating canary');
    }
    if (cleanExit !== EXIT_CLEAN) {
      return new CanaryResult(candidateId, violatingExit, cleanExit, false,
        'thrown out: candidate failed clean traffic');
    }
    return new CanaryResult(candidateId, violatingExit, cleanExit, true,
      'separates violating (exit 1) from clean (exit 0)');
  }
}

module.exports = {
  CANARY_MARKER,
  EXIT_CLEAN,
  EXIT_VIOLATING,
  CanaryFixture,
  CanaryResult,
  runCheck,
  SocraticCanaryValidator,
};
