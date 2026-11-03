'use strict';

// In-memory adapters. The shared test double for every platform.
// AWS and Atlassian adapters replace these at the edge. Domain tests run
// against this module unchanged in both products.
// Port of argus-aws-msp src/argus/adapters/in_memory.py (2026-11-03).

const { SocraticCanaryValidator } = require('../domain/canary.js');
const { guardReaderWriteAttempt, verifyBeforeWrite } = require('../domain/ports.js');

class InMemoryReader {
  constructor(evidence = {}) {
    this._evidence = { ...evidence };
  }

  fetchEvidence(incidentId) {
    return { ...(this._evidence[incidentId] ?? {}) };
  }

  write() {
    guardReaderWriteAttempt('write');
  }
}

class InMemoryEvaluator {
  // Runs the canary pair in-process. Stands in for the deny-all sandbox.
  constructor(violating, clean) {
    this._validator = new SocraticCanaryValidator();
    this._violating = violating;
    this._clean = clean;
  }

  runCanary(candidateId, check) {
    return this._validator.validate(candidateId, check, this._violating, this._clean);
  }
}

class InMemoryWriter {
  constructor() {
    this.executed = [];
  }

  execute(change, approvedDigest) {
    verifyBeforeWrite(change, approvedDigest);
    this.executed.push(change.changeId);
    return `executed:${change.changeId}`;
  }
}

class FixedClock {
  constructor(instant) {
    this._instant = instant;
  }

  nowIso() {
    return this._instant;
  }
}

module.exports = { InMemoryReader, InMemoryEvaluator, InMemoryWriter, FixedClock };
