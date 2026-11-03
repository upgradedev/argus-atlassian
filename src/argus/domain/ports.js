'use strict';

// Hexagonal ports and the three least-privilege roles (A7).
// Reader can only read. Evaluator can only run checks in a sandbox.
// Writer executes a change only after its digest matches the approved
// digest. Platform adapters implement these shapes; the domain holds
// no credential and no SDK handle.
// Port of argus-aws-msp src/argus/domain/ports.py (2026-11-03).
//
// Expected adapter shapes (duck-typed, since JS has no Protocol):
//   Reader:    fetchEvidence(incidentId) -> object of string to string
//   Evaluator: runCanary(candidateId, checkFn) -> CanaryResult
//   Clock:     nowIso() -> string
//   Writer:    execute(change, approvedDigest) -> string

const { DigestMismatchError, RefusedError } = require('./errors.js');

function guardReaderWriteAttempt(operation) {
  // Shared refusal used by read-only adapters and their tests.
  throw new RefusedError(`reader role cannot perform write operation: ${operation}`);
}

function verifyBeforeWrite(change, approvedDigest) {
  // The one check every Writer adapter must pass before it writes.
  if (!approvedDigest || change.digest() !== approvedDigest) {
    throw new DigestMismatchError(
      'writer refused: approval digest does not match change digest',
    );
  }
}

module.exports = { guardReaderWriteAttempt, verifyBeforeWrite };
