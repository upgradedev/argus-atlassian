'use strict';

// Domain errors. Callers catch these, never vendor SDK errors.
// Port of argus-aws-msp src/argus/domain/errors.py (2026-11-03).

class ArgusError extends Error {
  constructor(message) {
    super(message);
    this.name = new.target.name;
  }
}

class ValidationError extends ArgusError {}

class RefusedError extends ArgusError {}

class DigestMismatchError extends RefusedError {}

module.exports = { ArgusError, ValidationError, RefusedError, DigestMismatchError };
