'use strict';

// Typed Change IR (ARKON pattern). Never raw shell.
// A change is a list of typed operations over typed targets. Free-form
// command strings are rejected at construction, so a model can propose an
// operation but can never smuggle an arbitrary command past the gate.

const { ValidationError } = require('./errors.js');
const { digestPayload } = require('./digest.js');

const OpKind = Object.freeze({
  SET_CONFIG: 'set_config',
  REVOKE_ACCESS: 'revoke_access',
  GRANT_ACCESS: 'grant_access',
  ADD_RULE: 'add_rule',
  REMOVE_RULE: 'remove_rule',
  RESTART_COMPONENT: 'restart_component',
  ROLLBACK: 'rollback',
  NOTIFY: 'notify',
});
const OP_KINDS = new Set(Object.values(OpKind));

const FORBIDDEN_VALUE_TOKENS = Object.freeze([';', '&&', '||', '|', '`', '$(', '\n', '\r']);

class ChangeOp {
  constructor(kind, target, field = '', value = '') {
    if (!OP_KINDS.has(kind)) throw new ValidationError(`unknown op kind ${kind}`);
    if (!target) throw new ValidationError('change op needs a target');
    if ((kind === OpKind.SET_CONFIG || kind === OpKind.ADD_RULE) && !field) {
      throw new ValidationError(`${kind} needs a field`);
    }
    for (const text of [target, field, value]) {
      for (const token of FORBIDDEN_VALUE_TOKENS) {
        if (text.includes(token)) {
          throw new ValidationError('raw shell syntax is not a Typed Change IR value');
        }
      }
    }
    this.kind = kind;
    this.target = target;
    this.field = field;
    this.value = value;
    Object.freeze(this);
  }

  asDict() {
    return { kind: this.kind, target: this.target, field: this.field, value: this.value };
  }
}

class TypedChangeIR {
  constructor(changeId, title, ops, { evidenceClaims = [], preventionRule = '' } = {}) {
    if (!changeId || !title) throw new ValidationError('change IR needs id and title');
    if (!ops || ops.length === 0) throw new ValidationError('change IR needs at least one op');
    this.changeId = changeId;
    this.title = title;
    this.ops = Object.freeze([...ops]);
    this.evidenceClaims = Object.freeze([...evidenceClaims]);
    this.preventionRule = preventionRule;
    Object.freeze(this);
  }

  digest() {
    // Content-addressed SHA-256. Approval binds to this exact value.
    // Payload keys match the Python core byte for byte (pinned in tests).
    return digestPayload({
      change_id: this.changeId,
      title: this.title,
      ops: this.ops.map((op) => op.asDict()),
      evidence_claims: [...this.evidenceClaims],
      prevention_rule: this.preventionRule,
    });
  }

  renderForRole(role) {
    // One change, three lenses. Same digest under every lens.
    const opLines = this.ops.map((op) => `${op.kind}:${op.target}`).join(', ');
    const lenses = {
      director: `${this.title}. ${this.ops.length} step(s). Digest ${this.digest().slice(0, 12)}.`,
      secops: `${this.title}. Ops: ${opLines}. Claims: ${this.evidenceClaims.join(',') || 'none'}.`,
      standby: `Approve ${this.changeId}? ${this.title}. Ops: ${opLines}.`,
    };
    if (!(role in lenses)) throw new ValidationError(`unknown role lens ${role}`);
    return lenses[role];
  }
}

module.exports = { OpKind, FORBIDDEN_VALUE_TOKENS, ChangeOp, TypedChangeIR };
