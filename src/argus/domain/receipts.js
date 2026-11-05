'use strict';

// Accessible Merkle-sealed approval receipts (Aletheia).
// The receipt binds four facts into one Merkle root: the change digest,
// the approver, the decision and the moment. It renders three ways from
// the same root: plain text, a spoken sentence for screen readers and
// voice, and a Braille-ready line (Grade 1 letter mapping).

const { ValidationError } = require('./errors.js');
const { sha256Hex } = require('./digest.js');

function merkleRoot(leaves) {
  if (!leaves || leaves.length === 0) {
    throw new ValidationError('merkle tree needs at least one leaf');
  }
  let level = leaves.map((leaf) => sha256Hex(leaf));
  while (level.length > 1) {
    if (level.length % 2 === 1) level.push(level[level.length - 1]);
    const next = [];
    for (let i = 0; i < level.length; i += 2) next.push(sha256Hex(level[i] + level[i + 1]));
    level = next;
  }
  return level[0];
}

// Code points verified against the Python _BRAILLE map on 2026-11-03.
const BRAILLE = Object.freeze({
  a: '\u2801', b: '\u2803', c: '\u2809', d: '\u2819', e: '\u2811', f: '\u280b',
  g: '\u281b', h: '\u2813', i: '\u280a', j: '\u281a', k: '\u2805', l: '\u2807',
  m: '\u280d', n: '\u281d', o: '\u2815', p: '\u280f', q: '\u281f', r: '\u2817',
  s: '\u280e', t: '\u281e', u: '\u2825', v: '\u2827', w: '\u283a', x: '\u282d',
  y: '\u283d', z: '\u2835', ' ': ' ',
  0: '\u281a', 1: '\u2801', 2: '\u2803', 3: '\u2809', 4: '\u2819', 5: '\u2811',
  6: '\u280b', 7: '\u281b', 8: '\u2813', 9: '\u280a',
});

function toBraille(text) {
  return [...text].map((ch) => BRAILLE[ch.toLowerCase()] ?? ' ').join('');
}

class ApprovalReceipt {
  constructor(changeDigest, approver, decision, decidedAt, root) {
    this.changeDigest = changeDigest;
    this.approver = approver;
    this.decision = decision;
    this.decidedAt = decidedAt;
    this.root = root;
    Object.freeze(this);
  }

  leaves() {
    return [this.changeDigest, this.approver, this.decision, this.decidedAt];
  }

  plainText() {
    return (
      `Decision: ${this.decision}. Approver: ${this.approver}. ` +
      `At: ${this.decidedAt}. Change: ${this.changeDigest}. Seal: ${this.root}.`
    );
  }

  spokenText() {
    return (
      `Approval receipt. ${this.approver} ${this.decision} the change ` +
      `ending ${this.changeDigest.slice(-6)} at ${this.decidedAt}. ` +
      `Seal ending ${this.root.slice(-6)}.`
    );
  }

  brailleText() {
    return toBraille(this.spokenText());
  }
}

function buildReceipt(changeDigest, approver, decision, decidedAt) {
  if (decision !== 'approved' && decision !== 'rejected') {
    throw new ValidationError('decision must be approved or rejected');
  }
  if (!changeDigest || !approver || !decidedAt) {
    throw new ValidationError('receipt needs digest, approver and time');
  }
  const leaves = [changeDigest, approver, decision, decidedAt];
  return new ApprovalReceipt(changeDigest, approver, decision, decidedAt, merkleRoot(leaves));
}

function verifyReceipt(receipt) {
  return merkleRoot(receipt.leaves()) === receipt.root;
}

module.exports = { merkleRoot, toBraille, ApprovalReceipt, buildReceipt, verifyReceipt };
