'use strict';

// Provenance Thread (Mitos). Walk an incident back to the causing change.
// Each node seals the node before it with SHA-256, so a broken link is
// detectable without trusting the store that held the chain.
// Port of argus-aws-msp src/argus/domain/provenance.py (2026-11-03).

const { ValidationError } = require('./errors.js');
const { digestPayload } = require('./digest.js');

const MAX_WALK_STEPS = 9;

class ProvenanceNode {
  constructor(nodeId, kind, summary, actor, at, parentId = '') {
    if (!nodeId || !kind || !summary) {
      throw new ValidationError('provenance node needs id, kind and summary');
    }
    this.nodeId = nodeId;
    this.kind = kind;
    this.summary = summary;
    this.actor = actor;
    this.at = at; // ISO-8601 string, supplied by the adapter clock
    this.parentId = parentId;
    Object.freeze(this);
  }

  digest() {
    return digestPayload({
      node_id: this.nodeId,
      kind: this.kind,
      summary: this.summary,
      actor: this.actor,
      at: this.at,
      parent_id: this.parentId,
    });
  }
}

class ProvenanceThread {
  // An ordered chain from root cause (first) to incident (last).
  constructor() {
    this.nodes = new Map();
  }

  add(node) {
    if (this.nodes.has(node.nodeId)) {
      throw new ValidationError(`duplicate provenance node ${node.nodeId}`);
    }
    if (node.parentId && !this.nodes.has(node.parentId)) {
      throw new ValidationError(`unknown parent ${node.parentId}`);
    }
    this.nodes.set(node.nodeId, node);
  }

  walkBack(incidentId, maxSteps = MAX_WALK_STEPS) {
    // Return nodes from the incident back toward the root cause.
    if (maxSteps < 1) throw new ValidationError('max_steps must be at least 1');
    const chain = [];
    const seen = new Set();
    let currentId = incidentId;
    while (currentId && chain.length < maxSteps) {
      if (seen.has(currentId)) throw new ValidationError('cycle in provenance thread');
      seen.add(currentId);
      const node = this.nodes.get(currentId);
      if (node === undefined) {
        throw new ValidationError(`unknown provenance node ${currentId}`);
      }
      chain.push(node);
      currentId = node.parentId;
    }
    return chain;
  }

  rootCause(incidentId, maxSteps = MAX_WALK_STEPS) {
    const chain = this.walkBack(incidentId, maxSteps);
    return chain[chain.length - 1];
  }

  seal(incidentId) {
    // Hash-chain seal over the walk. Changes if any node changes.
    let acc = '';
    for (const node of [...this.walkBack(incidentId)].reverse()) {
      acc = digestPayload({ prev: acc, node: node.digest() });
    }
    return acc;
  }

  verifySeal(incidentId, expected) {
    return this.seal(incidentId) === expected;
  }
}

module.exports = { MAX_WALK_STEPS, ProvenanceNode, ProvenanceThread };
