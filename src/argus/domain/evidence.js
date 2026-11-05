'use strict';

// Seven-source Evidence Graph (SupportTrace).
// Sources are generic kinds, not vendor products, so adapters map their
// platform onto these seven kinds and keep the vendor name in platformLabel.

const { ValidationError } = require('./errors.js');

const EvidenceSource = Object.freeze({
  LOGS: 'logs', // Atlassian: audit log
  IDENTITY: 'identity', // Atlassian: directory and permissions
  EDGE: 'edge', // Atlassian: gateway and access policy
  EVENTS: 'events', // Atlassian: webhooks
  CONFIG: 'config', // Atlassian: project and workflow config
  DATA: 'data', // Atlassian: issues and pages
  PIPELINE: 'pipeline', // Atlassian: Bitbucket pipelines
});
const SOURCES = new Set(Object.values(EvidenceSource));
const REQUIRED_SOURCES = Object.freeze(new Set(SOURCES));

class EvidenceItem {
  constructor(itemId, source, summary, { platformLabel = '', supports = [] } = {}) {
    if (!itemId || !summary) throw new ValidationError('evidence item needs id and summary');
    if (!SOURCES.has(source)) throw new ValidationError(`unknown evidence source ${source}`);
    this.itemId = itemId;
    this.source = source;
    this.summary = summary;
    this.platformLabel = platformLabel;
    this.supports = Object.freeze([...supports]);
    Object.freeze(this);
  }
}

class EvidenceGraph {
  constructor() {
    this.items = new Map();
  }

  add(item) {
    if (this.items.has(item.itemId)) {
      throw new ValidationError(`duplicate evidence item ${item.itemId}`);
    }
    this.items.set(item.itemId, item);
  }

  sourcesPresent() {
    return new Set([...this.items.values()].map((item) => item.source));
  }

  missingSources() {
    const present = this.sourcesPresent();
    return new Set([...REQUIRED_SOURCES].filter((source) => !present.has(source)));
  }

  isComplete() {
    return this.missingSources().size === 0;
  }

  groundedClaims() {
    const claims = new Set();
    for (const item of this.items.values()) {
      for (const claim of item.supports) claims.add(claim);
    }
    return claims;
  }

  isGrounded(claimIds) {
    // Yes only when every claimed id traces to cited evidence.
    const grounded = this.groundedClaims();
    return claimIds.length > 0 && claimIds.every((id) => grounded.has(id));
  }

  ungrounded(claimIds) {
    const grounded = this.groundedClaims();
    return claimIds.filter((id) => !grounded.has(id));
  }
}

module.exports = { EvidenceSource, REQUIRED_SOURCES, EvidenceItem, EvidenceGraph };
