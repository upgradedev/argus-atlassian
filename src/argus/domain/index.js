'use strict';

// Barrel for the pure domain. No module under domain/ imports a Forge,
// Atlassian, or LLM SDK. The only platform import in the package is
// node:crypto (Node standard library) inside domain/digest.js.

module.exports = {
  ...require('./errors.js'),
  ...require('./canary.js'),
  ...require('./change_ir.js'),
  ...require('./evidence.js'),
  ...require('./policy_shield.js'),
  ...require('./ports.js'),
  ...require('./provenance.js'),
  ...require('./pipeline_facts.js'),
  ...require('./pipeline_repair.js'),
  ...require('./receipts.js'),
  ...require('./rules.js'),
  ...require('./standby.js'),
};
