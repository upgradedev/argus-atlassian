'use strict';

// Argus pure hexagonal core.
// Platform-agnostic on purpose. This package imports no Forge, Atlassian,
// cloud, or LLM SDK. Platform products (AWS MSP, Atlassian) supply adapters
// for the ports in domain/ports.js and reuse every domain rule unchanged.
//
// Ported 2026-11-03 from argus-aws-msp src/argus/ (Python), module by module:
// errors, canary, change_ir, evidence, policy_shield, ports, provenance,
// receipts, standby, plus adapters/in_memory. Equivalence with the Python
// core is proven by pinned digests in tests/argus-core.test.js, which were
// produced by the Python code, not by this port.
//
// Honest gap: the Elenchos rules r01-r20 named in STATE.md J3 do not exist
// in the Python core either. What exists here is the kill-test machine
// (domain/canary.js) that every future rule must pass. Authoring r01-r20
// against Bitbucket pipeline state is separate, later work.

const domain = require('./domain/index.js');

module.exports = {
  VERSION: '0.1.0',
  // canary
  CANARY_MARKER: domain.CANARY_MARKER,
  EXIT_CLEAN: domain.EXIT_CLEAN,
  EXIT_VIOLATING: domain.EXIT_VIOLATING,
  CanaryFixture: domain.CanaryFixture,
  CanaryResult: domain.CanaryResult,
  runCheck: domain.runCheck,
  SocraticCanaryValidator: domain.SocraticCanaryValidator,
  // change IR
  OpKind: domain.OpKind,
  ChangeOp: domain.ChangeOp,
  TypedChangeIR: domain.TypedChangeIR,
  // errors
  ArgusError: domain.ArgusError,
  ValidationError: domain.ValidationError,
  RefusedError: domain.RefusedError,
  DigestMismatchError: domain.DigestMismatchError,
  // evidence
  EvidenceSource: domain.EvidenceSource,
  REQUIRED_SOURCES: domain.REQUIRED_SOURCES,
  EvidenceItem: domain.EvidenceItem,
  EvidenceGraph: domain.EvidenceGraph,
  // policy shield
  ShieldMode: domain.ShieldMode,
  RiskClass: domain.RiskClass,
  TriageDecision: domain.TriageDecision,
  ToolCall: domain.ToolCall,
  PolicyShield: domain.PolicyShield,
  // ports
  guardReaderWriteAttempt: domain.guardReaderWriteAttempt,
  verifyBeforeWrite: domain.verifyBeforeWrite,
  // provenance
  ProvenanceNode: domain.ProvenanceNode,
  ProvenanceThread: domain.ProvenanceThread,
  // receipts
  ApprovalReceipt: domain.ApprovalReceipt,
  buildReceipt: domain.buildReceipt,
  verifyReceipt: domain.verifyReceipt,
  merkleRoot: domain.merkleRoot,
  toBraille: domain.toBraille,
  // Elenchos rules + pipeline facts (authored 2026-11-03, this repo)
  RULES: domain.RULES,
  CLEAN_STATE: domain.CLEAN_STATE,
  MIN_COVERAGE_THRESHOLD: domain.MIN_COVERAGE_THRESHOLD,
  ruleById: domain.ruleById,
  REPAIR_FACTS: domain.REPAIR_FACTS,
  repairFactsForRule: domain.repairFactsForRule,
  violatingStateFor: domain.violatingStateFor,
  evaluateRules: domain.evaluateRules,
  validateAllRules: domain.validateAllRules,
  extractPipelineFacts: domain.extractPipelineFacts,
  repairPipelineYaml: domain.repairPipelineYaml,
  // standby
  Engineer: domain.Engineer,
  PageOutcome: domain.PageOutcome,
  StandbyRoster: domain.StandbyRoster,
};
