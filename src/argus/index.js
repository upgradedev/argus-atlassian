'use strict';

// Argus pure hexagonal core.
// Platform-agnostic on purpose. This package imports no Forge, Atlassian,
// cloud, or LLM SDK. Platform adapters implement the ports in
// domain/ports.js and reuse every domain rule unchanged.
//
// Core modules: errors, canary, change_ir, evidence, policy_shield, ports,
// provenance, receipts, standby, rules (r01-r20), pipeline_facts,
// pipeline_repair, plus adapters/in_memory.

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
