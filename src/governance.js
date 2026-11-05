'use strict';

// Stored proposal and approval governance.
// This module owns the lifecycle the Rovo actions expose:
//   proposed -> verified -> executed (with a sealed receipt)
// A valid digest binds a human approval to one stored Typed Change IR.
// The writer is invoked only after the domain digest guard passes, an
// executed envelope refuses replay, and missing live infrastructure is
// reported as verified-dry-run rather than claimed as execution.

const {
  ArgusError,
  ChangeOp,
  DigestMismatchError,
  Engineer,
  OpKind,
  PolicyShield,
  RiskClass,
  StandbyRoster,
  ToolCall,
  TypedChangeIR,
  ValidationError,
  buildReceipt,
  repairFactsForRule,
  repairPipelineYaml,
  ruleById,
  verifyBeforeWrite,
} = require('./argus/index.js');

function serializeChange(change) {
  return {
    changeId: change.changeId,
    title: change.title,
    ops: change.ops.map((op) => op.asDict()),
    evidenceClaims: [...change.evidenceClaims],
    preventionRule: change.preventionRule,
    digest: change.digest(),
  };
}

function deserializeChange(serialized) {
  if (!serialized || typeof serialized !== 'object') {
    throw new ValidationError('stored change is missing');
  }
  const change = new TypedChangeIR(
    serialized.changeId,
    serialized.title,
    (serialized.ops ?? []).map(
      (op) => new ChangeOp(op.kind, op.target, op.field ?? '', op.value ?? ''),
    ),
    {
      evidenceClaims: serialized.evidenceClaims ?? [],
      preventionRule: serialized.preventionRule ?? '',
    },
  );
  if (serialized.digest && serialized.digest !== change.digest()) {
    throw new ValidationError('stored change digest does not match its content');
  }
  return change;
}

function receiptToPlain(receipt) {
  return {
    changeDigest: receipt.changeDigest,
    approver: receipt.approver,
    decision: receipt.decision,
    decidedAt: receipt.decidedAt,
    root: receipt.root,
    plainText: receipt.plainText(),
    spoken: receipt.spokenText(),
    braille: receipt.brailleText(),
  };
}

function publicEnvelope(envelope, storageMode) {
  if (!envelope) return null;
  const change = deserializeChange(envelope.change);
  return Object.freeze({
    version: envelope.version,
    status: envelope.status,
    storage: storageMode,
    changeId: envelope.changeId,
    issueKey: envelope.issueKey,
    ruleId: envelope.ruleId,
    proposedBy: envelope.proposedBy ?? '',
    createdAt: envelope.createdAt,
    digest: change.digest(),
    change: serializeChange(change),
    director: change.renderForRole('director'),
    secops: change.renderForRole('secops'),
    standby: change.renderForRole('standby'),
    receipt: envelope.receipt ?? null,
    shield: envelope.shield ?? null,
    executions: envelope.executions ?? {},
    repairPr: envelope.repairPr ?? null,
    executedAt: envelope.executedAt ?? null,
    assignedTo: envelope.assignedTo ?? '',
  });
}

function sanitizeKey(value) {
  return String(value).replace(/[^A-Za-z0-9._-]/g, '-');
}

function refused(reason, extra = {}) {
  return Object.freeze({
    status: 'refused', verified: false, executed: false, reason, ...extra,
  });
}

function createGovernance({
  store,
  writer = null,
  clock = { nowIso: () => new Date().toISOString() },
  storageMode = store?.mode ?? 'unknown-store',
  shield = new PolicyShield(),
} = {}) {
  if (!store || typeof store.get !== 'function' || typeof store.set !== 'function') {
    throw new ValidationError('governance requires an async key-value plan store');
  }

  function evaluateShield(toolName, ruleId, risk, grounded = true) {
    const call = new ToolCall(toolName, ruleId, risk, grounded);
    const triage = shield.triage(call);
    const effectiveDecision = shield.evaluate(call);
    const [promotable, promotionReason] = shield.canPromote(ruleId);
    return Object.freeze({
      ruleId,
      mode: shield.mode(ruleId),
      triage,
      effectiveDecision,
      falseAlarmRate: shield.falseAlarmRate(ruleId),
      promotable,
      promotionReason,
    });
  }

  async function nextSequence(issueKey, ruleId) {
    const key = `counter:${sanitizeKey(issueKey)}:${ruleId}`;
    const current = Number(await store.get(key) ?? 0);
    const next = Number.isFinite(current) ? current + 1 : 1;
    await store.set(key, next);
    return next;
  }

  async function loadEnvelope({ issueKey = '', changeId = '' } = {}) {
    let resolvedId = changeId;
    if (!resolvedId && issueKey) resolvedId = await store.get(`latest:${issueKey}`);
    if (!resolvedId) return null;
    const envelope = await store.get(`proposal:${resolvedId}`);
    return envelope ?? null;
  }

  async function propose({ issueKey = '', ruleId = '', proposedBy = '' } = {}) {
    if (!issueKey) throw new ValidationError('issueKey input is required');
    if (!ruleId) throw new ValidationError('ruleId input is required');
    const rule = ruleById(ruleId);
    const sequence = await nextSequence(issueKey, ruleId);
    const changeId = `proposal-${sanitizeKey(issueKey)}-${ruleId}-${sequence}`;
    const change = new TypedChangeIR(
      changeId,
      `Repair proposal for ${rule.id}: ${rule.title}`,
      repairFactsForRule(ruleId).map(
        (fact) => new ChangeOp(
          OpKind.SET_CONFIG,
          'bitbucket-pipelines.yml',
          fact.field,
          fact.value,
        ),
      ),
      {
        evidenceClaims: [`${issueKey}:${ruleId}`],
        preventionRule: ruleId,
      },
    );
    const shieldReport = evaluateShield('propose-typed-change', ruleId, RiskClass.BENIGN, true);
    const envelope = {
      version: 1,
      status: 'proposed',
      changeId,
      issueKey,
      ruleId,
      proposedBy,
      createdAt: clock.nowIso(),
      change: serializeChange(change),
      receipt: null,
      shield: shieldReport,
      executions: {},
      repairPr: null,
    };
    await store.set(`proposal:${changeId}`, envelope);
    await store.set(`latest:${issueKey}`, changeId);
    return publicEnvelope(envelope, storageMode);
  }

  async function getProposal(args = {}) {
    return publicEnvelope(await loadEnvelope(args), storageMode);
  }

  function priorExecution(envelope, kind) {
    if (envelope.executions?.[kind]) return envelope.executions[kind];
    // Envelopes written before per-action execution records used the
    // umbrella status. Treat those as consumed for every write kind.
    if (!envelope.executions && envelope.status === 'executed') return { legacy: true };
    return null;
  }

  function selectResponder({ standbyAccountId = '', roster = null, elapsedSeconds = 0 }) {
    if (standbyAccountId) {
      return { accountId: standbyAccountId, escalated: false, reason: 'standby account supplied' };
    }
    if (!Array.isArray(roster) || roster.length === 0) return null;
    const engineers = roster.map((entry) => new Engineer(
      entry.accountId ?? entry.id,
      entry.name ?? entry.accountId ?? entry.id,
      entry.reachable !== false,
    ));
    const outcome = new StandbyRoster(engineers)
      .whoToPage(Number(elapsedSeconds ?? 0));
    return {
      accountId: outcome.paged.engineerId,
      escalated: outcome.escalated,
      reason: outcome.reason,
    };
  }

  async function approveAndEscalate({
    issueKey = '',
    changeId = '',
    approvalDigest = '',
    standbyAccountId = '',
    roster = null,
    elapsedSeconds = 0,
    approvedBy = '',
  } = {}) {
    try {
      if (!/^[0-9a-f]{64}$/.test(approvalDigest)) {
        return refused('approvalDigest must be a lowercase hex SHA-256 digest');
      }
      const envelope = await loadEnvelope({ issueKey, changeId });
      if (!envelope) return refused('no stored approved plan exists for this issue');
      if (issueKey && envelope.issueKey !== issueKey) {
        return refused('stored plan belongs to a different issue');
      }
      if (priorExecution(envelope, 'escalation')) {
        return refused('stored plan standby escalation was already executed; create a new proposal');
      }

      const change = deserializeChange(envelope.change);
      try {
        verifyBeforeWrite(change, approvalDigest);
      } catch (err) {
        if (err instanceof DigestMismatchError) return refused(err.message);
        throw err;
      }

      const shieldReport = evaluateShield(
        'escalate-standby-responder',
        envelope.ruleId,
        RiskClass.DESTRUCTIVE_WRITE,
        true,
      );
      const selected = selectResponder({ standbyAccountId, roster, elapsedSeconds });
      if (!selected) {
        return Object.freeze({
          status: 'verified',
          verified: true,
          executed: false,
          changeId: envelope.changeId,
          digest: change.digest(),
          shield: shieldReport,
          reason: 'plan verified; no standby responder was selected',
        });
      }

      if (!writer) {
        return Object.freeze({
          status: 'verified-dry-run',
          verified: true,
          executed: false,
          changeId: envelope.changeId,
          digest: change.digest(),
          wouldAssignTo: selected.accountId,
          escalated: selected.escalated,
          shield: shieldReport,
          reason: `${selected.reason}; no live Atlassian writer is connected`,
        });
      }

      const result = await writer.escalateWithApproval(
        change,
        approvalDigest,
        envelope.issueKey,
        selected.accountId,
      );
      const receipt = receiptToPlain(buildReceipt(
        change.digest(),
        approvedBy || 'unknown-approver',
        'approved',
        clock.nowIso(),
      ));
      const executedAt = clock.nowIso();
      const executedEnvelope = {
        ...envelope,
        status: 'executed',
        executedAt,
        assignedTo: selected.accountId,
        receipt,
        shield: shieldReport,
        executions: {
          ...(envelope.executions ?? {}),
          escalation: { assignedTo: selected.accountId, executedAt, receipt },
        },
      };
      await store.set(`proposal:${envelope.changeId}`, executedEnvelope);

      return Object.freeze({
        status: 'executed',
        verified: true,
        executed: result.executed === true,
        changeId: envelope.changeId,
        digest: change.digest(),
        issueKey: envelope.issueKey,
        assignedTo: selected.accountId,
        escalated: selected.escalated,
        shield: shieldReport,
        receipt,
      });
    } catch (err) {
      if (err instanceof ArgusError) return refused(err.message, { error: err.name });
      throw err;
    }
  }

  async function approveAndOpenRepairPr({
    issueKey = '',
    changeId = '',
    approvalDigest = '',
    approvedBy = '',
    workspace = '',
    repository = '',
    sourceBranch = '',
    pipelinePath = 'bitbucket-pipelines.yml',
    pipelineYaml = '',
    repairer = null,
  } = {}) {
    try {
      if (!/^[0-9a-f]{64}$/.test(approvalDigest)) {
        return refused('approvalDigest must be a lowercase hex SHA-256 digest');
      }
      const envelope = await loadEnvelope({ issueKey, changeId });
      if (!envelope) return refused('no stored approved plan exists for this issue');
      if (issueKey && envelope.issueKey !== issueKey) {
        return refused('stored plan belongs to a different issue');
      }
      if (priorExecution(envelope, 'repairPr')) {
        return refused('stored plan repair PR was already opened; create a new proposal');
      }

      const change = deserializeChange(envelope.change);
      try {
        verifyBeforeWrite(change, approvalDigest);
      } catch (err) {
        if (err instanceof DigestMismatchError) return refused(err.message);
        throw err;
      }

      const shieldReport = evaluateShield(
        'open-repair-pr',
        envelope.ruleId,
        RiskClass.DESTRUCTIVE_WRITE,
        true,
      );
      const repair = typeof pipelineYaml === 'string' && pipelineYaml
        ? repairPipelineYaml(pipelineYaml)
        : null;
      const executeRepair = repairer
        ?? (writer?.openRepairPullRequest
          ? (c, digest, args) => writer.openRepairPullRequest(c, digest, args)
          : null);

      if (!executeRepair) {
        return Object.freeze({
          status: 'verified-dry-run',
          verified: true,
          executed: false,
          changeId: envelope.changeId,
          digest: change.digest(),
          repair,
          shield: shieldReport,
          reason: 'plan verified; no live Bitbucket writer is connected',
        });
      }
      if (!workspace || !repository) {
        return Object.freeze({
          status: 'verified',
          verified: true,
          executed: false,
          changeId: envelope.changeId,
          digest: change.digest(),
          repair,
          shield: shieldReport,
          reason: 'plan verified; workspace and repository are required to open the PR',
        });
      }

      const details = await executeRepair(change, approvalDigest, {
        workspace,
        repository,
        sourceBranch,
        pipelinePath,
        issueKey: envelope.issueKey,
      });
      const receipt = receiptToPlain(buildReceipt(
        change.digest(),
        approvedBy || 'unknown-approver',
        'approved',
        clock.nowIso(),
      ));
      const executedAt = clock.nowIso();
      const executions = {
        ...(envelope.executions ?? {}),
        repairPr: { repairPr: details, executedAt, receipt },
      };
      await store.set(`proposal:${envelope.changeId}`, {
        ...envelope,
        status: executions.escalation ? 'executed' : 'repair-pr-open',
        shield: shieldReport,
        executions,
        repairPr: details,
      });

      return Object.freeze({
        status: 'repair-pr-open',
        verified: true,
        executed: true,
        changeId: envelope.changeId,
        digest: change.digest(),
        issueKey: envelope.issueKey,
        repairPr: details,
        shield: shieldReport,
        receipt,
      });
    } catch (err) {
      if (err instanceof ArgusError) return refused(err.message, { error: err.name });
      throw err;
    }
  }

  return Object.freeze({
    propose,
    getProposal,
    approveAndEscalate,
    approveAndOpenRepairPr,
    storageMode,
  });
}

module.exports = { createGovernance, serializeChange, deserializeChange };
