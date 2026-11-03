'use strict';

// Maintained unit tests for the Argus pure core (JS port).
// Mirror of argus-aws-msp tests/test_argus_core.py, minus the Python-only
// gate-script tests. The pinned hex values below were produced by the
// Python core, not by this port:
//   python temp/reference_values.py   (2026-11-03, argus-aws-msp src)
// If a pinned digest fails here, the port is wrong. Do not update the pin
// from JS output.
//
// Run: node --test tests/

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  CanaryFixture,
  SocraticCanaryValidator,
  ChangeOp,
  OpKind,
  TypedChangeIR,
  EvidenceGraph,
  EvidenceItem,
  EvidenceSource,
  PolicyShield,
  RiskClass,
  ShieldMode,
  ToolCall,
  TriageDecision,
  ProvenanceNode,
  ProvenanceThread,
  Engineer,
  StandbyRoster,
  buildReceipt,
  verifyReceipt,
  ValidationError,
  RefusedError,
  DigestMismatchError,
} = require('../src/argus/index.js');
const {
  InMemoryEvaluator,
  InMemoryReader,
  InMemoryWriter,
} = require('../src/argus/adapters/in_memory.js');

const PYTHON_CHANGE_DIGEST =
  'ae685f4aeb54c6f2a77706c21278760d18291084022f1b88d2f98b7b5cd53b8d';
const PYTHON_SEAL =
  'dd00aa153ceee2f71ee904a019f4d1b31e7107e022bb55d158c519306d8ab699';
const PYTHON_RECEIPT_ROOT =
  '6f23369bffead43003aa2078eb2117b8366276d41e33b12f05816ac6c5b12a0d';

function makeChange() {
  return new TypedChangeIR(
    'chg-1',
    'Close public access',
    [new ChangeOp(OpKind.SET_CONFIG, 'acct/policy', 'public', 'false')],
    { evidenceClaims: ['claim-1'] },
  );
}

function makeThread() {
  const t = new ProvenanceThread();
  t.add(new ProvenanceNode('c1', 'commit', 'opened access', 'dev', '2026-11-03T00:00:00Z'));
  t.add(new ProvenanceNode('d1', 'deploy', 'deployed c1', 'pipe', '2026-11-03T01:00:00Z', 'c1'));
  t.add(new ProvenanceNode('i1', 'incident', 'P1 alarm', 'monitor', '2026-11-03T02:00:00Z', 'd1'));
  return t;
}

test('provenance: walk back finds root cause', () => {
  const t = makeThread();
  assert.deepEqual(t.walkBack('i1').map((n) => n.nodeId), ['i1', 'd1', 'c1']);
  assert.equal(t.rootCause('i1').nodeId, 'c1');
});

test('provenance: seal detects tampering and matches Python', () => {
  const t = makeThread();
  const seal = t.seal('i1');
  assert.equal(seal, PYTHON_SEAL);
  assert.equal(t.verifySeal('i1', seal), true);
  assert.equal(t.verifySeal('i1', '0'.repeat(64)), false);
});

test('provenance: unknown parent rejected', () => {
  assert.throws(
    () => new ProvenanceThread().add(new ProvenanceNode('x', 'deploy', 's', 'a', 't', 'missing')),
    ValidationError,
  );
});

test('evidence: seven sources, completeness and grounding', () => {
  const g = new EvidenceGraph();
  Object.values(EvidenceSource).forEach((source, i) => {
    g.add(new EvidenceItem(`e${i}`, source, 'finding', { supports: ['claim-1'] }));
  });
  assert.equal(g.isComplete(), true);
  assert.equal(g.isGrounded(['claim-1']), true);
  assert.equal(g.isGrounded(['claim-unknown']), false);
  assert.deepEqual(g.ungrounded(['claim-unknown']), ['claim-unknown']);
});

test('evidence: missing source is named', () => {
  const g = new EvidenceGraph();
  g.add(new EvidenceItem('e0', EvidenceSource.LOGS, 'only logs'));
  assert.ok(g.missingSources().has(EvidenceSource.PIPELINE));
});

test('change IR: digest is stable, content addressed, matches Python', () => {
  assert.equal(makeChange().digest(), PYTHON_CHANGE_DIGEST);
  assert.equal(makeChange().digest(), makeChange().digest());
  const other = new TypedChangeIR('chg-2', 'Close public access', makeChange().ops);
  assert.notEqual(makeChange().digest(), other.digest());
});

test('change IR: raw shell is rejected', () => {
  assert.throws(
    () => new ChangeOp(OpKind.SET_CONFIG, 'acct/policy', 'public', 'false; rm -rf /'),
    ValidationError,
  );
});

test('change IR: role lenses share one change, exact Python strings', () => {
  const change = makeChange();
  assert.equal(
    change.renderForRole('director'),
    'Close public access. 1 step(s). Digest ae685f4aeb54.',
  );
  assert.equal(
    change.renderForRole('secops'),
    'Close public access. Ops: set_config:acct/policy. Claims: claim-1.',
  );
  assert.equal(
    change.renderForRole('standby'),
    'Approve chg-1? Close public access. Ops: set_config:acct/policy.',
  );
  assert.throws(() => change.renderForRole('nobody'), ValidationError);
});

const violating = () => new CanaryFixture('violating', { policy: 'open' }, false);
const clean = () => new CanaryFixture('clean', { policy: 'private' }, true);

test('canary: separating check accepted with exit contract', () => {
  const v = new SocraticCanaryValidator();
  const r = v.validate('good', (s) => s.policy === 'private', violating(), clean());
  assert.equal(r.accepted, true);
  assert.deepEqual([r.violatingExit, r.cleanExit], [1, 0]);
});

test('canary: defective check is thrown out', () => {
  const v = new SocraticCanaryValidator();
  assert.equal(v.validate('lax', () => true, violating(), clean()).accepted, false);
});

test('canary: overstrict check is thrown out', () => {
  const v = new SocraticCanaryValidator();
  assert.equal(v.validate('strict', () => false, violating(), clean()).accepted, false);
});

test('canary: crashing check fails closed', () => {
  const v = new SocraticCanaryValidator();
  const r = v.validate('boom', () => { throw new Error('crash'); }, violating(), clean());
  assert.equal(r.accepted, false);
  assert.equal(r.cleanExit, 1);
});

test('canary: evaluator port uses same contract', () => {
  const e = new InMemoryEvaluator(violating(), clean());
  assert.equal(e.runCanary('good', (s) => s.policy === 'private').accepted, true);
});

test('canary: swapped fixtures rejected', () => {
  const v = new SocraticCanaryValidator();
  assert.throws(() => v.validate('x', () => true, clean(), violating()), ValidationError);
});

test('shield: observe records but does not refuse, then enforce refuses', () => {
  const shield = new PolicyShield();
  const risky = new ToolCall('tool', 'r1', RiskClass.DESTRUCTIVE_WRITE, true);
  assert.equal(shield.evaluate(risky), TriageDecision.PROCEED);
  const benign = new ToolCall('tool', 'r1', RiskClass.BENIGN, true);
  for (let i = 0; i < shield.minObservations; i += 1) shield.evaluate(benign);
  shield.promoteToEnforce('r1');
  assert.equal(shield.mode('r1'), ShieldMode.ENFORCE);
  assert.equal(shield.evaluate(risky), TriageDecision.CONFIRM);
});

test('shield: promotion blocked before thresholds', () => {
  assert.throws(() => new PolicyShield().promoteToEnforce('r-new'), ValidationError);
});

test('shield: high false alarm rate blocks promotion', () => {
  const shield = new PolicyShield();
  const risky = new ToolCall('tool', 'r2', RiskClass.DESTRUCTIVE_WRITE, true);
  for (let i = 0; i < shield.minObservations; i += 1) shield.evaluate(risky);
  for (let i = 0; i < 5; i += 1) shield.labelFalseAlarm('r2');
  const [ok] = shield.canPromote('r2');
  assert.equal(ok, false);
});

test('shield: exfiltration denied, ungrounded confirmed', () => {
  const shield = new PolicyShield();
  assert.equal(
    shield.triage(new ToolCall('tool', 'r3', RiskClass.EXFILTRATION, true)),
    TriageDecision.DENY,
  );
  assert.equal(
    shield.triage(new ToolCall('tool', 'r3', RiskClass.BENIGN, false)),
    TriageDecision.CONFIRM,
  );
});

const engineers = () => [
  new Engineer('e1', 'Nikos'),
  new Engineer('e2', 'Maria'),
  new Engineer('e3', 'Alex'),
];

test('standby: primary inside window then failover', () => {
  const roster = new StandbyRoster(engineers(), { ackWindowSeconds: 900 });
  assert.equal(roster.whoToPage(60).paged.engineerId, 'e1');
  const outcome = roster.whoToPage(901);
  assert.equal(outcome.paged.engineerId, 'e2');
  assert.equal(outcome.escalated, true);
});

test('standby: rotation offset fixture differs from parameter (C6)', () => {
  const roster = new StandbyRoster(engineers(), { ackWindowSeconds: 900, startIndex: 1 });
  assert.equal(roster.whoToPage(60).paged.engineerId, 'e2');
  assert.equal(roster.whoToPage(901).paged.engineerId, 'e3');
});

test('standby: acknowledgement stops paging', () => {
  const roster = new StandbyRoster(engineers(), { ackWindowSeconds: 900 });
  const outcome = roster.whoToPage(5000, 'e1');
  assert.equal(outcome.paged.engineerId, 'e1');
  assert.equal(outcome.escalated, false);
});

test('receipts: merkle receipt verifies, renders accessibly, matches Python', () => {
  const receipt = buildReceipt(makeChange().digest(), 'nikos', 'approved', '2026-11-03T03:00:00Z');
  assert.equal(receipt.root, PYTHON_RECEIPT_ROOT);
  assert.equal(verifyReceipt(receipt), true);
  assert.ok(receipt.spokenText().includes('approved'));
  assert.ok(receipt.brailleText().trim().length > 0);
});

test('receipts: tampered receipt fails verification', () => {
  const receipt = buildReceipt(makeChange().digest(), 'nikos', 'approved', '2026-11-03T03:00:00Z');
  const tampered = { ...receipt, decision: 'rejected' };
  // merge the plain methods back on for verifyReceipt's leaves() call
  Object.setPrototypeOf(tampered, Object.getPrototypeOf(receipt));
  assert.equal(verifyReceipt(tampered), false);
});

test('least privilege: reader cannot write', () => {
  assert.throws(() => new InMemoryReader().write('x'), RefusedError);
});

test('least privilege: writer requires matching digest', () => {
  const writer = new InMemoryWriter();
  const change = makeChange();
  assert.throws(() => writer.execute(change, '0'.repeat(64)), DigestMismatchError);
  assert.equal(writer.execute(change, change.digest()), 'executed:chg-1');
});
