'use strict';

// Pre-Tool Policy Shield (Threefold + Lachesis triage).
// Lifecycle per rule: Observe, then Label False Alarms, then Promote to
// Enforce. Promotion is deterministic. It needs enough observations and a
// false-alarm rate at or below the pinned threshold. No model promotes a
// rule, and no caller can skip the observe stage.
// Port of argus-aws-msp src/argus/domain/policy_shield.py (2026-11-03).

const { ValidationError } = require('./errors.js');

const MIN_OBSERVATIONS_TO_PROMOTE = 20;
const MAX_FALSE_ALARM_RATE = 0.05;

const ShieldMode = Object.freeze({ OBSERVE: 'observe', ENFORCE: 'enforce' });

const RiskClass = Object.freeze({
  BENIGN: 'benign',
  DESTRUCTIVE_WRITE: 'destructive_write',
  EXFILTRATION: 'exfiltration',
  UNTRUSTED_TO_ACTION: 'untrusted_to_action',
  CONFUSED_DEPUTY: 'confused_deputy',
});
const RISK_CLASSES = new Set(Object.values(RiskClass));

const TriageDecision = Object.freeze({
  PROCEED: 'proceed',
  GUIDE: 'guide',
  CONFIRM: 'confirm', // interrupt for human approval
  DENY: 'deny',
});

class ToolCall {
  constructor(tool, ruleId, risk, grounded) {
    if (!tool || !ruleId) throw new ValidationError('tool call needs tool and rule_id');
    if (!RISK_CLASSES.has(risk)) throw new ValidationError(`unknown risk class ${risk}`);
    this.tool = tool;
    this.ruleId = ruleId;
    this.risk = risk;
    this.grounded = grounded; // every argument traces to cited evidence
    Object.freeze(this);
  }
}

class PolicyShield {
  constructor({
    minObservations = MIN_OBSERVATIONS_TO_PROMOTE,
    maxFalseAlarmRate = MAX_FALSE_ALARM_RATE,
  } = {}) {
    this.minObservations = minObservations;
    this.maxFalseAlarmRate = maxFalseAlarmRate;
    this._rules = new Map();
  }

  _state(ruleId) {
    if (!this._rules.has(ruleId)) {
      this._rules.set(ruleId, {
        mode: ShieldMode.OBSERVE, observations: 0, wouldRefuse: 0, falseAlarms: 0,
      });
    }
    return this._rules.get(ruleId);
  }

  mode(ruleId) {
    return this._state(ruleId).mode;
  }

  falseAlarmRate(ruleId) {
    const state = this._state(ruleId);
    if (state.wouldRefuse === 0) return 0.0;
    return state.falseAlarms / state.wouldRefuse;
  }

  triage(call) {
    // Lachesis pre-tool triage. A score and a gate, never a verdict
    // on ungrounded or exfiltrating calls.
    if (call.risk === RiskClass.EXFILTRATION) return TriageDecision.DENY;
    if (!call.grounded) return TriageDecision.CONFIRM;
    if (call.risk === RiskClass.DESTRUCTIVE_WRITE || call.risk === RiskClass.CONFUSED_DEPUTY) {
      return TriageDecision.CONFIRM;
    }
    if (call.risk === RiskClass.UNTRUSTED_TO_ACTION) return TriageDecision.GUIDE;
    return TriageDecision.PROCEED;
  }

  evaluate(call) {
    // Observe records and lets the call through. Enforce refuses.
    const decision = this.triage(call);
    const state = this._state(call.ruleId);
    state.observations += 1;
    if (decision === TriageDecision.DENY || decision === TriageDecision.CONFIRM) {
      state.wouldRefuse += 1;
      if (state.mode === ShieldMode.OBSERVE) {
        return TriageDecision.PROCEED; // observed, not yet enforced
      }
    }
    return decision;
  }

  labelFalseAlarm(ruleId) {
    const state = this._state(ruleId);
    if (state.falseAlarms >= state.wouldRefuse) {
      throw new ValidationError('no observed refusal left to label as false alarm');
    }
    state.falseAlarms += 1;
  }

  canPromote(ruleId) {
    const state = this._state(ruleId);
    if (state.mode === ShieldMode.ENFORCE) return [false, 'already enforcing'];
    if (state.observations < this.minObservations) {
      return [false, `needs ${this.minObservations} observations, has ${state.observations}`];
    }
    const rate = this.falseAlarmRate(ruleId);
    if (state.wouldRefuse && rate > this.maxFalseAlarmRate) {
      return [false, `false alarm rate ${rate.toFixed(3)} above ${this.maxFalseAlarmRate.toFixed(3)}`];
    }
    return [true, 'promotion thresholds met'];
  }

  promoteToEnforce(ruleId) {
    const [ok, reason] = this.canPromote(ruleId);
    if (!ok) throw new ValidationError(`cannot promote ${ruleId}: ${reason}`);
    this._state(ruleId).mode = ShieldMode.ENFORCE;
  }
}

module.exports = {
  MIN_OBSERVATIONS_TO_PROMOTE,
  MAX_FALSE_ALARM_RATE,
  ShieldMode,
  RiskClass,
  TriageDecision,
  ToolCall,
  PolicyShield,
};
