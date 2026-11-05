'use strict';

// Standby On-Call Roster with deterministic auto-failover.
// Time enters as a number of seconds from the caller's clock port. The
// domain never reads a wall clock, so failover is fully testable.

const { ValidationError } = require('./errors.js');

const DEFAULT_ACK_WINDOW_SECONDS = 900; // 15 minutes to acknowledge a page

class Engineer {
  constructor(engineerId, name, reachable = true) {
    if (!engineerId || !name) throw new ValidationError('engineer needs id and name');
    this.engineerId = engineerId;
    this.name = name;
    this.reachable = reachable;
    Object.freeze(this);
  }
}

class PageOutcome {
  constructor(paged, escalated, reason) {
    this.paged = paged;
    this.escalated = escalated;
    this.reason = reason;
    Object.freeze(this);
  }
}

class StandbyRoster {
  // Ordered roster. Index 0 is primary for the current rotation.
  constructor(engineers, { ackWindowSeconds = DEFAULT_ACK_WINDOW_SECONDS, startIndex = 0 } = {}) {
    if (!engineers || engineers.length === 0) {
      throw new ValidationError('roster needs at least one engineer');
    }
    if (ackWindowSeconds < 1) throw new ValidationError('ack window must be positive');
    if (!(startIndex >= 0 && startIndex < engineers.length)) {
      throw new ValidationError('start_index outside roster');
    }
    // Rotate so the engineer on point is first. Rotation must not
    // change failover order for the rest of the roster.
    this._order = Object.freeze([...engineers.slice(startIndex), ...engineers.slice(0, startIndex)]);
    this._ackWindow = ackWindowSeconds;
  }

  get primary() {
    return this._order[0];
  }

  order() {
    return this._order;
  }

  whoToPage(elapsedSeconds, acknowledgedBy = '') {
    // Fail over one step per full ack window with no acknowledgement.
    if (elapsedSeconds < 0) throw new ValidationError('elapsed time cannot be negative');
    if (acknowledgedBy) {
      for (const engineer of this._order) {
        if (engineer.engineerId === acknowledgedBy) {
          return new PageOutcome(
            engineer, engineer !== this.primary, 'acknowledged; no further paging',
          );
        }
      }
      throw new ValidationError(`acknowledger ${acknowledgedBy} is not on the roster`);
    }
    const steps = Math.floor(elapsedSeconds / this._ackWindow);
    const reachable = this._order.filter((e) => e.reachable);
    if (reachable.length === 0) {
      throw new ValidationError('no reachable engineer on the roster');
    }
    const target = reachable[Math.min(steps, reachable.length - 1)];
    if (steps === 0) return new PageOutcome(target, false, 'primary paged, inside ack window');
    return new PageOutcome(target, true, `no ack after ${steps} window(s); failed over`);
  }
}

module.exports = { DEFAULT_ACK_WINDOW_SECONDS, Engineer, PageOutcome, StandbyRoster };
