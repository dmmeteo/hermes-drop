// The countdown never trusts the device clock. These tests drive both clocks
// by hand: a fake wall clock that can be wrong or can jump, and a fake
// monotonic clock that can freeze the way a suspended phone's does.
import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { createDeadline, formatRemaining } from '../src/client/countdown.js';

/** A deadline 30 minutes out, seen by a device whose clock is `skewMs` wrong. */
function scenario({ skewMs = 0, spanMs = 1_800_000 } = {}) {
  const serverNow = 1_800_000_000_000;
  let wall = serverNow + skewMs;
  let mono = 5_000;
  const deadline = createDeadline({
    expiresAt: serverNow + spanMs,
    now: serverNow,
    clock: { now: () => wall },
    monotonic: () => mono,
  });
  return {
    deadline,
    advance(ms) {
      wall += ms;
      mono += ms;
    },
    advanceWallOnly(ms) {
      wall += ms;
    },
    advanceMonotonicOnly(ms) {
      mono += ms;
    },
    jumpWall(ms) {
      wall += ms;
    },
  };
}

describe('formatRemaining', () => {
  it('renders minutes and seconds, seconds always two digits', () => {
    assert.equal(formatRemaining(1_800_000), '30:00');
    assert.equal(formatRemaining(1_787_000), '29:47');
    assert.equal(formatRemaining(62_000), '1:02');
    assert.equal(formatRemaining(9_000), '0:09');
  });

  it('rounds up, so the last visible second is a whole second', () => {
    assert.equal(formatRemaining(500), '0:01');
    assert.equal(formatRemaining(1), '0:01');
  });

  it('never renders a negative remainder', () => {
    assert.equal(formatRemaining(0), '0:00');
    assert.equal(formatRemaining(-90_000), '0:00');
  });
});

describe('createDeadline', () => {
  it('charges the time the answer spent getting back from the broker', () => {
    const serverNow = 1_800_000_000_000;
    const deadline = createDeadline({
      expiresAt: serverNow + 1_800_000,
      now: serverNow,
      // The broker's clock is from when it *answered*; the page only anchors
      // once the response has arrived and parsed. Uncharged, that leg would
      // make the countdown generous by a constant.
      elapsedSinceAnswerMs: 400,
      clock: { now: () => serverNow + 400 },
      monotonic: () => 0,
    });
    assert.equal(deadline.remaining(), 1_799_600);
  });

  it('starts from the broker-computed span, not from the device clock', () => {
    for (const skewMs of [0, 7 * 60_000, -3 * 3_600_000]) {
      const { deadline } = scenario({ skewMs });
      assert.equal(deadline.remaining(), 1_800_000, `skew ${skewMs}ms must not matter`);
    }
  });

  it('counts down in real time on a device whose clock is hours wrong', () => {
    const s = scenario({ skewMs: 4 * 3_600_000 });
    s.advance(90_000);
    assert.equal(s.deadline.remaining(), 1_710_000);
    assert.equal(formatRemaining(s.deadline.remaining()), '28:30');
  });

  it('believes the wall clock when the monotonic clock froze under suspend', () => {
    const s = scenario();
    // Backgrounded/asleep for ten minutes: some platforms stop performance.now().
    s.advanceWallOnly(600_000);
    assert.equal(s.deadline.remaining(), 1_200_000, 'the lost time must still be charged');
  });

  it('believes the monotonic clock when the wall clock jumps backwards', () => {
    const s = scenario();
    s.advance(300_000);
    s.jumpWall(-3_600_000); // NTP correction or a manual clock change
    assert.equal(s.deadline.remaining(), 1_500_000, 'a backwards jump must not buy time');
  });

  it('takes the pessimistic estimate when the wall clock jumps forwards', () => {
    const s = scenario();
    s.advanceMonotonicOnly(60_000);
    s.advanceWallOnly(900_000);
    assert.equal(s.deadline.remaining(), 900_000, 'less time left is the safe answer');
  });

  it('floors at zero and reports expiry', () => {
    const s = scenario({ spanMs: 10_000 });
    assert.equal(s.deadline.expired(), false);
    s.advance(11_000);
    assert.equal(s.deadline.remaining(), 0);
    assert.equal(s.deadline.expired(), true);
  });
});
