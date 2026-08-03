// Remaining-time tracking for the page's countdown.
//
// The device clock is not trusted. `/api/metadata` states both the absolute
// expiry and the broker's own clock at the moment it answered, so the span left
// at page load is server arithmetic — `expires_at - now` — with no device clock
// in it at all. From there the page has to advance that span locally, and both
// available local clocks can lie:
//
//   - `performance.now()` is monotonic, but on several platforms it stops while
//     the device is suspended, which would under-count elapsed time and leave
//     the page advertising a handoff the broker has already expired;
//   - `Date.now()` keeps running through suspend, but an NTP correction or a
//     manual change can move it in either direction mid-countdown.
//
// So both are tracked and the *smaller* remainder wins. Erring towards "less
// time left than you think" can only ever send someone back to Hermes for a
// fresh link; erring the other way shows a live form over a dead handoff.
// The broker remains the only authority: this is display, not enforcement.

/** `m:ss`, rounded up, floored at zero. */
export function formatRemaining(remainingMs) {
  const totalSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

/**
 * @param expiresAt            absolute broker expiry, epoch ms
 * @param now                  the broker's clock when it produced `expiresAt`
 * @param elapsedSinceAnswerMs time between the broker answering and this call.
 *   The caller measures the whole metadata round trip and passes it in, which
 *   over-charges by the request leg. That is deliberate: over-charging shortens
 *   the countdown, and short is the safe direction. Without it the countdown
 *   would be generous by a fixed sub-second constant — small, but it made the
 *   "never over-reports" property untrue as an absolute rather than merely
 *   non-accumulating.
 * @param clock                wall clock, injectable for tests
 * @param monotonic            monotonic clock in ms, injectable for tests
 */
export function createDeadline({
  expiresAt,
  now,
  elapsedSinceAnswerMs = 0,
  clock = Date,
  monotonic = () => performance.now(),
}) {
  // The broker's clock advanced while its answer was in flight, so the anchor
  // is `now` plus that flight time — and both estimates below are derived from
  // that one anchor, so neither can drift back to the uncharged value.
  const anchorServerNow = now + Math.max(0, elapsedSinceAnswerMs);
  const spanMs = expiresAt - anchorServerNow;
  const anchorMonotonic = monotonic();
  // Positive when the device clock runs behind the broker's.
  const skewMs = anchorServerNow - clock.now();

  function remaining() {
    const byMonotonic = spanMs - (monotonic() - anchorMonotonic);
    const byWallClock = expiresAt - (clock.now() + skewMs);
    return Math.max(0, Math.min(byMonotonic, byWallClock));
  }

  return {
    spanMs,
    remaining,
    expired: () => remaining() <= 0,
  };
}
