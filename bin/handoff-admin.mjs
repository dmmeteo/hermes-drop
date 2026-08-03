#!/usr/bin/env node
// Local admin CLI. Talks only to the broker's Unix control socket.
//
//   handoff-admin create [--ttl <s>] [--notice] -> prints the URL, or the
//                                                  ready-to-post waiting notice
//   handoff-admin await <id> [--timeout <s>]    -> blocks until submitted; no payload
//   handoff-admin claim <id> [--wait <s>]       -> prints the plaintext to stdout once
//   handoff-admin notice <received|expired>     -> the content the waiting
//                                                  message is edited into
//
// stdout carries the payload and nothing else; every diagnostic goes to stderr.
//
// A drop costs the channel exactly one message, edited in place through three
// fixed states (waiting -> received | expired). The edit is a direct Discord
// REST PATCH on the message id captured at post time, authorised with the
// active profile's credential; `notice` exists so the two quiet states are a
// contract rather than model prose.
//
// `await` is the subscription Hermes runs under
// terminal(background=true, notify_on_complete=true). Everything it emits — the
// command line included — is quoted into the wake message and therefore into
// durable session history, so it deals only in the non-secret handoff id.
//
// The contract Hermes must follow is a single rule:
//
//   exit 0        -> the payload is waiting: claim it and carry on.
//   any non-zero  -> do NOT claim. Tell the user the drop did not complete and
//                    offer a fresh link.
//
// The codes exist to explain *why*, not to be individually branched on:
//   0  submitted.
//   1  transport failure — the control socket was unreachable, the request
//      timed out, or the answer was malformed. A broker restart mid-wait lands
//      here, and the payload's fate is genuinely unknown.
//   2  usage — a caller mistake, never a statement about the handoff.
//   3  the broker answered "unavailable": expired, consumed, or the wait lapsed.
import { DEFAULTS } from '../src/config.js';
import { controlRequest } from '../src/control-client.js';
import { expiredNotice, receivedNotice, waitingNotice } from '../src/notice.js';

const socketPath = process.env.HANDOFF_CONTROL_SOCKET || DEFAULTS.controlSocketPath;
const [command, ...rest] = process.argv.slice(2);

function usage() {
  process.stderr.write(
    'usage: handoff-admin create [--ttl <seconds>] [--notice] [--platform <discord|telegram|plain>]\n' +
      '       handoff-admin await <handoff-id> [--timeout <seconds>]\n' +
      '       handoff-admin claim <handoff-id> [--wait <seconds>]\n' +
      '       handoff-admin notice <received|expired>\n',
  );
  process.exit(2);
}

/** Parses `<id> [--<flag> <seconds>]`, the shape both blocking commands take. */
function parseBlockingArgs(rest, flag, defaultSeconds) {
  const [handoffId, ...flags] = rest;
  if (!handoffId) usage();

  let seconds = defaultSeconds;
  for (let i = 0; i < flags.length; i += 1) {
    if (flags[i] !== flag) usage();
    seconds = Number(flags[i + 1]);
    // An explicit 0 is refused rather than honoured: it reads as "no limit" but
    // would behave as an instant timeout, reporting a perfectly live handoff as
    // lapsed. A caller mistake must not look like a verdict on the link.
    if (!Number.isFinite(seconds) || seconds <= 0) usage();
    i += 1;
  }
  return { handoffId, waitMs: Math.round(seconds * 1000) };
}

async function main() {
  if (command === 'create') {
    let ttlSeconds;
    let asNotice = false;
    let platform = 'discord';
    for (let i = 0; i < rest.length; i += 1) {
      if (rest[i] === '--ttl') {
        ttlSeconds = Number(rest[i + 1]);
        // Validated here as well as at the broker, so a typo exits 2 like every
        // other caller mistake instead of arriving as `null` and coming back as
        // a broker-side `invalid_request` on exit 1.
        if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) usage();
        i += 1;
      } else if (rest[i] === '--notice') {
        asNotice = true;
      } else if (rest[i] === '--platform') {
        platform = rest[i + 1];
        // `plain` is the no-markup shape for a platform whose rendering is not
        // verified end to end. Anything else is a caller mistake, not a fallback:
        // the notice must never be rendered for a platform nobody chose.
        if (!['discord', 'telegram', 'plain'].includes(platform)) usage();
        i += 1;
      } else usage();
    }

    const response = await controlRequest(socketPath, {
      op: 'create',
      ...(ttlSeconds === undefined ? {} : { ttl_seconds: ttlSeconds }),
    });
    if (!response.ok) {
      process.stderr.write(`create failed: ${response.error}\n`);
      process.exit(1);
    }
    process.stderr.write(
      `handoff ${response.handoff_id} expires ${new Date(response.expires_at).toISOString()} ` +
        `(one submission, one claim, max ${response.max_plaintext_bytes} bytes)\n`,
    );
    process.stdout.write(
      asNotice
        ? `${waitingNotice({
            handoffId: response.handoff_id,
            url: response.url,
            expiresAt: response.expires_at,
            platform,
          })}\n`
        : `${response.url}\n`,
    );
    return;
  }

  // The two states the waiting message is edited into. Pure rendering, so it
  // needs no broker — which matters, because the expired state is wanted
  // precisely when the handoff is gone. Only the states this contract defines
  // are accepted; there is no free-text status.
  if (command === 'notice') {
    const [state, ...extra] = rest;
    if (extra.length) usage();
    if (state === 'received') process.stdout.write(`${receivedNotice()}\n`);
    else if (state === 'expired') process.stdout.write(`${expiredNotice()}\n`);
    else usage();
    return;
  }

  if (command === 'await') {
    // Default matches the default TTL; the broker never waits past the
    // handoff's own expiry regardless of what is asked for.
    const { handoffId, waitMs } = parseBlockingArgs(rest, '--timeout', 1800);

    const response = await controlRequest(
      socketPath,
      { op: 'await', handoff_id: handoffId, wait_ms: waitMs },
      { timeoutMs: waitMs + 5000 },
    );
    if (!response.ok) {
      process.stderr.write(`handoff ${handoffId} unavailable\n`);
      process.exit(3);
    }
    // One line, no payload: this is what the wake message quotes.
    process.stdout.write(`handoff ${handoffId} submitted\n`);
    return;
  }

  if (command === 'claim') {
    const { handoffId, waitMs } = parseBlockingArgs(rest, '--wait', 0);
    const response = await controlRequest(
      socketPath,
      { op: 'claim', handoff_id: handoffId, wait_ms: waitMs },
      { timeoutMs: waitMs + 5000 },
    );
    if (!response.ok) {
      process.stderr.write(`claim unavailable: ${response.error}\n`);
      process.exit(1);
    }
    // Raw bytes, exactly once. No formatting, no logging, no trailing newline.
    process.stdout.write(Buffer.from(response.plaintext_b64, 'base64'));
    return;
  }

  usage();
}

main().catch((error) => {
  process.stderr.write(`error: ${error.message}\n`);
  process.exit(1);
});
