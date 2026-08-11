// Local admin control path: a Unix domain socket, mode 0600, newline-delimited
// JSON. There is deliberately no public admin endpoint — creating and claiming a
// handoff requires filesystem access to this socket, i.e. a shell inside the
// broker container (or the same host user in development).
import { chmod, mkdir, rm, stat } from 'node:fs/promises';
import { createServer } from 'node:net';
import { dirname } from 'node:path';

import { PAYLOAD_KINDS } from './broker.js';
import { PAYLOAD_KIND_FILES } from './file-container.js';
import { expiredNotice, receivedNotice, waitingNotice } from './notice.js';

const MAX_CONTROL_LINE_BYTES = 4096;

// The protocol this broker speaks, published on every `create` so a client that
// upgrades on its own schedule can tell what it is talking to instead of
// inferring it. Version 2 is the one that refuses an oversized claim before
// consuming it; version 1 accepts `max_response_bytes`, ignores it, and destroys
// the payload as it answers. Held against `contract/control-protocol.json`'s
// `version` by test/control-protocol.test.js.
const PROTOCOL_VERSION = 2;

// The floor under an advertised `max_response_bytes`. Every non-payload response
// line — the `response_too_large` refusal above all, and it is under 200 bytes
// with both counts spelled out — fits inside this, so a conforming client can
// always read the answer it gets. Below it the only possible outcome is a line
// the caller cannot buffer, which would surface as a transport fault rather than
// as the configuration mistake it is, so it is refused as a caller mistake.
const MIN_RESPONSE_BYTES = 1024;

// The platforms `create` will render a notice for. Kept here rather than imported
// from notice.js, whose export surface is pinned to the three states, and held
// against `contract/control-protocol.json` — the fixture both languages read — by
// test/control-protocol.test.js.
const ACCEPTED_NOTICE_PLATFORMS = Object.freeze(['discord', 'telegram', 'plain']);

/**
 * Makes the socket's directory safe to create the socket in, and says so.
 *
 * `listen()` creates the socket with the process umask and only then can it be
 * chmodded, so the directory is tightened to 0700 *before* the socket exists.
 * That closes the window instead of narrowing it: no other user can reach the
 * socket even for the instant it is world-writable. `mkdir` mode is subject to
 * umask, so chmod is applied explicitly, and to a pre-existing directory too.
 *
 * Since the directory became a **host bind mount** (compose.yml), the chmod can
 * legitimately fail: the directory belongs to the host operator and the container
 * runs as uid 1000. Failing there would reject `startControlServer`, and under
 * `restart: unless-stopped` that is a crash loop rather than a diagnosable error.
 * So a refused chmod is tolerated on exactly one condition — the directory is
 * *already* what this function would have made it, mode 0700 and owned by us.
 * Anything else throws, naming the mode, the owner and the command that fixes it.
 *
 * `ops` exists so tests can reproduce a refused chmod without needing a
 * foreign-owned directory; production passes nothing.
 */
export async function prepareSocketDir(socketDir, ops = {}) {
  const { mkdir: mkdirOp = mkdir, chmod: chmodOp = chmod, stat: statOp = stat } = ops;

  await mkdirOp(socketDir, { recursive: true, mode: 0o700 });
  try {
    await chmodOp(socketDir, 0o700);
    return { socketDir, mode: 0o700, chmodded: true };
  } catch (error) {
    const info = await statOp(socketDir);
    const mode = info.mode & 0o777;
    const uid = typeof process.getuid === 'function' ? process.getuid() : info.uid;
    const gid = typeof process.getgid === 'function' ? process.getgid() : info.gid;
    if (mode === 0o700 && info.uid === uid) return { socketDir, mode, chmodded: false };

    throw new Error(
      `control socket directory ${socketDir} cannot be secured: chmod 0700 failed ` +
        `(${error.code ?? error.message}) and the directory is mode 0${mode.toString(8)} ` +
        `uid ${info.uid} gid ${info.gid}, not mode 0700 uid ${uid}. ` +
        `Fix it on the host, then start again: install -d -m 700 -o ${uid} -g ${gid} ${socketDir}`,
      { cause: error },
    );
  }
}

export async function startControlServer({ socketPath, broker, logger, dirOps }) {
  const socketDir = dirname(socketPath);
  const prepared = await prepareSocketDir(socketDir, dirOps);
  if (!prepared.chmodded) {
    logger.info?.(`control socket directory ${socketDir} already mode 0700 and ours; kept as is`);
  }
  await rm(socketPath, { force: true });

  // Tracked so shutdown is bounded: an `await` subscription holds its
  // connection open for as long as it is parked, and `server.close()` waits for
  // every live connection.
  const sockets = new Set();

  const server = createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', async (chunk) => {
      buffer += chunk.toString('utf8');
      if (buffer.length > MAX_CONTROL_LINE_BYTES) {
        socket.end(`${JSON.stringify({ ok: false, error: 'invalid_request' })}\n`);
        return;
      }
      const newline = buffer.indexOf('\n');
      if (newline < 0) return;
      const line = buffer.slice(0, newline);
      buffer = '';
      let response;
      try {
        response = await handleControlRequest(JSON.parse(line), broker);
      } catch (error) {
        logger.warn?.(`control request rejected: ${error.message}`);
        response = { ok: false, error: 'invalid_request' };
      }
      socket.end(`${JSON.stringify(response)}\n`);
    });
    socket.on('error', (error) => logger.warn?.(`control socket error: ${error.message}`));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, resolve);
  });
  await chmod(socketPath, 0o600);
  logger.info?.(`control socket listening on ${socketPath}`);

  return {
    socketPath,
    async close() {
      await new Promise((resolve) => {
        server.close(resolve);
        // Callers destroy the broker's records before closing, so every parked
        // subscription already has its answer in flight. Give that a moment to
        // flush, then drop anything still attached rather than let one idle
        // connection hold the process open.
        setTimeout(() => {
          for (const socket of sockets) socket.destroy();
        }, 100).unref();
      });
      await rm(socketPath, { force: true });
    },
  };
}

/**
 * The exact size of the line a successful `claim` puts on the wire.
 *
 * Arithmetic, not an estimate: base64 is four characters per three payload bytes
 * rounded up, and neither the base64 alphabet nor a base64url handoff id contains
 * a character `JSON.stringify` escapes — so the envelope measured with an empty
 * payload plus the encoded length is the whole line, and the trailing newline
 * `socket.end` writes is the `+ 1`. test/seam4-claim.test.js holds it against a
 * real response, because an estimate here would be a destroyed payload there.
 */
function claimResponseBytes(handoffId, payloadBytes) {
  const envelope =
    Buffer.byteLength(JSON.stringify({ ok: true, handoff_id: handoffId, plaintext_b64: '' })) + 1;
  return envelope + 4 * Math.ceil(payloadBytes / 3);
}

/** The inverse: the largest payload whose response still fits in `maxResponseBytes`. */
function claimPayloadBudget(handoffId, maxResponseBytes) {
  const forBase64 = maxResponseBytes - claimResponseBytes(handoffId, 0);
  if (forBase64 <= 0) return 0;
  return Math.floor(forBase64 / 4) * 3;
}

async function handleControlRequest(request, broker) {
  if (!request || typeof request !== 'object') return { ok: false, error: 'invalid_request' };

  switch (request.op) {
    // `notice_platform` is opt-in. When it is given, the response carries all
    // three notice strings, so a caller that has to post the waiting message and
    // later edit it into one of the quiet states needs exactly one round trip.
    // There is deliberately no `notice` op: the two quiet states are constants
    // and identical on every platform, so fetching them would buy nothing.
    case 'create': {
      const platform = request.notice_platform;
      const wantsNotice = platform !== undefined;
      // Validated *before* minting. An unsupported platform must not consume a
      // handoff on its way to being refused, and it must never silently fall
      // back to a platform whose rendering was verified for someone else.
      if (wantsNotice && !ACCEPTED_NOTICE_PLATFORMS.includes(platform)) {
        return { ok: false, error: 'invalid_request' };
      }

      // The payload kind and its file count are validated on the same terms: a
      // kind this broker does not speak, or a count that is not a usable one, is
      // a caller mistake and must mint nothing on its way to being refused.
      const payloadKind = request.payload_kind;
      if (payloadKind !== undefined && !PAYLOAD_KINDS.includes(payloadKind)) {
        return { ok: false, error: 'invalid_request' };
      }
      const maxFiles = request.max_files;
      if (maxFiles !== undefined) {
        // Meaningless on a text drop, so it is refused rather than ignored: a
        // caller that asked for a file count and got a text drop was misheard.
        if (payloadKind !== PAYLOAD_KIND_FILES) return { ok: false, error: 'invalid_request' };
        if (!Number.isInteger(maxFiles) || maxFiles < 1) {
          return { ok: false, error: 'invalid_request' };
        }
      }

      const created = await broker.create({
        ...(request.ttl_seconds === undefined ? {} : { ttlSeconds: Number(request.ttl_seconds) }),
        ...(payloadKind === undefined ? {} : { payloadKind }),
        ...(maxFiles === undefined ? {} : { maxFiles }),
      });
      if (!created.ok) return created;

      // Stated here rather than in broker.js: the version and the kinds this
      // broker speaks are facts about the protocol this seam speaks, not about
      // the handoff it just minted. Every drop starts with this response, so a
      // client learns what it is talking to before there is a payload to lose —
      // no probe op, no extra round trip. A plugin that needs file drops reads
      // `payload_kinds` and refuses *before* posting a link, rather than
      // discovering a text-only broker at submit time.
      const answer = {
        ...created,
        protocol_version: PROTOCOL_VERSION,
        payload_kinds: PAYLOAD_KINDS,
      };
      if (!wantsNotice) return answer;

      return {
        ...answer,
        notice: waitingNotice({
          handoffId: created.handoff_id,
          url: created.url,
          expiresAt: created.expires_at,
          platform,
        }),
        notice_received: receivedNotice(),
        notice_expired: expiredNotice(),
      };
    }

    // Subscribe to the submission event. Blocks on the broker's own waiter, so
    // no caller ever polls, and answers with a status and an id — never with
    // the payload. This response is what a Hermes wake message quotes, so it is
    // deliberately the narrowest thing that can carry the news.
    case 'await': {
      if (typeof request.handoff_id !== 'string') return { ok: false, error: 'invalid_request' };
      const waitMs = Number(request.wait_ms ?? 0);
      if (!Number.isFinite(waitMs) || waitMs < 0) return { ok: false, error: 'invalid_request' };

      const outcome = await broker.waitForSubmission(request.handoff_id, waitMs);
      // Expired, destroyed, already claimed, never existed, or the wait ran
      // out: one *body* for all of them, as everywhere else. Unlike the other
      // seams the timing does differ — only a live pending handoff blocks — so
      // this op leaks liveness to its caller by construction. See the note in
      // broker.js: the caller here is local, trusted with plaintext, and the
      // handoff id it is probing with was never secret.
      if (outcome !== 'submitted') return { ok: false, error: 'unavailable' };
      return { ok: true, handoff_id: request.handoff_id, status: 'submitted' };
    }

    case 'claim': {
      if (typeof request.handoff_id !== 'string') return { ok: false, error: 'invalid_request' };

      // Optionally block until the browser submits, so an operator does not poll.
      const waitMs = Number(request.wait_ms ?? 0);
      if (!Number.isFinite(waitMs) || waitMs < 0) return { ok: false, error: 'invalid_request' };

      // The caller's reader ceiling, if it has one. Validated here — before the
      // wait and long before the claim — because an ill-typed ceiling is a caller
      // mistake, and a caller mistake must never be paid for with a payload.
      const ceiling = request.max_response_bytes;
      let maxPayloadBytes = Infinity;
      if (ceiling !== undefined) {
        if (!Number.isInteger(ceiling) || ceiling < MIN_RESPONSE_BYTES) {
          return { ok: false, error: 'invalid_request' };
        }
        maxPayloadBytes = claimPayloadBudget(request.handoff_id, ceiling);
      }

      if (waitMs > 0) await broker.waitForSubmission(request.handoff_id, waitMs);

      const result = broker.claim(request.handoff_id, { maxPayloadBytes });
      if (result.error === 'response_too_large') {
        // Translated back into the units the caller advertised in. `required_bytes`
        // is the real length of the line a successful claim would have written, so
        // an operator can compare it against the reader and act on the difference.
        return {
          ok: false,
          error: 'response_too_large',
          required_bytes: claimResponseBytes(request.handoff_id, result.payload_bytes),
          max_response_bytes: ceiling,
        };
      }
      if (!result.ok) return result;
      // Base64 is transport encoding for the JSON line, not a protection measure.
      const encoded = Buffer.from(result.plaintext).toString('base64');
      result.plaintext.fill(0);
      return { ok: true, handoff_id: result.handoff_id, plaintext_b64: encoded };
    }

    default:
      return { ok: false, error: 'invalid_request' };
  }
}
