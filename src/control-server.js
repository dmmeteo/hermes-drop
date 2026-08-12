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
import { OUTBOUND_PROTOCOL } from './outbound-drop.js';

const MAX_CONTROL_LINE_BYTES = 4096;

/**
 * The framed file-transfer revision this broker speaks, published on every
 * `create` (docs/FILE_TRANSFER_MVP.md, slice 3).
 *
 * Separate from `PROTOCOL_VERSION` on purpose. Adding the transfer is additive —
 * a text-only client sends none of it, receives none of it, and could not tell a
 * broker with it from a broker without — so bumping the protocol version would
 * have forced every such client to widen an accepted-version check for a
 * capability it will never use. What a *file* client needs is not a version
 * ordering but a yes-or-no answer, before it posts a link, and that is what this
 * field is: absence means this broker can mint a `files` drop and cannot transfer
 * one, which is exactly what a slice-2 broker was.
 */
const FILE_CLAIM_PROTOCOL = 1;

/** uint32 big-endian length in front of each file's bytes. */
const FRAME_HEADER_BYTES = 4;

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
    serveConnection({ socket, broker, logger });
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

const INVALID_REQUEST = Object.freeze({ ok: false, error: 'invalid_request' });

/**
 * One connection, from accept to close.
 *
 * Nearly every op on this socket is one line in, one line out, then closed. The
 * file claim is the exception and the reason this function exists: it is a
 * *conversation* — a begin, a metadata line, length-framed binary, a commit, an
 * answer — and it has to be one connection rather than two round trips, because
 * the connection is the lease.
 *
 * Three things follow from that and are all here rather than in the broker:
 *
 *   PHASE   what the connection will accept next. A commit is only ever accepted
 *           in `awaiting_commit`, which is reachable only by having personally
 *           begun the transfer and streamed all of it. A caller that learns a
 *           handoff id and a transfer id therefore still cannot commit: there is
 *           no phase it can present them in.
 *   ORDER   data events are processed through one promise chain. Without it a
 *           commit line pipelined behind the begin could be handled while the
 *           frames were still going out, and the "every advertised byte was
 *           flushed" check would be racing the writes it is about.
 *   RELEASE the lease is given back however the connection ends — a refusal, an
 *           error, a client that hangs up mid-frame, a process that dies. That is
 *           what makes a failed transfer cost a refusal instead of a payload.
 *
 * The `session` object is also the lease's owner token. Its identity is the
 * authorization: it never leaves this closure, so no other connection can present
 * it and nothing on the wire can imitate it.
 */
function serveConnection({ socket, broker, logger }) {
  const session = {
    phase: 'idle',
    lease: null,
    /** The frame views this transfer is walking, indexed by ack (`writeFrame`). */
    frames: null,
    /** Which frame the receiver still owes an ack for, or null. */
    outstandingFrame: null,
    /**
     * Inbound bytes seen while a frame was being written, so a flood is dropped
     * rather than retained.
     *
     * A pure memory bound and deliberately *not* a turn-taking verdict. An earlier
     * revision refused a commit because data had arrived while the broker was still
     * writing; that inferred receipt from the socket send buffer — a tunable — and it
     * was also a race, because a receiver can legitimately answer a large frame
     * before the broker's own write completion fires. Turn-taking is now structural:
     * every frame must be acked before the next is written, and a commit is only
     * accepted once all of them are (`file_claim.turn_taking`).
     *
     * Why bound rather than `socket.pause()`: pausing stops Node reading the fd, so
     * an early line accumulates in the *kernel* buffer and then arrives after the
     * resume looking exactly like a timely one — it hides the behaviour instead of
     * bounding it.
     */
    inboundDuringFrameBytes: 0,
  };
  let buffer = Buffer.alloc(0);
  // Serializes the async handling of successive lines. `socket.on('data')` will
  // happily re-enter an async listener; the file claim cannot survive that.
  let chain = Promise.resolve();

  /** Gives the lease back, if this connection still holds one. Idempotent. */
  function releaseLease(reason) {
    const lease = session.lease;
    if (!lease) return;
    session.lease = null;
    broker.abandonFileClaim(lease.handoffId, lease.transferId, reason);
  }

  /** The last thing written on this connection: one line, then closed. */
  function answerAndClose(response) {
    if (session.phase === 'closed') return;
    session.phase = 'closed';
    // Whatever the answer is, a lease that survived to here was not committed.
    releaseLease('connection_closed');
    socket.end(`${JSON.stringify(response)}\n`);
  }

  /** One chunk, flushed to the peer — the unit the broker counts as progress. */
  function write(chunk) {
    return new Promise((resolve, reject) => {
      if (socket.destroyed || socket.writableEnded) {
        reject(new Error('connection closed'));
        return;
      }
      socket.write(chunk, (error) => (error ? reject(error) : resolve()));
    });
  }

  /**
   * The broker took the lease away — the deadline lapsed, or the handoff was
   * destroyed under it. The connection is dropped rather than answered: binary
   * frames may be in flight, and a JSON line inserted between them would corrupt
   * the stream, so one behaviour is used for every phase rather than two that
   * differ by timing. The contract says so, and a receiver must treat a closed
   * connection as a failed transfer.
   */
  function onLeaseLost(reason) {
    logger.info?.(`control file claim lease lost reason=${reason}`);
    // The broker has already released it; clearing this first is what stops the
    // close handler from abandoning a lease that no longer exists.
    session.lease = null;
    session.phase = 'closed';
    socket.destroy();
  }

  async function beginFileClaim(request) {
    // Set before the manifest pass, which is a full SHA-256 over the container and
    // therefore the longest window on this connection: inbound data arriving during it
    // is bounded on the same terms as data arriving mid-frame.
    session.phase = 'beginning';
    if (typeof request.handoff_id !== 'string') return answerAndClose(INVALID_REQUEST);
    const leaseMs = request.lease_ms;
    // Ill-typed rather than ignored: a receiver that asked for a deadline and
    // silently got a different one cannot reason about its own timeout.
    if (leaseMs !== undefined && (!Number.isInteger(leaseMs) || leaseMs < 1)) {
      return answerAndClose(INVALID_REQUEST);
    }

    const begun = await broker.beginFileClaim(request.handoff_id, {
      owner: session,
      onLeaseLost,
      ...(leaseMs === undefined ? {} : { leaseMs }),
    });
    if (!begun.ok) return answerAndClose(begun);

    session.lease = { handoffId: begun.handoff_id, transferId: begun.transfer_id };
    // The frame views, held here for the life of the conversation and indexed by the
    // `next_index` each ack answers with. Kept in this closure rather than on the
    // broker's record so the record retains no filename and no second reference to
    // the payload between submit and claim.
    session.frames = begun.files;

    // Metadata carries the name, the size and the untrusted MIME hint, and
    // deliberately no digest: the receiver has to compute what it acks.
    if (
      !(await writeStep(
        `${JSON.stringify({
          ok: true,
          handoff_id: begun.handoff_id,
          transfer_id: begun.transfer_id,
          lease_expires_at: begun.lease_expires_at,
          total_bytes: begun.total_bytes,
          files: begun.files.map((file) => ({
            name: file.name,
            size: file.size,
            type: file.type,
          })),
        })}\n`,
      ))
    ) {
      return;
    }
    // ...and then exactly one frame, after which the connection waits. The receiver
    // has to read it and hash it to say anything the broker will accept.
    await writeFrame(0);
  }

  /**
   * Writes frame `index` and leaves the connection waiting for its ack.
   *
   * One frame at a time is the whole mechanism behind size-independent receipt: the
   * broker stops here, and no amount of socket buffer can answer for the receiver.
   */
  async function writeFrame(index) {
    const file = session.frames[index];
    const header = Buffer.allocUnsafe(FRAME_HEADER_BYTES);
    header.writeUInt32BE(file.size, 0);
    // A lease lost mid-frame has already destroyed the socket; the phase check stops
    // us writing views the broker may have zeroized rather than trusting `write` to
    // notice. Checked before the header *and* between the header and the body,
    // because the body is the write large enough for a lease to lapse underneath it.
    session.phase = 'streaming';
    if (!(await writeStep(header))) return;
    // `file.bytes` is a view into the broker's container and is handed to `write` as
    // one: a 42 MiB file is not copied to be sent.
    if (file.size > 0 && !(await writeStep(file.bytes))) return;

    // ORDER IS LOAD-BEARING — this transition must happen before this function
    // returns, with no `await` after it and nothing deferred to a later tick.
    //
    // What makes the conversation race-free is that every phase change and every line
    // dispatch happen on the one promise chain, so a line can never be judged against
    // a phase that is mid-update. That holds only while the update is synchronous with
    // the end of the write. Deferring it — an `await` here, a `setImmediate`, an
    // unawaited promise — would let the ack the receiver has *already* sent be
    // dispatched while the phase still reads `streaming`, and it would be refused as
    // an ack with no frame outstanding. That failure is timing-dependent and would
    // appear only under load or on large frames, which is exactly the class of bug the
    // structural rule replaced (see `ackFileClaimFrame` in src/broker.js).
    session.phase = 'awaiting_frame_ack';
    session.outstandingFrame = index;
  }

  /**
   * One write, with the failure handling every step of the conversation shares.
   * Returns false when the connection is gone and the caller should stop.
   */
  async function writeStep(chunk) {
    if (session.phase === 'closed') return false;
    try {
      await write(chunk);
    } catch (error) {
      // The peer went away mid-transfer. Nothing was consumed, and the lease goes
      // back so the next receiver can have it without waiting out the deadline.
      logger.warn?.(`control file claim stream failed: ${error.message}`);
      session.phase = 'closed';
      releaseLease('stream_failed');
      socket.destroy();
      return false;
    }
    return session.phase !== 'closed';
  }

  async function ackFrame(request) {
    const lease = session.lease;
    if (!lease) return answerAndClose(INVALID_REQUEST);
    if (typeof request.transfer_id !== 'string') return answerAndClose(INVALID_REQUEST);
    if (!Number.isInteger(request.index) || request.index < 0) {
      return answerAndClose(INVALID_REQUEST);
    }
    if (!Number.isInteger(request.size) || request.size < 0) {
      return answerAndClose(INVALID_REQUEST);
    }
    if (typeof request.sha256 !== 'string') return answerAndClose(INVALID_REQUEST);

    const result = broker.ackFileClaimFrame(lease.handoffId, request.transfer_id, {
      owner: session,
      index: request.index,
      size: request.size,
      digest: request.sha256,
    });
    if (!result.ok) return answerAndClose(result);

    // The answer goes out before the next frame, so the receiver always reads a line
    // where it expects a line and binary where it expects binary.
    if (!(await writeStep(`${JSON.stringify({ ok: true, index: result.index, next_index: result.next_index })}\n`))) {
      return;
    }
    if (result.next_index === null) {
      session.phase = 'awaiting_commit';
      session.outstandingFrame = null;
      return;
    }
    await writeFrame(result.next_index);
  }

  function commitFileClaim(request) {
    const lease = session.lease;
    // Unreachable while the phase check above holds, and checked anyway: this is
    // the line that must never retire a payload for a caller that did not stream
    // it.
    if (!lease) return answerAndClose(INVALID_REQUEST);
    if (request.handoff_id !== lease.handoffId) return answerAndClose(INVALID_REQUEST);
    if (typeof request.transfer_id !== 'string') return answerAndClose(INVALID_REQUEST);
    if (!Number.isInteger(request.received_bytes) || request.received_bytes < 0) {
      return answerAndClose(INVALID_REQUEST);
    }
    if (!Array.isArray(request.digests)) return answerAndClose(INVALID_REQUEST);

    // The transfer id comes from the request rather than from the lease, so a
    // commit that names the wrong transfer is refused by the broker as exactly
    // that instead of being quietly corrected into a valid one.
    const result = broker.commitFileClaim(lease.handoffId, request.transfer_id, {
      owner: session,
      receivedBytes: request.received_bytes,
      digests: request.digests,
    });
    // `answerAndClose` releases whatever lease is left. A commit the broker
    // accepted left none; one it refused for a mismatched id left the real one,
    // and that has to go back rather than sit out its deadline.
    answerAndClose(result);
  }

  async function handleLine(line) {
    let request;
    try {
      request = JSON.parse(line);
    } catch {
      // The class, never the message. V8 embeds a ~10-character window of the offending
      // input in a `JSON.parse` error, and since `create_outbound_drop` this socket
      // carries plaintext inbound — so that window can be a piece of a secret's base64,
      // in the artifact most likely to be pasted into an issue or shipped to a log
      // aggregator. The byte offset was the only diagnostic value in the message and it
      // is not in the snippet.
      logger.warn?.('control request rejected: malformed json');
      return answerAndClose(INVALID_REQUEST);
    }
    if (!request || typeof request !== 'object') return answerAndClose(INVALID_REQUEST);

    switch (request.op) {
      // The two ops that are a conversation rather than an exchange. Each is
      // accepted in exactly one phase; anything else — a commit with no lease, a
      // second begin on one connection, a line after a commit — is a caller
      // mistake, and answering it ends the connection and the lease with it.
      case 'begin_file_claim':
        if (session.phase !== 'idle') return answerAndClose(INVALID_REQUEST);
        return beginFileClaim(request);

      case 'ack_frame':
        // Only while a frame is outstanding. This is the phase an early commit lands
        // in, and refusing the commit here rather than inferring anything from
        // timing is what makes the rule hold at every payload size.
        if (session.phase !== 'awaiting_frame_ack') return answerAndClose(INVALID_REQUEST);
        return ackFrame(request);

      case 'commit_file_claim':
        if (session.phase !== 'awaiting_commit') {
          logger.warn?.(
            `control file claim refused reason=commit_out_of_turn phase=${session.phase}`,
          );
          return answerAndClose(INVALID_REQUEST);
        }
        return commitFileClaim(request);

      default: {
        // Every other op: one line in, one line out, then closed, exactly as
        // before. They are not available mid-conversation.
        if (session.phase !== 'idle') return answerAndClose(INVALID_REQUEST);
        let response;
        try {
          response = await handleControlRequest(request, broker);
        } catch (error) {
          // The error's *name* and the op, not its message. A thrown message can quote
          // its input, and one op's input is now a secret; the name and the op are what
          // an operator needs to find the bug, and neither can carry a payload.
          logger.warn?.(
            `control request rejected: op=${typeof request.op === 'string' ? request.op : 'unknown'} ` +
              `error=${error?.name ?? 'Error'}`,
          );
          response = INVALID_REQUEST;
        }
        return answerAndClose(response);
      }
    }
  }

  async function onChunk(chunk) {
    if (session.phase === 'closed') return;
    buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
    // Bounded unconditionally, not only while a line is incomplete. `buffer` holds a
    // whole line including its newline — the unit `transport.max_request_bytes`
    // counts in (`transport.size_convention`) — and this protocol never has more
    // than two lines in flight on one connection, so anything past the ceiling is
    // either an oversized request or a flood, and both are the same refusal.
    if (buffer.length > MAX_CONTROL_LINE_BYTES) return answerAndClose(INVALID_REQUEST);
    for (;;) {
      if (session.phase === 'closed') return;
      const newline = buffer.indexOf(0x0a);
      if (newline < 0) return;
      const line = buffer.subarray(0, newline).toString('utf8');
      buffer = buffer.subarray(newline + 1);
      await handleLine(line);
    }
  }

  socket.on('data', (chunk) => {
    // A memory bound, not a verdict. While a frame is being written the chain is
    // busy, so each arriving chunk is held in a closure until it drains — for a
    // 42 MiB frame that is an arbitrary amount of broker memory held for the length
    // of the write, working directly against the budget this slice exists to bound.
    // One request line's worth is kept, which is all a legitimate ack needs; past
    // that the connection goes, which costs the caller its lease and the payload
    // nothing. Whether the line itself was *allowed* is decided by the phase machine
    // when it is parsed, not here.
    if (session.phase === 'streaming' || session.phase === 'beginning') {
      session.inboundDuringFrameBytes += chunk.length;
      if (session.inboundDuringFrameBytes > MAX_CONTROL_LINE_BYTES) {
        logger.warn?.('control file claim connection dropped reason=inbound_flood');
        session.phase = 'closed';
        releaseLease('inbound_flood');
        socket.destroy();
        return;
      }
    }
    chain = chain.then(() => onChunk(chunk)).catch((error) => {
      logger.warn?.(`control connection failed: ${error.message}`);
      session.phase = 'closed';
      releaseLease('connection_failed');
      socket.destroy();
    });
  });
  // The disconnect edge: a receiver that dies mid-frame, or hangs up without
  // committing, gives its lease back here and the payload stays claimable.
  socket.on('close', () => releaseLease('receiver_disconnected'));

  // Half-close, which is not the same edge and used to be indistinguishable from
  // a healthy pause. The server keeps its side open when a peer ends its writable
  // half (`allowHalfOpen`), because a client is allowed to send its one request
  // line with `end()` and still be answered. But a peer that has ended its
  // writable half can never send a commit — so a lease held at that moment is a
  // lease nothing will ever finish, and holding it to its deadline would keep the
  // next receiver waiting a minute for a payload already sitting there.
  //
  // Queued behind the chain rather than acted on at once: `end` can arrive while a
  // pipelined commit is still being processed, and that commit is entitled to
  // settle first.
  socket.on('end', () => {
    chain = chain
      .then(() => {
        if (!session.lease) return;
        session.phase = 'closed';
        releaseLease('receiver_half_closed');
        socket.end();
      })
      .catch((error) => logger.warn?.(`control half-close failed: ${error.message}`));
  });
  socket.on('error', (error) => logger.warn?.(`control socket error: ${error.message}`));
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

/**
 * Canonical base64, or null. Strict on three counts Node's decoder is not: the
 * alphabet, the padded length, and that re-encoding reproduces the input exactly —
 * so `AA==` and `AA=` cannot both mean the same byte, and a value with trailing
 * junk is refused rather than silently truncated.
 */
function decodeBase64Strict(value) {
  if (typeof value !== 'string' || value.length === 0) return null;
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return null;
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length === 0 || bytes.toString('base64') !== value) return null;
  return bytes;
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
        // The other half of the pre-flight check. `payload_kinds` says this broker
        // can mint a file drop; this says it can also hand the bytes back. They
        // were separate capabilities for one release and a client cannot assume
        // the pair, so both are advertised.
        file_claim_protocol: FILE_CLAIM_PROTOCOL,
        // The outbound direction, advertised on the response every *inbound* drop
        // starts with as well as on its own, for the same pre-flight reason as
        // `file_claim_protocol`: a plugin learns whether this broker can hand a
        // secret *out* from the first call it makes, rather than from the call it
        // makes after deciding to post one.
        outbound_protocol: OUTBOUND_PROTOCOL,
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

    // The outbound direction (docs/OUTBOUND_SECRET_DROP_MVP.md): the caller already
    // holds the secret and wants the *user* to receive it, so this is the one op on
    // this socket that carries plaintext inbound. Everything about it is arranged so
    // that the plaintext's life is this call: it is decoded, handed to the store,
    // encrypted and wiped, and what comes back is a link, a code and no payload.
    case 'create_outbound_drop': {
      // Decoded strictly and canonically. A lenient decode would let two different
      // request lines mean the same secret, and this op is the one place where what
      // arrives on the socket *is* the payload.
      const plaintext = decodeBase64Strict(request.plaintext_b64);
      if (plaintext === null) return { ok: false, error: 'invalid_request' };

      // One `finally` for every exit below, because this function owns the buffer and
      // the paths out of it are a refused TTL, a refused ceiling, a thrown AEAD and a
      // receipt. The store wipes it too — on its own success and refusal paths — and
      // wiping an already-zeroed buffer costs nothing, which is the right price for
      // not having to prove that the two agree on every future branch.
      try {
        const ttlSeconds = request.ttl_seconds;
        // Type-checked, not coerced. Every other numeric field on this socket is
        // (`max_files`, `lease_ms`, `index`, `size`, `received_bytes`), the fixture
        // says `"type": "number"`, and coercion here is not harmless: `true` becomes a
        // one-second drop and `"1800"` becomes a value the fixture says was refused.
        // A foreign client with a type slip would get a link and a code for a drop
        // that is already dead, which the user cannot tell from a stolen secret.
        if (ttlSeconds !== undefined && typeof ttlSeconds !== 'number') {
          return { ok: false, error: 'invalid_request' };
        }

        const created = await broker.createOutboundDrop({
          plaintext,
          ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
        });
        if (!created.ok) return created;
        return {
          ...created,
          protocol_version: PROTOCOL_VERSION,
          outbound_protocol: OUTBOUND_PROTOCOL,
        };
      } finally {
        plaintext.fill(0);
      }
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
