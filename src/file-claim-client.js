// Receiver for the framed file claim (docs/FILE_TRANSFER_MVP.md, slice 3).
//
// The counterpart to `begin_file_claim` / `ack_frame` / `commit_file_claim` in
// src/control-server.js: it opens one connection, takes the lease, reads the
// metadata line, then walks the frames one at a time — read it, hash it, ack it,
// and only then does the broker send the next — and finally commits with the
// digests it computed *itself*.
//
// The digests are the whole point of the protocol and therefore of this client. The
// broker never sends them, so an ack or a commit that verifies is evidence the bytes
// arrived rather than a promise that they did, and a receiver that echoed what it
// was told would be lying to the only party that can still refuse. The per-frame
// ack is what makes that evidence size-independent: the broker stops after each
// frame, so no socket buffer can answer on the receiver's behalf.
//
// Deliberately low-level and deliberately not a spool writer. It streams bytes to
// an `onChunk` callback and stops there; the private directory, the generated
// storage names and the atomic publish are slice 4's, and they belong on the
// Hermes side rather than here.
//
// **This module's option surface is what a real receiver needs and nothing more.**
// The hooks that let a test be a hostile or broken receiver — abandon mid-stream,
// commit twice, commit a digest it did not compute — live in
// test/helpers/hostile-receiver.js, which drives the socket itself. They used to
// live here, and a `mutateCommit` that can rewrite the digests is a forge-a-commit
// primitive: not something to keep in a module slice 4 imports for real, however
// opt-in it is.
//
// Ownership of what comes back, in the same terms as src/file-container.js: bytes
// handed to `onChunk` are this client's own buffers off the wire, so the caller
// owns and zeroizes whatever it retains. `collectBytes` assembles a whole file per
// entry and is a convenience for small payloads; a consumer at 42 MiB should use
// `onChunk` and keep nothing.
import { connect } from 'node:net';
import { createHash } from 'node:crypto';

/** uint32 big-endian length in front of every file's bytes. */
export const FRAME_HEADER_BYTES = 4;

/** How long this client will wait on a silent socket before giving up. */
const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * A pull reader over a socket: newline-delimited lines for the JSON phases, exact
 * byte counts for the frames. One buffer, no assembly of anything the caller did
 * not ask to collect — a 42 MiB frame is hashed as it arrives and only copied if
 * `collectBytes` is on.
 *
 * Exported for test/helpers/hostile-receiver.js, which needs to read this wire
 * format while behaving badly on it. A reader is not a forgery primitive, so it is
 * the part that is safe to share.
 */
export class FrameReader {
  #iterator;
  #pending = Buffer.alloc(0);
  #done = false;

  constructor(socket) {
    this.#iterator = socket[Symbol.asyncIterator]();
  }

  async #pull() {
    if (this.#done) return false;
    const next = await this.#iterator.next();
    if (next.done) {
      this.#done = true;
      return false;
    }
    this.#pending =
      this.#pending.length === 0 ? next.value : Buffer.concat([this.#pending, next.value]);
    return true;
  }

  /** One JSON line, or null when the peer closed without sending one. */
  async readLine() {
    for (;;) {
      const newline = this.#pending.indexOf(0x0a);
      if (newline >= 0) {
        const line = this.#pending.subarray(0, newline).toString('utf8');
        this.#pending = this.#pending.subarray(newline + 1);
        return line;
      }
      if (!(await this.#pull())) return null;
    }
  }

  /**
   * Exactly `count` bytes, handed to `onChunk` as they arrive. Returns the number
   * actually read: fewer than `count` means the peer closed mid-frame, which is a
   * truncated transfer and not an error to throw over.
   */
  async readBytes(count, onChunk) {
    let read = 0;
    while (read < count) {
      if (this.#pending.length === 0 && !(await this.#pull())) return read;
      const take = Math.min(count - read, this.#pending.length);
      onChunk(this.#pending.subarray(0, take));
      this.#pending = this.#pending.subarray(take);
      read += take;
    }
    return read;
  }
}

export function writeLine(socket, request) {
  return new Promise((resolve, reject) => {
    socket.write(`${JSON.stringify(request)}\n`, (error) => (error ? reject(error) : resolve()));
  });
}

export function parseLine(line) {
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

/**
 * The verdict for "the commit went out and no answer came back".
 *
 * Not `transfer_failed`: that error carries the broker's promise that nothing was
 * consumed, and a receiver that read no answer knows nothing of the kind. The
 * commit is one-shot, non-idempotent and not requeryable, so the payload may have
 * been retired with only the answer lost. See `file_claim.client_verdicts` in the
 * contract for the caller semantics — do not publish, do not retry, do not record
 * the drop as spent.
 */
export const TRANSFER_INDETERMINATE = 'transfer_indeterminate';

function indeterminate(reason) {
  return { ok: false, error: TRANSFER_INDETERMINATE, reason, phase: 'commit' };
}

/**
 * Runs one whole file claim and resolves with a verdict — never throws for a
 * protocol outcome, only for a caller mistake such as an unusable socket path.
 *
 * On success: `{ ok: true, status: 'claimed', bytes, fileCount, files: [{ name,
 * type, size, sha256, bytes? }] }`. On failure: `{ ok: false, error, reason?,
 * phase }`, where `error` is the broker's own (`transfer_failed`, `unavailable`,
 * `invalid_request`), a local `transfer_failed` for a failure that provably
 * preceded the commit, or `transfer_indeterminate` when the commit was written and
 * no answer was read. This client never reports success on a transfer it could not
 * finish, and never reports `transfer_failed` for an outcome it cannot rule on.
 */
export async function receiveFileClaim(
  socketPath,
  handoffId,
  { leaseMs, timeoutMs = DEFAULT_TIMEOUT_MS, collectBytes = true, onChunk } = {},
) {
  const socket = connect(socketPath);
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error('file claim timed out')));
  const reader = new FrameReader(socket);
  // A socket error after the peer has gone is the protocol working, not something
  // to crash the process over: every phase below decides for itself what a dead
  // connection means.
  let socketError = null;
  socket.on('error', (error) => {
    socketError = error;
  });
  // The one fact that decides between "failed" and "indeterminate" on every exit
  // path below, so it is tracked rather than inferred from where we happened to be.
  let commitWritten = false;

  try {
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });

    const begin = { op: 'begin_file_claim', handoff_id: handoffId };
    if (leaseMs !== undefined) begin.lease_ms = leaseMs;
    await writeLine(socket, begin);

    const metadataLine = await reader.readLine();
    if (metadataLine === null) {
      return { ok: false, error: 'transfer_failed', reason: 'connection_closed', phase: 'begin' };
    }
    const metadata = parseLine(metadataLine);
    if (metadata === null) {
      return { ok: false, error: 'transfer_failed', reason: 'malformed_metadata', phase: 'begin' };
    }
    if (!metadata.ok) return { ...metadata, phase: 'begin' };
    if (!Array.isArray(metadata.files)) {
      return { ok: false, error: 'transfer_failed', reason: 'malformed_metadata', phase: 'begin' };
    }
    if (metadata.private_text !== undefined) {
      const descriptor = metadata.private_text;
      if (
        descriptor === null
        || typeof descriptor !== 'object'
        || Array.isArray(descriptor)
        || !Object.hasOwn(descriptor, 'size')
        || !Object.hasOwn(descriptor, 'sha256')
        || Object.keys(descriptor).length !== 2
        || !Number.isInteger(descriptor.size)
        || descriptor.size < 0
        || descriptor.size > 65_536
        || typeof descriptor.sha256 !== 'string'
        || !/^[0-9a-f]{64}$/.test(descriptor.sha256)
      ) {
        return { ok: false, error: 'transfer_failed', reason: 'malformed_metadata', phase: 'begin' };
      }
    }

    const files = [];
    const digests = [];
    let privateInput;
    let received = 0;
    // One frame at a time, each acked before the next is written. The broker will not
    // send frame i+1 until it has checked this receiver's digest for frame i against
    // the manifest, which is what makes "the receiver has the bytes" independent of
    // the socket send buffer — see `file_claim.receipt` in the contract.
    for (let index = 0; index !== null; ) {
      const privateFrame = metadata.private_text !== undefined && index === 0;
      const fileIndex = index - (metadata.private_text !== undefined ? 1 : 0);
      const entry = privateFrame ? metadata.private_text : metadata.files[fileIndex];
      if (!entry || !Number.isSafeInteger(entry.size) || entry.size < 0) {
        return { ok: false, error: 'transfer_failed', reason: 'malformed_metadata', phase: 'frames' };
      }
      const header = [];
      const headerBytes = await reader.readBytes(FRAME_HEADER_BYTES, (chunk) =>
        header.push(Buffer.from(chunk)),
      );
      if (headerBytes < FRAME_HEADER_BYTES) {
        return { ok: false, error: 'transfer_failed', reason: 'truncated', phase: 'frames', index };
      }
      const frameLength = Buffer.concat(header).readUInt32BE(0);
      // The advertised size and the framed length are two statements about the
      // same number; a disagreement is a broken transport, not something to
      // reconcile in favour of either one. Reading `frameLength` bytes anyway
      // would mis-attribute the remainder to the next file and surface as a
      // `size_mismatch` pointing at this receiver rather than at the framing. The
      // Python receiver refuses on the same terms — two implementations of one
      // protocol must not differ in strictness.
      if (frameLength !== entry.size) {
        return {
          ok: false,
          error: 'transfer_failed',
          reason: 'frame_length_mismatch',
          phase: 'frames',
          index,
        };
      }

      const hash = createHash('sha256');
      const parts = [];
      const got = await reader.readBytes(frameLength, (chunk) => {
        hash.update(chunk);
        // Streamed, not accumulated: this is the callback a spool writes from, and
        // it sees every byte whether or not anything is retained afterwards.
        if (onChunk && !privateFrame) onChunk(chunk, { index: fileIndex, entry });
        if (collectBytes || privateFrame) parts.push(Buffer.from(chunk));
      });
      received += got;
      const digest = hash.digest('hex');
      if (privateFrame) {
        if (digest !== entry.sha256) {
          return { ok: false, error: 'transfer_failed', reason: 'digest_mismatch', phase: 'frames' };
        }
        try {
          privateInput = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(parts));
        } catch {
          return { ok: false, error: 'transfer_failed', reason: 'invalid_utf8', phase: 'frames' };
        }
      } else {
        files.push({
          name: entry.name,
          type: entry.type,
          size: entry.size,
          frameLength,
          sha256: digest,
          ...(collectBytes ? { bytes: Buffer.concat(parts) } : {}),
        });
      }
      digests.push(digest);
      if (got < frameLength) {
        return { ok: false, error: 'transfer_failed', reason: 'truncated', phase: 'frames', index };
      }

      // The ack, over the bytes that actually arrived. The broker checks it against
      // the manifest before it writes anything else, so a receiver cannot reach the
      // commit without having read every frame.
      await writeLine(socket, {
        op: 'ack_frame',
        transfer_id: metadata.transfer_id,
        index,
        size: got,
        sha256: digest,
      });
      const ackLine = await reader.readLine();
      if (ackLine === null) {
        return { ok: false, error: 'transfer_failed', reason: 'connection_closed', phase: 'ack', index };
      }
      const ack = parseLine(ackLine);
      if (ack === null) {
        return { ok: false, error: 'transfer_failed', reason: 'malformed_answer', phase: 'ack', index };
      }
      if (!ack.ok) return { ...ack, phase: 'ack', index };
      index = ack.next_index ?? null;
    }

    await writeLine(socket, {
      op: 'commit_file_claim',
      handoff_id: handoffId,
      transfer_id: metadata.transfer_id,
      received_bytes: received,
      digests,
    });
    commitWritten = true;

    const answerLine = await reader.readLine();
    // From here on the outcome is the broker's, and silence is not a refusal.
    if (answerLine === null) return indeterminate('commit_answer_lost');
    const answer = parseLine(answerLine);
    if (answer === null) return indeterminate('malformed_answer');
    if (!answer.ok) return { ...answer, phase: 'commit' };
    return {
      ok: true,
      handoffId: answer.handoff_id,
      status: answer.status,
      fileCount: answer.files,
      bytes: answer.bytes,
      transferId: metadata.transfer_id,
      leaseExpiresAt: metadata.lease_expires_at,
      totalBytes: metadata.total_bytes,
      files,
      ...(privateInput === undefined ? {} : { privateInput }),
    };
  } catch (error) {
    const detail = (socketError ?? error).message;
    // A transport fault after the commit went out is the same unknown as a closed
    // connection: the broker may have accepted it and lost only the answer.
    if (commitWritten) return { ...indeterminate('transport_after_commit'), detail };
    return { ok: false, error: 'transfer_failed', reason: 'transport', phase: 'transport', detail };
  } finally {
    socket.destroy();
  }
}
