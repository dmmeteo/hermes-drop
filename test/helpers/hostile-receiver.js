// A deliberately misbehaving file-claim receiver. **Test-only, and it lives here
// for that reason.**
//
// Proving that a failed transfer costs a refusal rather than a payload needs a
// receiver that abandons mid-stream, reads half the bytes, commits twice, commits a
// digest it never computed, or speaks out of turn. Every one of those is a
// primitive no real receiver should have — `mutateCommit` in particular can rewrite
// the digests, which is a forge-a-commit primitive — so none of them belong in
// `src/file-claim-client.js`, a module slice 4 will import for real.
//
// What is shared with production is only the byte reader (`FrameReader`), because a
// reader cannot forge anything. The conversation itself is driven here, which has a
// second benefit: it is an independent implementation of the same wire format, so a
// test passing here and there is two readings of the contract agreeing rather than
// one reading agreeing with itself.
import { connect } from 'node:net';
import { createHash } from 'node:crypto';

import { FRAME_HEADER_BYTES, FrameReader, parseLine, writeLine } from '../../src/file-claim-client.js';

const DEFAULT_TIMEOUT_MS = 30_000;

/**
 * Runs one file claim with any of the hooks below, and answers with the same
 * verdict shape `receiveFileClaim` uses.
 *
 * Hooks, and the failure each one models:
 *
 *   onMetadata(metadata, control)   inspect or interfere the moment the manifest
 *                                  lands. `'abort'` hangs up before a single frame.
 *   afterFrames(state, control)     `'abort'` = the receiver's process died with the
 *                                  bytes in hand; `'skip-commit'` = it half-closes
 *                                  and never commits; a delay sits on the lease.
 *   afterCommit(answerless)         runs once the commit line is out but before any
 *                                  answer is read. `'abort'` is the indeterminate
 *                                  case: the broker may have accepted it.
 *   mutateCommit(commit, state)     rewrite the ACK — wrong digests, wrong order,
 *                                  wrong count, wrong byte total, wrong transfer id.
 *   commitTimes                     >1 sends them together, so the broker has to
 *                                  settle a genuine double commit.
 *   stopReadingAfterBytes           stop reading the socket at all: a receiver whose
 *                                  process died mid-transfer. Only meaningful with an
 *                                  abort, since the rest of the stream is still
 *                                  queued ahead of any answer.
 *   truncateAfterBytes              read every byte but stop feeding the digest after
 *                                  N — a receiver that took the whole transfer and
 *                                  lost part of it on the way to disk. The commit is
 *                                  then honest about its byte count and wrong about
 *                                  its digest.
 *   pipelineCommit                  write the commit *with* the begin, before a frame
 *                                  has been read, using digests computed from
 *                                  content the caller already knows. This is the
 *                                  out-of-turn case the broker must refuse.
 *   commitAfterMetadata(metadata)   the same violation one step later: read the
 *                                  manifest, commit on the strength of content
 *                                  already known, and only then drain what was sent.
 *                                  It gets the real transfer id, so the transfer-id
 *                                  check cannot be what refuses it. Implies no acks.
 *   ackFrames: false                never ack a frame. The broker parks after frame 0
 *                                  and sends nothing more.
 *   mutateAck(ack, state)           rewrite an ack — wrong digest, wrong size, wrong
 *                                  index, wrong transfer id.
 *   afterFrameRead(state, control)  runs once each frame has been read and hashed but
 *                                  before its ack goes out. `'abort'` is a receiver
 *                                  that died with an ack outstanding; a delay sits on
 *                                  the lease at exactly that point.
 *   extraAckBeforeCommit            send one more ack after the last frame is already
 *                                  acked, when nothing is outstanding.
 *   onFrameAck(answer)              observe each ack answer (`index`, `next_index`).
 */
export async function hostileFileClaim(
  socketPath,
  handoffId,
  {
    leaseMs,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    collectBytes = true,
    onMetadata,
    afterFrames,
    afterCommit,
    mutateCommit,
    commitTimes = 1,
    stopReadingAfterBytes = Infinity,
    truncateAfterBytes = Infinity,
    pipelineCommit,
    commitAfterMetadata,
    ackFrames = true,
    mutateAck,
    afterFrameRead,
    extraAckBeforeCommit = false,
    onFrameAck,
  } = {},
) {
  const socket = connect(socketPath);
  socket.setTimeout(timeoutMs, () => socket.destroy(new Error('file claim timed out')));
  const reader = new FrameReader(socket);
  let socketError = null;
  socket.on('error', (error) => {
    socketError = error;
  });
  let commitWritten = false;

  // `writeLine`/`readLine` go through the same reader the transfer uses, because a
  // second listener on `socket` would compete with it for data events and lose.
  const control = {
    socket,
    abort: () => socket.destroy(),
    writeLine: (request) => writeLine(socket, request),
    readLine: () => reader.readLine(),
  };

  const aborted = (phase) => ({ ok: false, error: 'transfer_failed', reason: 'aborted', phase });

  try {
    await new Promise((resolve, reject) => {
      socket.once('connect', resolve);
      socket.once('error', reject);
    });

    const begin = { op: 'begin_file_claim', handoff_id: handoffId };
    if (leaseMs !== undefined) begin.lease_ms = leaseMs;

    if (pipelineCommit) {
      // Both lines in one write, so the commit is in the broker's inbound buffer
      // before it has finished — or in some orderings, before it has started —
      // writing the frames.
      await new Promise((resolve, reject) => {
        socket.write(
          `${JSON.stringify(begin)}\n${JSON.stringify({ op: 'commit_file_claim', handoff_id: handoffId, ...pipelineCommit })}\n`,
          (error) => (error ? reject(error) : resolve()),
        );
      });
      commitWritten = true;
    } else {
      await writeLine(socket, begin);
    }

    const metadataLine = await reader.readLine();
    if (metadataLine === null) {
      return { ok: false, error: 'transfer_failed', reason: 'connection_closed', phase: 'begin' };
    }
    const metadata = parseLine(metadataLine);
    if (metadata === null) {
      return { ok: false, error: 'transfer_failed', reason: 'malformed_metadata', phase: 'begin' };
    }
    if (!metadata.ok) return { ...metadata, phase: 'begin' };

    if (pipelineCommit) {
      // The commit went out before a single frame was read, which is the whole point.
      // The frames were still written, though, so they sit in the stream ahead of any
      // answer: they have to be drained to reach it. Draining is not reading in the
      // sense that matters — nothing is hashed and the commit that was already sent
      // could not have depended on them — and it is the only way to observe the
      // refusal rather than a truncated line of binary.
      // Only frame 0 was written: the broker sends one frame and then waits for its
      // ack, so nothing else is ahead of the answer.
      await reader.readBytes(FRAME_HEADER_BYTES + (metadata.files[0]?.size ?? 0), () => {});
      const answerLine = await reader.readLine();
      if (answerLine === null) {
        return { ok: false, error: 'transfer_indeterminate', reason: 'commit_answer_lost', phase: 'commit' };
      }
      return { ...(parseLine(answerLine) ?? {}), phase: 'commit', pipelined: true };
    }

    if (onMetadata) {
      const verdict = await onMetadata(metadata, control);
      if (verdict === 'abort') {
        socket.destroy();
        return aborted('metadata');
      }
    }

    if (commitAfterMetadata) {
      // The commit goes out having read the manifest and not one frame byte — the
      // case that matters, because the digests can only be right if this caller
      // already knew the content. The frames are then drained (not hashed, not
      // collected) purely to reach the answer line behind them; a receiver that
      // simply stopped reading would deadlock against a broker mid-write instead of
      // observing its refusal.
      await writeLine(socket, {
        op: 'commit_file_claim',
        handoff_id: handoffId,
        ...commitAfterMetadata(metadata),
      });
      commitWritten = true;
      // Same as above: frame 0 is all the broker sent before it parked.
      await reader.readBytes(FRAME_HEADER_BYTES + (metadata.files[0]?.size ?? 0), () => {});
      const answerLine = await reader.readLine();
      if (answerLine === null) {
        return { ok: false, error: 'transfer_indeterminate', reason: 'commit_answer_lost', phase: 'commit' };
      }
      return { ...(parseLine(answerLine) ?? {}), phase: 'commit', earlyCommit: true };
    }

    const files = [];
    let received = 0;
    let hashed = 0;
    let truncated = false;
    let index = 0;
    while (index !== null) {
      const entry = metadata.files[index];
      const header = [];
      const headerBytes = await reader.readBytes(FRAME_HEADER_BYTES, (chunk) =>
        header.push(Buffer.from(chunk)),
      );
      if (headerBytes < FRAME_HEADER_BYTES) {
        truncated = true;
        break;
      }
      const frameLength = Buffer.concat(header).readUInt32BE(0);

      const hash = createHash('sha256');
      const parts = [];
      const wanted = Math.min(frameLength, Math.max(0, stopReadingAfterBytes - received));
      const got = await reader.readBytes(wanted, (chunk) => {
        // Everything read counts as received; only the first `truncateAfterBytes`
        // reach the digest. With the default the two are the same number, which is
        // what an honest receiver does.
        const room = Math.max(0, truncateAfterBytes - hashed);
        if (room === 0) return;
        const kept = chunk.subarray(0, Math.min(room, chunk.length));
        hash.update(kept);
        hashed += kept.length;
        if (collectBytes) parts.push(Buffer.from(kept));
      });
      received += got;
      const digest = hash.digest('hex');
      files.push({
        name: entry?.name,
        type: entry?.type,
        size: entry?.size,
        frameLength,
        sha256: digest,
        index,
        ...(collectBytes ? { bytes: Buffer.concat(parts) } : {}),
      });
      if (got < wanted) {
        truncated = true;
        break;
      }

      if (afterFrameRead) {
        const verdict = await afterFrameRead({ index, frameLength, received, metadata }, control);
        if (verdict === 'abort') {
          socket.destroy();
          return aborted('frame_ack');
        }
      }

      if (!ackFrames) break;

      let ack = {
        op: 'ack_frame',
        transfer_id: metadata.transfer_id,
        index,
        size: got,
        sha256: digest,
      };
      if (mutateAck) ack = mutateAck(ack, { index, entry, metadata });
      await writeLine(socket, ack);

      const ackLine = await reader.readLine();
      if (ackLine === null) {
        return { ok: false, error: 'transfer_failed', reason: 'connection_closed', phase: 'ack', index };
      }
      const answered = parseLine(ackLine);
      if (answered === null) {
        return { ok: false, error: 'transfer_failed', reason: 'malformed_answer', phase: 'ack', index };
      }
      if (onFrameAck) onFrameAck(answered);
      if (!answered.ok) return { ...answered, phase: 'ack', index };
      index = answered.next_index ?? null;
    }

    if (extraAckBeforeCommit) {
      // Nothing is outstanding now, so this ack has no frame to be about.
      await writeLine(socket, {
        op: 'ack_frame',
        transfer_id: metadata.transfer_id,
        index: metadata.files.length - 1,
        size: metadata.files[metadata.files.length - 1].size,
        sha256: files[files.length - 1].sha256,
      });
      const line = await reader.readLine();
      if (line === null) {
        return { ok: false, error: 'transfer_failed', reason: 'connection_closed', phase: 'ack' };
      }
      return { ...(parseLine(line) ?? {}), phase: 'ack', extraAck: true };
    }

    if (afterFrames) {
      const verdict = await afterFrames({ metadata, files, received, truncated }, control);
      if (verdict === 'abort') {
        socket.destroy();
        return aborted('frames');
      }
      if (verdict === 'skip-commit') {
        socket.end();
        return { ok: false, error: 'transfer_failed', reason: 'not_committed', phase: 'frames' };
      }
    }

    let commit = {
      op: 'commit_file_claim',
      handoff_id: handoffId,
      transfer_id: metadata.transfer_id,
      received_bytes: received,
      digests: files.map((file) => file.sha256),
    };
    if (mutateCommit) commit = mutateCommit(commit, { metadata, files });

    let line = '';
    for (let attempt = 0; attempt < commitTimes; attempt += 1) {
      line += `${JSON.stringify(commit)}\n`;
    }
    await new Promise((resolve, reject) => {
      socket.write(line, (error) => (error ? reject(error) : resolve()));
    });
    commitWritten = true;

    if (afterCommit) {
      const verdict = await afterCommit({ metadata, files, received }, control);
      if (verdict === 'abort') {
        socket.destroy();
        // The commit is out and nobody read the answer: the one genuinely unknown
        // outcome in the protocol.
        return { ok: false, error: 'transfer_indeterminate', reason: 'commit_answer_lost', phase: 'commit' };
      }
    }

    const answers = [];
    for (let attempt = 0; attempt < commitTimes; attempt += 1) {
      const answerLine = await reader.readLine();
      if (answerLine === null) break;
      answers.push(parseLine(answerLine) ?? { ok: false, error: 'transfer_failed', reason: 'malformed_answer' });
    }
    if (answers.length === 0) {
      return { ok: false, error: 'transfer_indeterminate', reason: 'commit_answer_lost', phase: 'commit' };
    }

    const answer = answers[0];
    if (!answer.ok) return { ...answer, phase: 'commit', answers };
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
      answers,
    };
  } catch (error) {
    const detail = (socketError ?? error).message;
    if (commitWritten) {
      return { ok: false, error: 'transfer_indeterminate', reason: 'transport_after_commit', phase: 'commit', detail };
    }
    return { ok: false, error: 'transfer_failed', reason: 'transport', phase: 'transport', detail };
  } finally {
    socket.destroy();
  }
}
