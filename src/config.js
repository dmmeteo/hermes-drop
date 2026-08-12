// Deployment configuration. Everything security-relevant is server-side and
// never client-supplied.
import {
  DEFAULT_FILE_LIMITS,
  FileContainerError,
  fileContainerCeiling,
  resolveFileLimits,
} from './file-container.js';
// The outbound lifetime floor is the store's own rule (src/outbound-drop.js); it is
// read here so a deployment cannot configure a default the store would refuse.
import { MIN_OUTBOUND_TTL_SECONDS } from './outbound-drop.js';

/**
 * What one file drop reserves: the largest plaintext it could ever hold, which is
 * the whole container — 42 MiB of file bytes plus the header and the manifest
 * ceiling. Reserving only the file-byte total would leave the broker holding
 * ~6.4 KB per drop it never accounted for, and the reservation is supposed to
 * *be* the worst case rather than approximately it.
 */
export const FILE_RESERVATION_BYTES = fileContainerCeiling(DEFAULT_FILE_LIMITS);

/**
 * The process-wide ceiling on live file-drop bytes: four fully reserved drops
 * (docs/FILE_TRANSFER_MVP.md, "Broker model").
 *
 * Like the per-drop caps it may only be lowered. It is not a free-standing
 * operational dial: it is derived from `DEFAULT_FILE_LIMITS`, so raising it is a
 * decision about how much of this process's memory a browser can reserve, and
 * belongs in a change to these defaults reviewed with them.
 *
 * It bounds *resident payload* bytes. It does not bound the transient cost of the
 * submission path itself, which buffers a base64 body and decodes it; that is
 * bounded separately, by admitting at most one widened body per drop
 * (`acquireSubmitSlot` in src/broker.js).
 */
export const DEFAULT_MAX_LIVE_FILE_BYTES = 4 * FILE_RESERVATION_BYTES;

/**
 * How long one ordinary request may take, end to end. Enforced by this process
 * rather than by `server.requestTimeout`, so a request that runs out of time can
 * be answered with the same uniform body as every other refusal instead of
 * Node's 408 (src/public-server.js).
 */
const DEFAULT_REQUEST_TIMEOUT_MS = 15_000;

/**
 * The deadline for one *admitted file submission*, and nothing else.
 *
 * A maximal drop is a 44,046,639-byte container, which is 58,728,876 characters of
 * base64 on the wire. The 15-second default cannot carry that below ~31 Mbit/s
 * sustained upstream, so with only that number the advertised 42 MiB would be a
 * promise the transport cannot keep — the MVP's acceptance criterion is a drop
 * that can actually be *submitted*. 600 seconds clears a maximal body at slightly
 * under 1 Mbit/s, which is the low end of a real mobile uplink.
 */
const DEFAULT_FILE_SUBMIT_TIMEOUT_MS = 600_000;

/**
 * How far past a body ceiling this server will keep reading purely so the client
 * still gets the uniform `unavailable` instead of a connection reset.
 *
 * Additive on purpose. It used to be `ceiling * 8`, which was ~1 MiB of politeness
 * at the 128 KiB text ceiling and became a ~470 MB single-request drain once the
 * file ceiling grew 448x. A constant keeps the drain a fraction of the ceiling
 * rather than a multiple of it, and 1 MiB is chosen so every over-limit body that
 * used to be answered politely still is.
 */
const DEFAULT_BODY_OVERRUN_ALLOWANCE_BYTES = 1024 * 1024;

/**
 * How long one file-claim transfer lease may live (docs/FILE_TRANSFER_MVP.md,
 * "Lifecycle changes": a bounded lease timeout returns `transferring` to
 * `submitted`).
 *
 * It bounds two different things at once, which is why it is an operator's number
 * and a receiver may only narrow it. It is the longest a crashed or wedged
 * receiver can keep a drop out of reach of the next one — and, because a leased
 * drop still holds its live-file reservation, the longest it can hold a quarter of
 * the process-wide file budget without making progress.
 *
 * 60 seconds is generous for what happens inside a lease: the bytes travel over a
 * Unix socket, and the receiver's real work is hashing them and writing them to a
 * local disk. A maximal 42 MiB drop needs roughly two seconds of that on an
 * ordinary SSD and well under twenty on a slow one.
 */
const DEFAULT_FILE_CLAIM_LEASE_MS = 60_000;

/**
 * How many transfer leases one handoff will grant without a commit.
 *
 * Each granted lease costs a full SHA-256 pass over the container — up to 42 MiB of
 * event-loop-blocking hashing — and a failed transfer deliberately restores the drop
 * for free, so the pass is repeatable for the whole TTL unless it is bounded. The
 * submit path bounds container validation the same way and for the same stated
 * reason (`containerFailures`, `src/broker.js`).
 *
 * It differs from that one in what happens when the budget is spent: the submit path
 * destroys the drop, because the caller there is proving it cannot produce a valid
 * container. Here the container is known good and the failures are the *receiver's*,
 * so destroying would throw away the user's files over a broken consumer. The
 * handoff simply stops granting leases and lapses on its TTL.
 *
 * Eight leaves real room for the retries a receiver legitimately needs — a crash, a
 * lapsed lease, a lost connection — while capping the work one drop can be made to
 * do at roughly a second of hashing.
 */
const DEFAULT_MAX_TRANSFER_ATTEMPTS = 8;

/**
 * The outbound drop's own default TTL: thirty minutes for this deployment.
 *
 * Configurable, and deliberately a *separate* number from the inbound `ttlSeconds`
 * even though the two currently agree: an inbound drop waits for a person to compose
 * a secret, an outbound one waits for a person to open a link and type three digits,
 * and those are different windows to reason about. The shorter it is the less of it
 * there is for anyone else in the conversation to open the link in, which is the
 * argument for lowering it — but it is a deployment policy, not a constant, so it is
 * an operator's dial rather than a hard-coded number.
 */
const DEFAULT_OUTBOUND_TTL_SECONDS = 1800;

/**
 * The outbound hard maximum: the longest outbound drop a caller may *ask* for.
 *
 * Distinct from `maxTtlSeconds` because outbound exposure is a different risk from
 * inbound: an outbound link and its code sit in a conversation everyone in it can
 * read, so an operator has to be able to shorten the outbound ceiling without
 * shortening the window a user gets to compose an inbound secret. It is narrow-only
 * against `maxTtlSeconds` — no outbound drop may outlive the broker's own maximum —
 * and it must not be below `outboundTtlSeconds`, or the default would not fit inside
 * its own ceiling.
 *
 * Deliberately *not* equal to the default: an exceptional request above the default
 * is legitimate (a secret handed to someone who has to walk to another machine), and
 * capping requests at the default would refuse it with no dial to allow it.
 */
const DEFAULT_MAX_OUTBOUND_TTL_SECONDS = 3600;

/**
 * The largest outbound secret this broker will accept, and a narrow-only ceiling.
 *
 * It is small because of where the plaintext comes from: an outbound secret arrives
 * on the control socket, inside one newline-delimited request line bounded at 4096
 * bytes (`MAX_CONTROL_LINE_BYTES`, src/control-server.js). 2048 bytes of secret is
 * 2732 characters of base64, which leaves the rest of the line to its own fields
 * with room to spare — and the feature is a short private value, not a file
 * (MVP, "Deliberate scope": outbound file sharing is out).
 */
export const MAX_OUTBOUND_PLAINTEXT_BYTES = 2048;

/**
 * How long a reserved outbound drop waits for its claimant's acknowledgement.
 *
 * It bounds the one window in which the payload is both decryptable by a browser
 * and still resident here, so it is what makes "destroyed after reveal" true for a
 * browser that reveals and then vanishes. A raise as well as a lower is an
 * operator's call — it is a statement about how long a phone on a bad connection
 * needs to retry the same claim — but it may not outlive the drop it is inside, and
 * it is clamped to the record's own expiry at claim time regardless.
 */
const DEFAULT_OUTBOUND_ACK_WINDOW_MS = 60_000;

export const DEFAULTS = Object.freeze({
  port: 8787,
  host: '0.0.0.0',
  /** Absolute base URL used to print handoff links. Resolved after listen when unset. */
  baseUrl: null,
  ttlSeconds: 1800,
  maxTtlSeconds: 3600,
  maxPlaintextBytes: 65536,
  maxBodyBytes: 131072,
  maxAeadFailures: 3,
  controlSocketPath: './run/control.sock',
  sweepIntervalMs: 1000,
  enableHsts: false,
  // File-drop caps. Deliberately *not* derived from maxPlaintextBytes: keeping
  // the two apart is what stops a multi-megabyte file limit from silently
  // becoming the ceiling on secrets and tool results as well.
  maxFiles: DEFAULT_FILE_LIMITS.maxFiles,
  maxFileBytes: DEFAULT_FILE_LIMITS.maxFileBytes,
  maxFileTotalBytes: DEFAULT_FILE_LIMITS.maxTotalBytes,
  maxLiveFileBytes: DEFAULT_MAX_LIVE_FILE_BYTES,
  requestTimeoutMs: DEFAULT_REQUEST_TIMEOUT_MS,
  fileSubmitTimeoutMs: DEFAULT_FILE_SUBMIT_TIMEOUT_MS,
  bodyOverrunAllowanceBytes: DEFAULT_BODY_OVERRUN_ALLOWANCE_BYTES,
  fileClaimLeaseMs: DEFAULT_FILE_CLAIM_LEASE_MS,
  maxTransferAttempts: DEFAULT_MAX_TRANSFER_ATTEMPTS,
  // Outbound drops. Separate from every number above because the direction is
  // reversed: these bound a secret this broker was *given*, not one it was sent.
  outboundTtlSeconds: DEFAULT_OUTBOUND_TTL_SECONDS,
  maxOutboundTtlSeconds: DEFAULT_MAX_OUTBOUND_TTL_SECONDS,
  maxOutboundPlaintextBytes: MAX_OUTBOUND_PLAINTEXT_BYTES,
  outboundAckWindowMs: DEFAULT_OUTBOUND_ACK_WINDOW_MS,
});

const NUMERIC = new Set([
  'port',
  'ttlSeconds',
  'maxTtlSeconds',
  'maxPlaintextBytes',
  'maxBodyBytes',
  'maxAeadFailures',
  'sweepIntervalMs',
  'maxFiles',
  'maxFileBytes',
  'maxFileTotalBytes',
  'maxLiveFileBytes',
  'requestTimeoutMs',
  'fileSubmitTimeoutMs',
  'bodyOverrunAllowanceBytes',
  'fileClaimLeaseMs',
  'maxTransferAttempts',
  'outboundTtlSeconds',
  'maxOutboundTtlSeconds',
  'maxOutboundPlaintextBytes',
  'outboundAckWindowMs',
]);

const ENV_KEYS = {
  HANDOFF_PORT: 'port',
  HANDOFF_HOST: 'host',
  HANDOFF_BASE_URL: 'baseUrl',
  HANDOFF_TTL_SECONDS: 'ttlSeconds',
  HANDOFF_MAX_TTL_SECONDS: 'maxTtlSeconds',
  HANDOFF_MAX_PLAINTEXT_BYTES: 'maxPlaintextBytes',
  HANDOFF_MAX_BODY_BYTES: 'maxBodyBytes',
  HANDOFF_MAX_AEAD_FAILURES: 'maxAeadFailures',
  HANDOFF_CONTROL_SOCKET: 'controlSocketPath',
  HANDOFF_ENABLE_HSTS: 'enableHsts',
  HANDOFF_MAX_FILES: 'maxFiles',
  HANDOFF_MAX_FILE_BYTES: 'maxFileBytes',
  HANDOFF_MAX_FILE_TOTAL_BYTES: 'maxFileTotalBytes',
  HANDOFF_MAX_LIVE_FILE_BYTES: 'maxLiveFileBytes',
  HANDOFF_REQUEST_TIMEOUT_MS: 'requestTimeoutMs',
  HANDOFF_FILE_SUBMIT_TIMEOUT_MS: 'fileSubmitTimeoutMs',
  HANDOFF_BODY_OVERRUN_ALLOWANCE_BYTES: 'bodyOverrunAllowanceBytes',
  HANDOFF_FILE_CLAIM_LEASE_MS: 'fileClaimLeaseMs',
  HANDOFF_MAX_TRANSFER_ATTEMPTS: 'maxTransferAttempts',
  HANDOFF_OUTBOUND_TTL_SECONDS: 'outboundTtlSeconds',
  HANDOFF_MAX_OUTBOUND_TTL_SECONDS: 'maxOutboundTtlSeconds',
  HANDOFF_MAX_OUTBOUND_PLAINTEXT_BYTES: 'maxOutboundPlaintextBytes',
  HANDOFF_OUTBOUND_ACK_WINDOW_MS: 'outboundAckWindowMs',
};

/** The environment key an operator would have set to produce this config key. */
const ENV_KEY_FOR = Object.fromEntries(
  Object.entries(ENV_KEYS).map(([envKey, key]) => [key, envKey]),
);

/**
 * Validates the three per-drop file caps through the codec's own resolver, so
 * the broker, the container and the browser cannot disagree about what a limit
 * means. The resolver is narrow-only by construction: an attempt to *raise* any
 * cap is refused rather than clamped, because the manifest ceiling, the live
 * budget and the browser's advertised limits are all derived from the same
 * defaults, and a raise that only took effect in one of them would fail late.
 *
 * A refusal names the environment key an operator would have set, because a
 * `bad_limits` code on its own tells them nothing about which line to fix.
 */
function resolveConfiguredFileLimits(config) {
  try {
    return resolveFileLimits({
      maxFiles: config.maxFiles,
      maxFileBytes: config.maxFileBytes,
      maxTotalBytes: config.maxFileTotalBytes,
    });
  } catch (error) {
    if (!(error instanceof FileContainerError)) throw error;
    const keys = ['maxFiles', 'maxFileBytes', 'maxFileTotalBytes']
      .map((key) => `${ENV_KEY_FOR[key]}=${config[key]}`)
      .join(', ');
    const why =
      error.code === 'limits_too_high'
        ? 'file limits may only be lowered from the reviewed defaults ' +
          `(${DEFAULT_FILE_LIMITS.maxFiles} files, ${DEFAULT_FILE_LIMITS.maxFileBytes} bytes ` +
          `per file, ${DEFAULT_FILE_LIMITS.maxTotalBytes} bytes in total)`
        : 'file limits are not a coherent set';
    throw new Error(`${why}: ${keys} (${error.code})`, { cause: error });
  }
}

export function loadConfig(overrides = {}, env = process.env) {
  const config = { ...DEFAULTS };

  for (const [envKey, key] of Object.entries(ENV_KEYS)) {
    const raw = env[envKey];
    if (raw === undefined || raw === '') continue;
    if (NUMERIC.has(key)) {
      const parsed = Number(raw);
      if (!Number.isFinite(parsed) || parsed < 0) throw new Error(`${envKey} must be a number`);
      config[key] = parsed;
    } else if (key === 'enableHsts') {
      config[key] = raw === '1' || raw.toLowerCase() === 'true';
    } else {
      config[key] = raw;
    }
  }

  Object.assign(config, overrides);

  if (config.ttlSeconds <= 0 || config.ttlSeconds > config.maxTtlSeconds) {
    throw new Error('ttlSeconds must be > 0 and <= maxTtlSeconds');
  }
  if (config.maxBodyBytes <= config.maxPlaintextBytes) {
    throw new Error('maxBodyBytes must exceed maxPlaintextBytes');
  }

  /** The frozen triple every file-aware component reads, instead of three loose numbers. */
  config.fileLimits = resolveConfiguredFileLimits(config);

  if (
    !Number.isSafeInteger(config.maxLiveFileBytes) ||
    config.maxLiveFileBytes < 1 ||
    config.maxLiveFileBytes > DEFAULT_MAX_LIVE_FILE_BYTES
  ) {
    throw new Error(
      `${ENV_KEY_FOR.maxLiveFileBytes} must be a positive integer and may only be lowered ` +
        `from ${DEFAULT_MAX_LIVE_FILE_BYTES} (got ${config.maxLiveFileBytes})`,
    );
  }
  /** What one file drop of these limits reserves, so nothing has to re-derive it. */
  config.fileReservationBytes = fileContainerCeiling(config.fileLimits);

  // A budget under a single drop's reservation cannot admit any file drop at all.
  // That is a deployment that is broken at startup, so it is refused there rather
  // than answering every file creation with the uniform unavailable at runtime.
  if (config.maxLiveFileBytes < config.fileReservationBytes) {
    throw new Error(
      `${ENV_KEY_FOR.maxLiveFileBytes} (${config.maxLiveFileBytes}) is below one drop's ` +
        `reservation of ${config.fileReservationBytes} bytes ` +
        `(${ENV_KEY_FOR.maxFileTotalBytes}=${config.fileLimits.maxTotalBytes} plus the ` +
        'container header and manifest ceiling): no file drop could ever be created',
    );
  }

  // Timeouts. A deadline may be raised as well as lowered — it is a statement
  // about the deployment's upstream bandwidth, not a security ceiling — but it may
  // not outlive the drop it is carrying, because a request that is still uploading
  // when its handoff lapses cannot succeed.
  if (!Number.isSafeInteger(config.requestTimeoutMs) || config.requestTimeoutMs < 1) {
    throw new Error(`${ENV_KEY_FOR.requestTimeoutMs} must be a positive integer`);
  }
  if (
    !Number.isSafeInteger(config.fileSubmitTimeoutMs) ||
    config.fileSubmitTimeoutMs < config.requestTimeoutMs
  ) {
    throw new Error(
      `${ENV_KEY_FOR.fileSubmitTimeoutMs} must be an integer at or above ` +
        `${ENV_KEY_FOR.requestTimeoutMs} (${config.requestTimeoutMs}): it extends that deadline ` +
        'for one admitted file submission, it does not replace it',
    );
  }
  if (config.fileSubmitTimeoutMs > config.maxTtlSeconds * 1000) {
    throw new Error(
      `${ENV_KEY_FOR.fileSubmitTimeoutMs} (${config.fileSubmitTimeoutMs}) exceeds the longest ` +
        `drop this broker will mint (${ENV_KEY_FOR.maxTtlSeconds}=${config.maxTtlSeconds}s): ` +
        'an upload that outlives its handoff cannot be accepted',
    );
  }
  if (
    !Number.isSafeInteger(config.bodyOverrunAllowanceBytes) ||
    config.bodyOverrunAllowanceBytes < 0
  ) {
    throw new Error(`${ENV_KEY_FOR.bodyOverrunAllowanceBytes} must be a non-negative integer`);
  }
  // A lease may be raised as well as lowered — how long a receiver legitimately
  // needs is a fact about the operator's disk, not a security ceiling — but it may
  // not outlive the longest drop this broker will mint, because a lease on a
  // handoff that has already lapsed cannot be committed.
  if (!Number.isSafeInteger(config.fileClaimLeaseMs) || config.fileClaimLeaseMs < 1) {
    throw new Error(`${ENV_KEY_FOR.fileClaimLeaseMs} must be a positive integer`);
  }
  // At least two, or a single transient failure would strand a payload nobody can
  // collect — which is the loss the whole two-phase design exists to prevent.
  if (!Number.isSafeInteger(config.maxTransferAttempts) || config.maxTransferAttempts < 2) {
    throw new Error(
      `${ENV_KEY_FOR.maxTransferAttempts} must be an integer of at least 2: one transfer must ` +
        'be retriable after a receiver crash, or a lost connection would strand the payload',
    );
  }
  if (config.fileClaimLeaseMs > config.maxTtlSeconds * 1000) {
    throw new Error(
      `${ENV_KEY_FOR.fileClaimLeaseMs} (${config.fileClaimLeaseMs}) exceeds the longest drop ` +
        `this broker will mint (${ENV_KEY_FOR.maxTtlSeconds}=${config.maxTtlSeconds}s): a lease ` +
        'on a handoff that has already lapsed could never be committed',
    );
  }

  // Outbound drops. The ceiling is validated first, because it is what the default
  // below is then checked against: an outbound drop is bounded by its *own* maximum,
  // narrow-only against the broker-wide one, so shortening outbound exposure does not
  // mean shortening the window an inbound drop gets.
  if (
    !Number.isSafeInteger(config.maxOutboundTtlSeconds) ||
    config.maxOutboundTtlSeconds < MIN_OUTBOUND_TTL_SECONDS ||
    // Narrow-only against this module's own constant, not only against the inbound
    // maximum. `maxTtlSeconds` has no ceiling of its own — it is validated as the thing
    // `ttlSeconds` must fit inside — so bounding the outbound ceiling by it alone means
    // an operator who raises the inbound maximum for an inbound reason (a slow uplink
    // and a 42 MiB file drop) silently raises how long an outbound secret and its
    // 3-digit code stay readable in a chat conversation. That is precisely the exposure
    // this dial exists to bound independently, and the README says in bold that it
    // cannot happen. The sibling plaintext ceiling below is narrow-only the same way.
    config.maxOutboundTtlSeconds > DEFAULT_MAX_OUTBOUND_TTL_SECONDS ||
    config.maxOutboundTtlSeconds > config.maxTtlSeconds
  ) {
    throw new Error(
      `${ENV_KEY_FOR.maxOutboundTtlSeconds} must be an integer between ` +
        `${MIN_OUTBOUND_TTL_SECONDS} and ${ENV_KEY_FOR.maxTtlSeconds} ` +
        `(${config.maxTtlSeconds}), and may only be lowered from ` +
        `${DEFAULT_MAX_OUTBOUND_TTL_SECONDS} (got ${config.maxOutboundTtlSeconds})`,
    );
  }
  // The floor is a second, not a positive float. Below that a drop can lapse before
  // the message carrying its own link has rendered, which is indistinguishable to the
  // user from a secret somebody else took — see the same floor in src/outbound-drop.js.
  if (
    !Number.isFinite(config.outboundTtlSeconds) ||
    config.outboundTtlSeconds < MIN_OUTBOUND_TTL_SECONDS ||
    config.outboundTtlSeconds > config.maxOutboundTtlSeconds
  ) {
    throw new Error(
      `${ENV_KEY_FOR.outboundTtlSeconds} must be >= ${MIN_OUTBOUND_TTL_SECONDS} and <= ` +
        `${ENV_KEY_FOR.maxOutboundTtlSeconds} (${config.maxOutboundTtlSeconds}): ` +
        `got ${config.outboundTtlSeconds}`,
    );
  }
  // Narrow-only, like the file caps and for the same class of reason: the ceiling is
  // what keeps an outbound secret inside the control protocol's request line, so a
  // raise would fail late — as a refused request on the socket — rather than here.
  if (
    !Number.isSafeInteger(config.maxOutboundPlaintextBytes) ||
    config.maxOutboundPlaintextBytes < 1 ||
    config.maxOutboundPlaintextBytes > MAX_OUTBOUND_PLAINTEXT_BYTES
  ) {
    throw new Error(
      `${ENV_KEY_FOR.maxOutboundPlaintextBytes} must be a positive integer and may only be ` +
        `lowered from ${MAX_OUTBOUND_PLAINTEXT_BYTES} (got ${config.maxOutboundPlaintextBytes})`,
    );
  }
  if (!Number.isSafeInteger(config.outboundAckWindowMs) || config.outboundAckWindowMs < 1) {
    throw new Error(`${ENV_KEY_FOR.outboundAckWindowMs} must be a positive integer`);
  }
  if (config.outboundAckWindowMs > config.outboundTtlSeconds * 1000) {
    throw new Error(
      `${ENV_KEY_FOR.outboundAckWindowMs} (${config.outboundAckWindowMs}) exceeds the drop it ` +
        `sits inside (${ENV_KEY_FOR.outboundTtlSeconds}=${config.outboundTtlSeconds}s): a window ` +
        'that outlives its own drop is one the broker cannot honour',
    );
  }

  if (config.baseUrl) config.baseUrl = config.baseUrl.replace(/\/+$/, '');

  return Object.freeze(config);
}
