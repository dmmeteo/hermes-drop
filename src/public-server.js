// Public browser-facing HTTP surface. Three things only: the page, its two
// self-hosted assets, and two capability-authorized POST endpoints.
//
// Nothing here reads the query string, and nothing logs anything but the method,
// the path and the status — the capability arrives in a header and the payload is
// ciphertext, so neither can reach the access log.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { PAYLOAD_DECLARATIONS, PAYLOAD_DECLARATION_HEADER } from './broker.js';

/** The single generic unavailable body shared by every failure path. */
export const UNAVAILABLE_JSON = '{"status":"unavailable"}';

export const CAPABILITY_HEADER = 'x-handoff-capability';

/**
 * The pre-body payload declaration (docs/UNIVERSAL_DROP_DELIVERY_PLAN.md, U1),
 * re-exported from the broker that owns and advertises it. It is read here, before
 * the body, because it is what decides how large that body may be.
 */
export { PAYLOAD_DECLARATIONS, PAYLOAD_DECLARATION_HEADER };


const PUBLIC_DIR = fileURLToPath(new URL('./public/', import.meta.url));

const ASSETS = new Map([
  ['/assets/app.js', { file: 'assets/app.js', type: 'text/javascript; charset=utf-8' }],
  ['/assets/app.css', { file: 'app.css', type: 'text/css; charset=utf-8' }],
]);

const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'none'",
  "font-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

function securityHeaders(config) {
  const headers = {
    'content-security-policy': CSP,
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'geolocation=(), camera=(), microphone=(), usb=()',
    'cache-control': 'no-store',
  };
  if (config.enableHsts) {
    headers['strict-transport-security'] = 'max-age=31536000; includeSubDomains';
  }
  return headers;
}

export async function startPublicServer({ config, broker, logger }) {
  const page = await readFile(`${PUBLIC_DIR}index.html`);
  const assets = new Map();
  for (const [route, asset] of ASSETS) {
    try {
      assets.set(route, { body: await readFile(`${PUBLIC_DIR}${asset.file}`), type: asset.type });
    } catch (error) {
      throw new Error(
        `missing asset ${asset.file} — run "npm run build" first (${error.code ?? error.message})`,
      );
    }
  }

  const server = createServer((request, response) => {
    response.removeHeader?.('Server');
    // Every request carries its own deadline. A file submission is the one thing
    // that may extend it, and it does so from inside `handle`.
    const deadline = armDeadline(request, response, config);
    handle(request, response, { config, broker, logger, page, assets, deadline })
      .catch((error) => {
        logger.error?.(`request failed: ${error.message}`);
        if (!response.headersSent) sendUnavailable(response, config);
        else response.end();
      })
      .finally(() => deadline.clear());
  });
  // Bound slow-loris style body dribbling on a prototype with no proxy in front.
  //
  // Header dribbling stays Node's to enforce; `connectionsCheckingInterval` is
  // lowered from its 30-second default so that the 10 seconds below means ten
  // seconds rather than "somewhere inside the next half minute".
  server.headersTimeout = 10_000;
  server.connectionsCheckingInterval = 2_000;
  // The whole-request deadline is this process's own (`armDeadline`), because
  // Node's is one number for the entire server — it cannot be longer for a 56 MiB
  // file submission than for a metadata POST — and because it answers 408, a
  // status the public contract does not have. Node's is kept as a backstop well
  // clear of ours, so a bug in our timer still cannot park a socket forever.
  server.requestTimeout = config.fileSubmitTimeoutMs + 30_000;

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(config.port, config.host, resolve);
  });

  return {
    port: server.address().port,
    async close() {
      await new Promise((resolve) => server.close(resolve));
    },
  };
}

/**
 * One deadline per request, enforced here rather than by `server.requestTimeout`.
 *
 * Two reasons it is ours. First, a maximal file submission legitimately needs
 * minutes while everything else needs seconds, and Node's timeout is one number
 * for the whole server. Second, Node answers an expired request with `408 Request
 * Timeout` — a distinguishable terminal response that a text drop essentially
 * never produced, and that would make the file path the one place where the
 * public contract's single uniform body does not hold. Expiring here answers
 * `{"status":"unavailable"}` like every other refusal.
 *
 * "As far as Node permits" is doing real work in that sentence: the client may
 * still see a reset if the socket dies before the answer flushes, and a body far
 * past its ceiling is still cut off. What is fixed is the ordinary case.
 */
function armDeadline(request, response, config) {
  let timer = null;
  let expired = false;

  const expire = () => {
    expired = true;
    if (!response.headersSent) sendUnavailable(response, config);
    else response.end();
    // Stop reading the upload, but only once the answer is on the wire: destroying
    // the socket first would turn the uniform body into a reset.
    if (response.writableFinished) request.destroy();
    else response.once('finish', () => request.destroy());
  };

  const arm = (ms) => {
    if (timer) clearTimeout(timer);
    timer = setTimeout(expire, ms);
    // The live socket is what holds the process open; this timer only has to fire
    // while that is true, so it must not be the thing that delays a shutdown.
    timer.unref();
  };
  arm(config.requestTimeoutMs);

  return {
    /** Widens the deadline for one admitted file submission. Never narrows it. */
    extend(ms) {
      if (!expired && ms > config.requestTimeoutMs) arm(ms);
    },
    clear() {
      if (timer) clearTimeout(timer);
      timer = null;
    },
    get expired() {
      return expired;
    },
  };
}

async function handle(request, response, context) {
  const { config, broker, logger, page, assets, deadline } = context;
  // Deliberately drop everything after "?": no handoff input is ever read from
  // the request target.
  const path = request.url.split('?')[0];
  const log = (status) => logger.info?.(`${request.method} ${path} ${status}`);

  // Every /api/* request answers with the JSON contract, whatever the method, so
  // probing an endpoint the wrong way discloses nothing new.
  const isApi = path.startsWith('/api/');

  if (!isApi && (request.method === 'GET' || request.method === 'HEAD')) {
    if (path === '/') {
      send(response, 200, page, 'text/html; charset=utf-8', config, request.method === 'HEAD');
      return log(200);
    }
    const asset = assets.get(path);
    if (asset) {
      send(response, 200, asset.body, asset.type, config, request.method === 'HEAD');
      return log(200);
    }
    // Unknown GET target: the same document, so nothing about handoff existence
    // or app structure is discoverable.
    send(response, 404, page, 'text/html; charset=utf-8', config, request.method === 'HEAD');
    return log(404);
  }

  if (request.method === 'POST' && path === '/api/metadata') {
    const capability = request.headers[CAPABILITY_HEADER];
    if (typeof capability !== 'string') {
      sendUnavailable(response, config);
      return log(404);
    }

    const result = await broker.metadata(capability);
    if (!result.ok) {
      sendUnavailable(response, config);
      return log(404);
    }
    const { ok, ...metadata } = result;
    sendJson(response, 200, metadata, config);
    return log(200);
  }

  if (request.method === 'POST' && path === '/api/submit') {
    const capability = request.headers[CAPABILITY_HEADER];
    if (typeof capability !== 'string') {
      sendUnavailable(response, config);
      return log(404);
    }

    // Which lane this body is, declared before it is read. Only the two words the
    // broker speaks get past here: anything else — a third value, a repeated header
    // Node has joined with a comma, a non-string — is the uniform refusal, so the
    // broker is never handed a declaration it would have to interpret. Absence is
    // passed through as absence, which a universal drop reads as text for the
    // documented compatibility window.
    const declaration = request.headers[PAYLOAD_DECLARATION_HEADER];
    if (declaration !== undefined && !PAYLOAD_DECLARATIONS.includes(declaration)) {
      sendUnavailable(response, config);
      return log(404);
    }

    // Admission before buffering. The bound is the drop's own: a text submission
    // keeps `maxBodyBytes` and is not gated, while a declared file submission is
    // widened to what the drop's advertised limits can produce, admits one body at a
    // time, and reserves its file memory *here* — before the first byte. Asking the
    // broker first is what keeps a 42 MiB container from being cut off by a ceiling
    // sized for a 64 KiB secret — without raising that ceiling, or the number of
    // concurrent 56 MiB buffers, for anyone else.
    const slot = broker.acquireSubmitSlot(capability, { declaration });
    if (!slot.ok) {
      sendUnavailable(response, config);
      return log(404);
    }
    // Only an admitted file body earns the long deadline, and only after the
    // capability has authorized it: an unauthenticated caller cannot buy minutes.
    if (slot.widened) deadline.extend(config.fileSubmitTimeoutMs);

    try {
      // Only ciphertext ever reaches this buffer, and it is bounded before the read.
      let body = await readBody(request, slot.ceiling, config);
      let envelope = null;
      if (body !== null) {
        try {
          envelope = JSON.parse(body);
        } catch {
          envelope = null;
        }
      }
      // The parsed envelope is all the broker needs, and decrypting a maximal one
      // takes seconds. Letting the raw body go now means it is not still resident
      // alongside the ciphertext, the decoded ciphertext and the plaintext.
      body = null;

      const result = await broker.submit(capability, envelope, { declaration });
      if (!result.ok) {
        sendUnavailable(response, config);
        return log(404);
      }
      sendJson(response, 200, { status: 'received' }, config);
      return log(200);
    } finally {
      // However this ended — receipt, refusal, deadline, transport error or an
      // abort halfway through the body — the next attempt must be admissible, and
      // the file memory this request reserved must be back in the process budget
      // unless the submission won and took it over.
      slot.release();
    }
  }


  sendUnavailable(response, config);
  return log(404);
}

/**
 * Reads at most `limit` bytes. Past the limit nothing is buffered any more, but
 * the request is drained so the caller still receives the ordinary generic
 * unavailable response instead of a connection reset. A body absurdly past the
 * limit is cut off — that client gets a reset, which is the one case where the
 * uniform contract cannot be honoured.
 *
 * "Absurdly past" is `limit + bodyOverrunAllowanceBytes`, additive rather than a
 * multiple of the limit. It used to be `limit * 8`, which was about a megabyte of
 * politeness at the 128 KiB text ceiling and became a ~470 MB single-request drain
 * the moment a file drop widened the ceiling 448-fold.
 *
 * Settles on `close` as well as `end`, and that is load-bearing rather than
 * defensive: a client that abandons an upload mid-body emits neither `end` nor
 * necessarily `error`, and an unsettled read here would hold the caller's submit
 * slot — and with it the drop's only chance to be submitted to — for the rest of
 * its TTL.
 */
function readBody(request, limit, config) {
  const cutoff = limit + config.bodyOverrunAllowanceBytes;
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let oversize = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        oversize = true;
        chunks.length = 0;
        if (size > cutoff) {
          resolve(null);
          request.destroy();
        }
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (oversize) return resolve(null);
      const whole = Buffer.concat(chunks);
      // The pieces are dead the moment they are joined, and at the file ceiling
      // they are 56 MiB of them. Dropping the references here rather than when
      // `readBody` returns keeps one whole copy of a maximal body out of the peak.
      chunks.length = 0;
      resolve(whole.toString('utf8'));
    });
    request.on('error', () => resolve(null));
    request.on('close', () => resolve(null));
  });
}

function send(response, status, body, type, config, headOnly = false) {
  // A request whose deadline already expired has been answered. Writing again
  // would throw over the top of a response the client has, or is about to have.
  if (response.writableEnded) return;
  response.writeHead(status, {
    ...securityHeaders(config),
    'content-type': type,
    'content-length': body.length,
  });
  response.end(headOnly ? undefined : body);
}

function sendJson(response, status, payload, config) {
  send(response, status, Buffer.from(JSON.stringify(payload)), 'application/json; charset=utf-8', config);
}

export function sendUnavailable(response, config) {
  send(response, 404, Buffer.from(UNAVAILABLE_JSON), 'application/json; charset=utf-8', config);
}
