// Public browser-facing HTTP surface. Three things only: the page, its two
// self-hosted assets, and two capability-authorized POST endpoints.
//
// Nothing here reads the query string, and nothing logs anything but the method,
// the path and the status — the capability arrives in a header and the payload is
// ciphertext, so neither can reach the access log.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

/** The single generic unavailable body shared by every failure path. */
export const UNAVAILABLE_JSON = '{"status":"unavailable"}';

export const CAPABILITY_HEADER = 'x-handoff-capability';

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
    handle(request, response, { config, broker, logger, page, assets }).catch((error) => {
      logger.error?.(`request failed: ${error.message}`);
      if (!response.headersSent) sendUnavailable(response, config);
      else response.end();
    });
  });
  // Bound slow-loris style body dribbling on a prototype with no proxy in front.
  server.requestTimeout = 15_000;
  server.headersTimeout = 10_000;

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

async function handle(request, response, context) {
  const { config, broker, logger, page, assets } = context;
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

    // Only ciphertext ever reaches this buffer, and it is bounded before the read.
    const body = await readBody(request, config.maxBodyBytes);
    let envelope = null;
    if (body !== null) {
      try {
        envelope = JSON.parse(body);
      } catch {
        envelope = null;
      }
    }

    const result = await broker.submit(capability, envelope);
    if (!result.ok) {
      sendUnavailable(response, config);
      return log(404);
    }
    sendJson(response, 200, { status: 'received' }, config);
    return log(200);
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
 */
function readBody(request, limit) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    let oversize = false;
    request.on('data', (chunk) => {
      size += chunk.length;
      if (size > limit) {
        oversize = true;
        chunks.length = 0;
        if (size > limit * 8) {
          resolve(null);
          request.destroy();
        }
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => resolve(oversize ? null : Buffer.concat(chunks).toString('utf8')));
    request.on('error', () => resolve(null));
  });
}

function send(response, status, body, type, config, headOnly = false) {
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
