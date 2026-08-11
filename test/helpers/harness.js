// Test harness: boots a real broker (public HTTP server on an ephemeral port +
// local control socket in a temp dir) and tears it down.
//
// No test in this suite may print, assert on, or persist plaintext beyond the
// single equality check that a claim returned what was submitted.
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { startHandoffBroker } from '../../src/main.js';
import { controlRequest } from '../../src/control-client.js';
import { fetchMetadata, sealBytesEnvelope } from '../../src/client/handoff-client.js';
import { receiveFileClaim } from '../../src/file-claim-client.js';
import { FILE_ENVELOPE_VERSION, encodeFileContainer } from '../../src/file-container.js';

export async function startTestBroker(overrides = {}) {
  const dir = await mkdtemp(join(tmpdir(), 'handoff-test-'));
  const controlSocketPath = join(dir, 'control.sock');
  const broker = await startHandoffBroker({
    port: 0,
    controlSocketPath,
    logger: { info() {}, warn() {}, error() {} },
    ...overrides,
  });

  return {
    ...broker,
    control: (request) => controlRequest(controlSocketPath, request),
    async stop() {
      await broker.close();
      await rm(dir, { recursive: true, force: true });
    },
  };
}

export function decodeBase64Url(value) {
  return Buffer.from(value, 'base64url');
}

/**
 * Mints one file-kind drop and hands back everything a test needs to submit to
 * it: its id, its capability, the metadata the page would have fetched, and a
 * sealer that turns `[{ name, type, bytes }]` into a real envelope v2.
 *
 * Everything goes through the production paths — the control socket for `create`,
 * the public metadata endpoint, the codec in `src/file-container.js` and the same
 * client sealer the browser bundle ships — so nothing here agrees with the broker
 * by construction.
 */
export async function createFileDrop(broker, { ttlSeconds = 120, maxFiles } = {}) {
  const request = { op: 'create', payload_kind: 'files', ttl_seconds: ttlSeconds };
  if (maxFiles !== undefined) request.max_files = maxFiles;
  const created = await broker.control(request);
  if (!created.ok) return { created, capability: null, metadata: null };

  const capability = splitHandoffUrl(created.url).capability;
  const metadata = await fetchMetadata({ capability, origin: broker.baseUrl });
  return {
    created,
    id: created.handoff_id,
    capability,
    metadata,
    expiresAt: created.expires_at,
    seal: (files) => sealFileEnvelope({ capability, metadata, files }),
    send: async (envelope) => {
      const response = await fetch(`${broker.baseUrl}/api/submit`, {
        method: 'POST',
        headers: {
          'x-handoff-capability': capability,
          'content-type': 'application/json',
        },
        body: JSON.stringify(envelope),
      });
      return response.ok ? 'received' : 'unavailable';
    },
  };
}

/**
 * Claims a file drop the way the plugin will: `begin_file_claim` over the real
 * control socket, the real length-framed stream, and a commit carrying digests
 * the receiver computed itself (src/file-claim-client.js).
 *
 * This is the only way to retire a file payload. There is deliberately no shortcut
 * that skips the transfer — a test that could retire a container without moving it
 * would be pinning a claim path production does not have.
 */
export function claimFileDrop(broker, handoffId, options) {
  return receiveFileClaim(broker.controlSocketPath, handoffId, options);
}

/** One HDROP2 container, sealed under the metadata's own advertised limits. */
export async function sealFileEnvelope({ capability, metadata, files }) {
  const container = await encodeFileContainer(files, {
    limits: {
      maxFiles: metadata.max_files,
      maxFileBytes: metadata.max_file_bytes,
      maxTotalBytes: metadata.max_total_bytes,
    },
  });
  return sealBytesEnvelope({
    capability,
    metadata,
    bytes: container,
    version: FILE_ENVELOPE_VERSION,
  });
}

/** Splits a handoff URL into its request target and its `#fragment` capability. */
export function splitHandoffUrl(url) {
  const hashIndex = url.indexOf('#');
  if (hashIndex < 0) return { target: url, capability: null };
  return {
    target: url.slice(0, hashIndex),
    capability: url.slice(hashIndex + 1),
  };
}
