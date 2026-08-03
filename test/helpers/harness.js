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

/** Splits a handoff URL into its request target and its `#fragment` capability. */
export function splitHandoffUrl(url) {
  const hashIndex = url.indexOf('#');
  if (hashIndex < 0) return { target: url, capability: null };
  return {
    target: url.slice(0, hashIndex),
    capability: url.slice(hashIndex + 1),
  };
}
