// A REAL broker for the Python tests. Not a stub of anything.
//
// Two modes, because two different things need proving:
//
//   default    `createBroker` + `startControlServer` on a caller-supplied temp
//              socket, with the public HTTP server left out — the control client
//              under test never speaks HTTP, and no port is opened.
//
//   --public   the whole `startHandoffBroker` entry point (src/main.js), so the
//              minted URL is real and a submission can actually be made through
//              the real browser-facing client. This is what lets a `DropWaiter`
//              park on a real AF_UNIX `await` and be woken by a real HPKE
//              submission rather than by a fake that was written to agree with
//              the design. The listener is loopback on an ephemeral port and
//              nothing outside this process ever dials it.
//
// Contract with the Python side:
//   argv[2]         absolute socket path to listen on
//   argv[3]         optional `--public`
//   stdout          `READY <socketPath>`, then `BASE_URL <url>` in --public mode
//   stdin           `SUBMIT <handoffUrl> <base64-of-utf8-plaintext>` (--public
//                   only) -> one line `SUBMITTED <status>` back on stdout
//                   `SUBMIT_FILES <handoffUrl> <name>:<base64> ...` (--public
//                   only) -> the same, for a `files` drop: it builds a real HDROP2
//                   container and seals it as envelope v2, so the Python receiver
//                   under test meets bytes the production encoder produced
//   SIGTERM/SIGINT  closes everything and exits 0
//
// The submit path deliberately goes through `sendSecret`, the same module the
// browser page runs (`src/client/handoff-client.js`), so the envelope, the
// capability header and the one-shot semantics are the production ones.
import { createInterface } from 'node:readline';

import { createBroker } from '../../../src/broker.js';
import { fetchMetadata, sealBytesEnvelope, sendSecret } from '../../../src/client/handoff-client.js';
import { loadConfig } from '../../../src/config.js';
import { startControlServer } from '../../../src/control-server.js';
import { FILE_ENVELOPE_VERSION, encodeFileContainer } from '../../../src/file-container.js';
import { startHandoffBroker } from '../../../src/main.js';

const socketPath = process.argv[2];
const wantsPublic = process.argv.includes('--public');
if (!socketPath) {
  process.stderr.write('usage: broker_harness.mjs <socket-path> [--public]\n');
  process.exit(2);
}

const quietLogger = { info() {}, warn() {}, error() {} };

let shutdownTargets;
let baseUrl = null;

if (wantsPublic) {
  const started = await startHandoffBroker({
    port: 0,
    host: '127.0.0.1',
    controlSocketPath: socketPath,
    // `null`, not `''`: `startHandoffBroker` picks the listener's real
    // ephemeral-port URL with `config.baseUrl ?? …` (src/main.js:16), and an
    // empty string is not nullish. Overrides beat env (src/config.js:59), so
    // this also pins the URL against an inherited HANDOFF_BASE_URL.
    baseUrl: null,
    logger: quietLogger,
  });
  baseUrl = started.baseUrl;
  shutdownTargets = { close: () => started.close() };
  process.stdout.write(`READY ${started.controlSocketPath}\n`);
  process.stdout.write(`BASE_URL ${started.baseUrl}\n`);
} else {
  const config = loadConfig({ controlSocketPath: socketPath }, {});
  const broker = createBroker(config, quietLogger);
  // `main.js` resolves baseUrl from the public listener's port after listen
  // (src/main.js:16-17); `broker.create` refuses until one is set
  // (src/broker.js:206). No public server runs here, so set the same shape
  // explicitly. Nothing dials it.
  broker.setBaseUrl('http://127.0.0.1:0');
  const control = await startControlServer({ socketPath, broker, logger: quietLogger });
  shutdownTargets = {
    close: async () => {
      broker.destroyAll?.();
      await control.close();
    },
  };
  process.stdout.write(`READY ${control.socketPath}\n`);
}

if (wantsPublic) {
  const capabilityOf = (url) => {
    const hashIndex = url.indexOf('#');
    return hashIndex < 0 ? null : url.slice(hashIndex + 1);
  };

  /**
   * One real HDROP2 container, sealed as envelope v2 and posted to the real submit
   * endpoint — the same path `test/helpers/harness.js` uses on the Node side. The
   * Python receiver under test therefore meets bytes the production encoder
   * produced rather than a fixture written to agree with it.
   */
  const submitFiles = async (url, specs, text) => {
    const capability = capabilityOf(url);
    const metadata = await fetchMetadata({ capability, origin: baseUrl });
    const files = specs.map((spec) => {
      const separator = spec.indexOf(':');
      return {
        name: Buffer.from(spec.slice(0, separator), 'base64').toString('utf8'),
        type: '',
        bytes: new Uint8Array(Buffer.from(spec.slice(separator + 1), 'base64')),
      };
    });
    const container = await encodeFileContainer(files, {
      limits: {
        maxFiles: metadata.max_files,
        maxFileBytes: metadata.max_file_bytes,
        maxTotalBytes: metadata.max_total_bytes,
      },
      ...(text === undefined ? {} : { text }),
    });
    const envelope = await sealBytesEnvelope({
      capability,
      metadata,
      bytes: container,
      version: FILE_ENVELOPE_VERSION,
    });
    const response = await fetch(`${baseUrl}/api/submit`, {
      method: 'POST',
      headers: {
        'x-handoff-capability': capability,
        'x-handoff-payload': 'files',
        'content-type': 'application/json',
      },
      body: JSON.stringify(envelope),
    });
    return response.ok ? 'received' : 'unavailable';
  };

  const lines = createInterface({ input: process.stdin });
  lines.on('line', async (line) => {
    const [command, url, ...rest] = line.trim().split(/\s+/);
    try {
      if (command === 'SUBMIT') {
        const plaintext = Buffer.from(rest[0], 'base64').toString('utf8');
        const outcome = await sendSecret({
          capability: capabilityOf(url),
          plaintext,
          origin: baseUrl,
        });
        process.stdout.write(`SUBMITTED ${outcome.status}\n`);
        return;
      }
      if (command === 'SUBMIT_FILES') {
        process.stdout.write(`SUBMITTED ${await submitFiles(url, rest)}\n`);
        return;
      }
      if (command === 'SUBMIT_COMBINED') {
        const text = Buffer.from(rest.shift(), 'base64').toString('utf8');
        process.stdout.write(`SUBMITTED ${await submitFiles(url, rest, text)}\n`);
        return;
      }
      process.stdout.write('SUBMIT_ERROR unknown-command\n');
    } catch (error) {
      process.stdout.write(`SUBMIT_ERROR ${error.message.replace(/\s+/g, '-')}\n`);
    }
  });
}

let closing = false;
const shutdown = async () => {
  if (closing) return;
  closing = true;
  await shutdownTargets.close();
  process.exit(0);
};
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
