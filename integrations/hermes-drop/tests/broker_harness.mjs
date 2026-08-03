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
//   SIGTERM/SIGINT  closes everything and exits 0
//
// The submit path deliberately goes through `sendSecret`, the same module the
// browser page runs (`src/client/handoff-client.js`), so the envelope, the
// capability header and the one-shot semantics are the production ones.
import { createInterface } from 'node:readline';

import { createBroker } from '../../../src/broker.js';
import { sendSecret } from '../../../src/client/handoff-client.js';
import { loadConfig } from '../../../src/config.js';
import { startControlServer } from '../../../src/control-server.js';
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
  const lines = createInterface({ input: process.stdin });
  lines.on('line', async (line) => {
    const [command, url, encoded] = line.trim().split(/\s+/);
    if (command !== 'SUBMIT') {
      process.stdout.write('SUBMIT_ERROR unknown-command\n');
      return;
    }
    try {
      const hashIndex = url.indexOf('#');
      const capability = hashIndex < 0 ? null : url.slice(hashIndex + 1);
      const plaintext = Buffer.from(encoded, 'base64').toString('utf8');
      const outcome = await sendSecret({ capability, plaintext, origin: baseUrl });
      process.stdout.write(`SUBMITTED ${outcome.status}\n`);
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
