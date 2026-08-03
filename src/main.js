// Process entrypoint and test harness entrypoint: one broker, one public HTTP
// server, one local control socket, all in a single Node process.
import { loadConfig } from './config.js';
import { createBroker } from './broker.js';
import { startControlServer } from './control-server.js';
import { startPublicServer } from './public-server.js';
import { createLogger } from './logger.js';

export async function startHandoffBroker(overrides = {}) {
  const { logger: loggerOverride, ...configOverrides } = overrides;
  const config = loadConfig(configOverrides);
  const logger = loggerOverride ?? createLogger();

  const broker = createBroker(config, logger);
  const publicServer = await startPublicServer({ config, broker, logger });
  const baseUrl = config.baseUrl ?? `http://127.0.0.1:${publicServer.port}`;
  broker.setBaseUrl(baseUrl);

  const controlServer = await startControlServer({
    socketPath: config.controlSocketPath,
    broker,
    logger,
  });

  const sweeper = setInterval(() => broker.sweep(), config.sweepIntervalMs);
  sweeper.unref();

  logger.info?.(`handoff broker listening on ${baseUrl}`);

  return {
    config,
    broker,
    baseUrl,
    port: publicServer.port,
    controlSocketPath: controlServer.socketPath,
    testSnapshot: (handoffId) => broker.testSnapshot(handoffId),
    async close() {
      clearInterval(sweeper);
      // Destroy first. That releases every blocked `await` subscription with a
      // definitive `unavailable` — which is the truth, since shutdown destroys
      // the handoffs — and leaves the control server nothing long-lived to wait
      // for. Closing first made shutdown block until the last subscriber's
      // handoff expired, up to a full TTL.
      broker.destroyAll();
      await controlServer.close();
      await publicServer.close();
    },
  };
}

const isDirectRun =
  process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isDirectRun) {
  const instance = await startHandoffBroker();
  // Shutdown destroys every pending handoff: the keys were never persisted, so
  // failing closed is the intended behaviour.
  const shutdown = async (signal) => {
    await instance.close();
    process.exit(signal === 'SIGINT' ? 130 : 0);
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}
