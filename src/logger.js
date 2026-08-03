// Deliberately dumb logger. It only ever receives strings that the caller has
// already vetted: non-secret handoff ids, states, byte counts, request paths.
// Capabilities, ciphertext and plaintext must never be passed in.

export function createLogger(stream = process.stderr) {
  const write = (level, message) => {
    stream.write(`${new Date().toISOString()} ${level} ${message}\n`);
  };
  return {
    info: (message) => write('info', message),
    warn: (message) => write('warn', message),
    error: (message) => write('error', message),
  };
}

export const silentLogger = { info() {}, warn() {}, error() {} };
