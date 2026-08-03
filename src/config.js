// Deployment configuration. Everything security-relevant is server-side and
// never client-supplied.

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
});

const NUMERIC = new Set([
  'port',
  'ttlSeconds',
  'maxTtlSeconds',
  'maxPlaintextBytes',
  'maxBodyBytes',
  'maxAeadFailures',
  'sweepIntervalMs',
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
};

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
  if (config.baseUrl) config.baseUrl = config.baseUrl.replace(/\/+$/, '');

  return Object.freeze(config);
}
