// Operational safety of the container's command line.
//
// The live incident during this slice was a host-side `pkill -f "node
// src/main.js"` that matched the *containerised* broker, because the container
// and `npm start` produced byte-identical argv on the host process table.
// Nothing about the container was wrong; the command line was just
// indistinguishable. These tests keep it distinguishable.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { chmod, mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { controlRequest } from '../src/control-client.js';
import { prepareSocketDir, startControlServer } from '../src/control-server.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

const read = (name) => readFile(new URL(`../${name}`, import.meta.url), 'utf8');

/** A chmod that fails the way a foreign-owned bind mount fails. */
function refusingChmod(code = 'EPERM') {
  return async () => {
    const error = new Error(`chmod refused (${code})`);
    error.code = code;
    throw error;
  };
}

/** Enough broker for the control server to answer one request. */
const stubBroker = {
  async create() {
    return { ok: true, handoff_id: 'stub', url: 'http://stub.test/#x', expires_at: 0 };
  },
};

const quietLogger = { info() {}, warn() {}, error() {} };

/** The marker that makes the container's process unmistakable on `ps`. */
const CONTAINER_MARKER = '--role=handoff-broker-container';

describe('the container command line', () => {
  it('cannot be confused with a local `npm start` on the host process table', async () => {
    const dockerfile = await read('Dockerfile');
    const cmd = dockerfile.match(/^CMD (.+)$/m)[1];

    assert.ok(cmd.includes(CONTAINER_MARKER), 'the container argv carries its own marker');
    assert.ok(!/CMD \["node", ?"src\/main\.js"\]/.test(dockerfile), 'the colliding argv is gone');

    // `npm start` runs `node src/main.js` from the repo root. The two argv
    // strings must share no exact form, so no pattern that matches one can
    // silently match the other.
    const start = JSON.parse(await read('package.json')).scripts.start;
    assert.ok(start.includes('node src/main.js'));
    assert.ok(!start.includes(CONTAINER_MARKER), 'the local runner must not wear the marker');
    assert.ok(cmd.includes('/app/src/main.js'), 'and the container uses its absolute path');
  });

  it('still starts and serves, because the marker is inert argv', async () => {
    // The real entrypoint, launched the way the container launches it: extra
    // argument present, direct-run detection intact, page served.
    const socketPath = await mkdtemp(join(tmpdir(), 'hd-argv-')).then((dir) =>
      join(dir, 'c.sock'),
    );
    const child = spawn(process.execPath, ['src/main.js', CONTAINER_MARKER], {
      cwd: ROOT,
      env: {
        ...process.env,
        HANDOFF_PORT: '0',
        HANDOFF_HOST: '127.0.0.1',
        HANDOFF_CONTROL_SOCKET: socketPath,
        HANDOFF_BASE_URL: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    try {
      const baseUrl = await new Promise((resolve, reject) => {
        let log = '';
        const timer = setTimeout(() => reject(new Error(`no listen line: ${log}`)), 10_000);
        const onChunk = (chunk) => {
          log += chunk;
          const match = log.match(/listening on (http:\/\/\S+)/);
          if (!match) return;
          clearTimeout(timer);
          resolve(match[1]);
        };
        child.stdout.on('data', onChunk);
        child.stderr.on('data', onChunk);
        child.on('exit', (code) => reject(new Error(`exited ${code}: ${log}`)));
      });

      const response = await fetch(baseUrl);
      assert.equal(response.status, 200, 'the broker serves with the marker on its argv');
    } finally {
      // Kill this exact PID — the discipline the README documents.
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
      await rm(dirname(socketPath), { recursive: true, force: true });
    }
  });

  it('warns operators away from the pattern kill that caused the incident', async () => {
    const readme = await read('README.md');
    assert.match(readme, /pkill/, 'the hazard is named');
    assert.match(readme, /\bPID\b/, 'and the safe alternative is given');
  });
});

// The control socket moves from a container-private tmpfs to a host bind mount,
// so the gateway can reach it without `docker compose exec`. This does *not*
// narrow the trust boundary — the host operator already reached `claim` through docker — it removes
// plaintext from process argv, from `docker` logs, and from the terminal tool's
// truncation path. What it costs is a new failure mode: Docker creates a missing
// bind-mount source as `root:root`, the container runs as uid 1000, and the
// unconditional `chmod` at startup then throws inside a `restart: unless-stopped`
// container — a crash loop. These tests pin both halves of the fix.
describe('the host socket mount contract', () => {
  it('no longer hides the socket in a container-private tmpfs', async () => {
    const compose = await read('compose.yml');
    const tmpfsEntries = [...compose.matchAll(/^\s*- (\/\S+?)(?::|\s*$)/gm)]
      .map((match) => match[1])
      .filter((path) => path.startsWith('/'));

    assert.ok(
      !tmpfsEntries.includes('/run/handoff'),
      'the /run/handoff tmpfs entry is gone: a tmpfs is invisible to the host gateway',
    );
    assert.match(compose, /^\s*- \/tmp:mode=1777\s*$/m, 'but /tmp is still a tmpfs');
    assert.match(compose, /^\s*read_only: true\s*$/m, 'and the root filesystem stays read-only');
  });

  it('bind-mounts the configured host directory at the same in-container path', async () => {
    const compose = await read('compose.yml');
    const mount = compose.match(/^\s*- \$\{HANDOFF_SOCKET_DIR[^}]*\}:(\S+)\s*$/m);

    assert.ok(mount, 'the host socket directory is bind-mounted, and its path is configurable');
    assert.equal(
      mount[1],
      '/run/handoff',
      'at the path HANDOFF_CONTROL_SOCKET already points into, so nothing else changes',
    );
    assert.match(
      await read('Dockerfile'),
      /HANDOFF_CONTROL_SOCKET=\/run\/handoff\/control\.sock/,
      'which is exactly where the image expects the socket',
    );
  });

  it('declares the uid it runs as, instead of assuming it', async () => {
    const compose = await read('compose.yml');
    const user = compose.match(/^\s*user: "(\d+):(\d+)"\s*$/m);

    assert.ok(user, 'the container uid/gid is pinned in compose, not inferred from the image');
    assert.equal(user[1], '1000', 'the host operator uid — reachability depends on the match');
    assert.equal(user[2], '1000');

    // And the preflight that validates the host directory expects the same ids,
    // so the two halves of the contract cannot drift apart.
    const installer = await read('bin/install-hermes-drop.sh');
    assert.match(installer, /HANDOFF_SOCKET_UID:?[-=]"?1000/, 'preflight defaults to the same uid');
    assert.match(installer, /HANDOFF_SOCKET_GID:?[-=]"?1000/, 'and the same gid');
  });
});

describe('the control socket directory', () => {
  let dirs = [];

  const tempDir = async (mode) => {
    const dir = await mkdtemp(join(tmpdir(), 'hd-sockdir-'));
    dirs.push(dir);
    if (mode !== undefined) await chmod(dir, mode);
    return dir;
  };

  const cleanup = async () => {
    for (const dir of dirs) await rm(dir, { recursive: true, force: true });
    dirs = [];
  };

  it('is tightened to 0700 when the broker owns it, exactly as before', async () => {
    const parent = await tempDir();
    const socketDir = join(parent, 'nested');
    try {
      await prepareSocketDir(socketDir);
      assert.equal((await stat(socketDir)).mode & 0o777, 0o700);
    } finally {
      await cleanup();
    }
  });

  it('tolerates a chmod it is not allowed to make when the mode and owner are already right', async () => {
    // A host bind mount belongs to the host operator. `chmod` from inside the
    // container fails even though the directory is already exactly what the
    // broker would have made it.
    const socketDir = await tempDir(0o700);
    try {
      const result = await prepareSocketDir(socketDir, { chmod: refusingChmod() });
      assert.equal(result.mode, 0o700, 'the directory is accepted as already correct');
      assert.equal(result.chmodded, false, 'and the broker knows it did not set it');
    } finally {
      await cleanup();
    }
  });

  it('refuses to serve out of a directory that is actually too open', async () => {
    const socketDir = await tempDir(0o755);
    try {
      await assert.rejects(
        () => prepareSocketDir(socketDir, { chmod: refusingChmod() }),
        (error) => {
          assert.match(error.message, /0755/, 'the real mode is named');
          assert.match(error.message, new RegExp(socketDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
          assert.match(error.message, /install -d -m 700/, 'and the fix is spelled out');
          return true;
        },
      );
    } finally {
      await cleanup();
    }
  });

  it('refuses a directory owned by somebody else', async () => {
    const socketDir = await tempDir(0o700);
    const foreignStat = async (path) => {
      const info = await stat(path);
      return { ...info, mode: info.mode, uid: info.uid + 1, gid: info.gid };
    };
    try {
      await assert.rejects(
        () => prepareSocketDir(socketDir, { chmod: refusingChmod(), stat: foreignStat }),
        /uid/,
      );
    } finally {
      await cleanup();
    }
  });

  it('lets the broker start and serve when the chmod is refused but the directory is correct', async () => {
    // The crash-loop regression, end to end: `restart: unless-stopped` plus a
    // throwing startup is an unbounded restart loop, so this must be a start.
    const socketDir = await tempDir(0o700);
    const socketPath = join(socketDir, 'control.sock');
    let control;
    try {
      control = await startControlServer({
        socketPath,
        broker: stubBroker,
        logger: quietLogger,
        dirOps: { chmod: refusingChmod() },
      });
      const response = await controlRequest(socketPath, { op: 'create' });
      assert.equal(response.ok, true, 'the broker is serving on the mounted directory');
      assert.equal((await stat(socketPath)).mode & 0o777, 0o600, 'and the socket is still 0600');
    } finally {
      await control?.close();
      await cleanup();
    }
  });
});
