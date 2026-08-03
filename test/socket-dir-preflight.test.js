// `bin/install-hermes-drop.sh --preflight` — the host half of the socket mount
// contract for the host control-socket directory.
//
// The container declares `user: "1000:1000"` and bind-mounts a host directory at
// /run/handoff. Reachability therefore depends on a host directory that exists,
// is mode 0700, and is owned by that uid. Docker will happily create a missing
// bind-mount source as `root:root`, which is precisely the state that breaks the
// broker — so this refuses *before* anything is deployed, and it refuses with the
// command that fixes it.
//
// Preflight is read-only by contract: it validates, it never creates or chmods.
// Creating the directory is an operator action at S11/M3, not a side effect of a
// check. Every test below runs against a temp directory; nothing here touches a
// real deployment path or any Hermes profile.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const SCRIPT = fileURLToPath(new URL('../bin/install-hermes-drop.sh', import.meta.url));

const created = [];

async function tempDir(mode) {
  const dir = await mkdtemp(join(tmpdir(), 'hd-preflight-'));
  created.push(dir);
  if (mode !== undefined) await chmod(dir, mode);
  return dir;
}

function run(args, env = {}) {
  return new Promise((resolve) => {
    execFile(
      'bash',
      [SCRIPT, ...args],
      { encoding: 'utf8', env: { ...process.env, ...env } },
      (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
    );
  });
}

/** The uid/gid this test process can actually own a directory as. */
const asMe = { HANDOFF_SOCKET_UID: String(process.getuid()), HANDOFF_SOCKET_GID: String(process.getgid()) };

describe('the host socket directory preflight', () => {
  after(async () => {
    for (const dir of created) await rm(dir, { recursive: true, force: true });
  });

  it('accepts a directory that is mode 0700 and owned by the container uid', async () => {
    const dir = await tempDir(0o700);
    const result = await run(['--preflight'], { ...asMe, HANDOFF_SOCKET_DIR: dir });

    assert.equal(result.code, 0, result.stderr);
    assert.match(result.stdout, /\bok\b/i);
    assert.ok(result.stdout.includes(dir), 'the directory it checked is named');
  });

  it('refuses a directory that is too open, naming the command that fixes it', async () => {
    const dir = await tempDir(0o755);
    const result = await run(['--preflight'], { ...asMe, HANDOFF_SOCKET_DIR: dir });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /0755/, 'the mode it found');
    assert.match(result.stderr, /install -d -m 700/, 'and the actionable fix');
    assert.ok(result.stderr.includes(dir));
    assert.equal((await stat(dir)).mode & 0o777, 0o755, 'and it changed nothing');
  });

  it('refuses a directory owned by another uid', async () => {
    const dir = await tempDir(0o700);
    const result = await run(['--preflight'], {
      HANDOFF_SOCKET_DIR: dir,
      HANDOFF_SOCKET_UID: String(process.getuid() + 1),
      HANDOFF_SOCKET_GID: String(process.getgid()),
    });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /uid/i);
    assert.match(result.stderr, /install -d -m 700/);
  });

  it('refuses a missing directory instead of creating it', async () => {
    const parent = await tempDir();
    const dir = join(parent, 'not-there');
    const result = await run(['--preflight'], { ...asMe, HANDOFF_SOCKET_DIR: dir });

    assert.notEqual(result.code, 0);
    assert.ok(result.stderr.includes(dir));
    assert.match(result.stderr, /install -d -m 700/);
    assert.deepEqual(await readdir(parent), [], 'preflight creates nothing — that is an operator step');
  });

  it('refuses a path that is not a directory', async () => {
    const parent = await tempDir();
    const file = join(parent, 'control.sock');
    await writeFile(file, '');
    const result = await run(['--preflight'], { ...asMe, HANDOFF_SOCKET_DIR: file });

    assert.notEqual(result.code, 0);
    assert.match(result.stderr, /not a directory/i);
  });

  it('exits 2 on usage when the directory is not configured at all', async () => {
    const result = await run(['--preflight'], { HANDOFF_SOCKET_DIR: '' });

    assert.equal(result.code, 2);
    assert.match(result.stderr, /HANDOFF_SOCKET_DIR/);
  });

  it('exits 2 on usage with no arguments, and says what it does support', async () => {
    const result = await run([]);

    assert.equal(result.code, 2);
    assert.match(result.stderr, /--preflight/);
  });

  it('advertises the plugin installer subcommands S3 added', async () => {
    // Superseded assertion. Until S3 these three exited 2 saying "not
    // implemented yet", because succeeding quietly would have left an operator
    // believing a plugin was installed. They exist now — their behaviour is
    // covered against a temp profile by
    // integrations/hermes-drop/tests/test_installer.py — so what this suite
    // keeps is the usage contract visible from the Node side.
    const result = await run([]);
    assert.equal(result.code, 2);
    for (const token of ['install', '--copy', '--uninstall', '--preflight']) {
      assert.ok(result.stderr.includes(token), `usage omits ${token}`);
    }
  });

  it('never guesses a Hermes profile to install into', async () => {
    // The one safety property of the installer that belongs in this suite: with
    // no HERMES_HOME it must refuse rather than fall back to ~/.hermes. A
    // profile-scoped installer that defaults to the live default profile is one
    // mistyped command away from installing into it.
    for (const args of [['install'], ['--copy'], ['--uninstall']]) {
      const env = { ...process.env, ...asMe, HANDOFF_SOCKET_DIR: tmpdir() };
      delete env.HERMES_HOME;
      const result = await new Promise((resolve) => {
        execFile(
          'bash',
          [SCRIPT, ...args],
          { encoding: 'utf8', env },
          (error, stdout, stderr) => resolve({ code: error?.code ?? 0, stdout, stderr }),
        );
      });

      assert.notEqual(result.code, 0, args.join(' '));
      assert.match(result.stderr, /HERMES_HOME/, args.join(' '));
    }
  });
});
