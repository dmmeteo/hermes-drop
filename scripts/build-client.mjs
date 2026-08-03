#!/usr/bin/env node
// Bundles the browser page's module graph — including the pinned @hpke/core — into
// one self-hosted file, so the page needs no import map, no CDN and no
// 'unsafe-inline' in its CSP. Left unminified on purpose: the whole point of
// self-hosting every byte is that the shipped encryption code is inspectable.
import { mkdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

import { build } from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));
const outDir = `${root}src/public/assets`;
const outFile = `${outDir}/app.js`;

await mkdir(outDir, { recursive: true });

const result = await build({
  entryPoints: [`${root}src/client/app.js`],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: false,
  sourcemap: false,
  legalComments: 'inline',
  outfile: outFile,
  metafile: true,
});

const bytes = Object.values(result.metafile.outputs)[0].bytes;
process.stderr.write(`built ${outFile.replace(root, '')} (${bytes} bytes)\n`);
