# Encrypted file drops — MVP design

Status: **proposed implementation baseline**

## Goal

Allow the current conversation to request one short-lived, origin-bound drop that can contain **one or several small files**. File bytes and filenames must never appear in chat or in Hermes durable conversation state.

This extends the existing Hermes Drop lifecycle; it does not create a generic file host or outbound file-sharing service.

## MVP limits

- Up to **5 files** per drop.
- Up to **42 MiB total plaintext** per drop.
- Up to **42 MiB per file** (the total cap remains authoritative).
- Empty files are allowed; empty submissions are not.
- Existing TTL rules remain unchanged (30 minutes by default, 60 maximum).
- One encrypted submission, one local claim, then destruction under the existing lifecycle.
- No folders, directory trees, resumable/chunked upload, preview, antivirus guarantee, or 5 GiB-class transfer.

Limits must be broker-advertised metadata and server-enforced, not trusted from the browser. Operators may lower them and may not raise them: the manifest ceiling, the browser's advertised limits and the broker's live-memory budget are all derived from the defaults above, so a higher cap is a change to those defaults, reviewed with them, not a deployment setting.

## Why the current text path is insufficient

The cryptographic primitive already accepts bytes, but the product and transport assume UTF-8 text:

1. The page exposes only a `textarea` and calls `utf8(plaintext)` before HPKE sealing.
2. The broker stores one undifferentiated `plaintext` byte array with no payload kind or file manifest.
3. The control protocol returns the claim as base64 inside one JSON line.
4. The plugin decodes the claim into text and injects it into model context through the secret placeholder vault.
5. The current 64 KiB broker cap and 1 MiB control response ceiling are intentionally sized for secrets, not files.
6. Filenames, MIME hints, per-file sizes, and integrity metadata do not exist.

The key architectural issue is therefore **not encryption**. It is keeping binary data out of model context and delivering it to a safe local file boundary.

## Product/API shape

### Request

Add a separate model tool rather than overloading `request_private_input`:

- `request_private_files({ purpose?, minutes?, max_files? })`
- No destination fields, preserving the origin-bound schema invariant.
- `max_files` may only narrow the broker/operator limit; it cannot raise it.

Add `/drop-file` as the deterministic command equivalent. The existing `/drop` remains text-only and backward compatible.

### Browser

The metadata response gains a non-secret request mode and limits:

```json
{
  "payload_kind": "files",
  "max_files": 5,
  "max_total_bytes": 44040192,
  "max_file_bytes": 44040192
}
```

For file drops, the page renders:

- a native multi-file picker (`accept` unrestricted);
- drag/drop as progressive enhancement;
- selected filename, byte size, remove action, total size;
- explicit limit errors before encryption;
- the existing one-shot Send/retry behavior.

Do not put filenames in status messages, URLs, logs, or unencrypted metadata.

### Encrypted payload

Introduce envelope version 2 with an encrypted binary container:

```text
magic: "HDROP2" (6 bytes)
manifest_length: uint32 big-endian, at most 6437 (see below)
manifest: UTF-8 JSON, strict — no BOM, no trailing bytes
file bytes: concatenated in manifest order
```

`manifest_length` is checked against a fixed ceiling *before* any manifest byte
is read. The ceiling is derived from the file count rather than chosen: worst
case per entry is a 255-byte name and a 255-byte type, each doubled because JSON
escapes quotes, plus a 64-character digest, two 16-digit integers and the keys —
1280 bytes, so five files fit in 6437. Raising `max_files` therefore has to raise
this ceiling in the same change, or maximal drops fail late and only for users
whose filenames happen to be long. Transports (the control protocol's framing,
the browser's assembly buffer) size themselves from
`10 + manifest_ceiling + max_total_bytes`.

Encrypted manifest shape:

```json
{
  "kind": "files",
  "files": [
    {
      "name": "config.json",
      "size": 1234,
      "offset": 0,
      "sha256": "<64 lowercase hex>",
      "type": "application/json"
    }
  ]
}
```

Rules:

- `name` is the browser-provided basename only; directory components are stripped,
  and it is capped at 255 UTF-8 bytes.
- `name` must already be canonical: the decoder re-runs sanitization and refuses
  any name it would have changed, so the label that is displayed and the bytes
  that were hashed can never disagree. Sanitization is therefore a fixed point.
- `type` is an untrusted display hint and may be empty. It is printable ASCII,
  capped at 255 bytes; anything else becomes empty rather than being repaired.
- `sha256` is exactly 64 lowercase hex characters — one spelling, no other.
- offsets must be contiguous, ordered, non-overlapping, and exactly consume the payload.
- SHA-256 is verified after decryption before a claim can succeed.
- Unknown keys, at either level of the manifest, are a refusal rather than
  something to ignore.
- The whole container is sealed once with the existing HPKE suite and handoff binding.
- The broker validates the container after AEAD success and before transitioning to `submitted`.

Envelope v2 is a **required integration**, not something the container delivers
on its own: `buildInfo` must carry the version on both sides and the broker's
`envelope.v` equality check must widen to an allowlist. Until that lands, the
codec's `FILE_ENVELOPE_VERSION` is a declared constant with nothing bound to it.

A custom minimal container is preferred over ZIP in the MVP: no archive parser/decompression attack surface, no compression bombs, deterministic validation, and no new browser dependency. ZIP can be an export convenience later, not the security boundary.

## Broker model

A handoff record gains `payloadKind` (`text` or `files`) and kind-specific limits. Text defaults remain unchanged.

For file payloads, the broker holds the decrypted validated container in memory until claim or expiry. The 42 MiB default is intentionally bounded; additionally add:

- `HANDOFF_MAX_FILES` (default 5);
- `HANDOFF_MAX_FILE_BYTES` (default 42 MiB);
- `HANDOFF_MAX_FILE_TOTAL_BYTES` (default 42 MiB);
- `HANDOFF_MAX_LIVE_FILE_BYTES` (default 168 MiB process-wide, enough for four fully reserved file drops).

Creation must refuse a new file drop when reserving its advertised maximum would exceed the process-wide live-file budget. This prevents many pending/submitted drops from turning the broker into an unbounded memory sink.

Do not silently reuse `HANDOFF_MAX_PLAINTEXT_BYTES`: keeping text and file caps separate avoids accidentally raising secret/tool-result limits to multi-megabyte values.

## Local claim and safe attachment boundary

Do **not** return file bytes from `claim_private_input`, and do not place them in the placeholder vault or model request.

Add `claim_private_files({ drop_id })`. On success the plugin must:

1. claim over a file-capable control operation;
2. write each file into a newly created private directory (`0700`) under a configured spool root;
3. create files with `0600`, using generated storage names rather than trusting submitted paths;
4. verify size and SHA-256 while writing;
5. atomically publish the completed directory only after every file verifies;
6. return a small durable-safe tool result containing generated local paths, original display names, sizes, and hashes — never file contents;
7. schedule spool deletion (default 15 minutes), with explicit cleanup on gateway startup.

Suggested result:

```json
{
  "drop_id": "…",
  "files": [
    {
      "path": "/run/hermes-drop/claims/<claim-id>/0001",
      "name": "config.json",
      "size": 1234,
      "sha256": "…"
    }
  ],
  "expires_at": 0
}
```

The generated local path is the agent attachment boundary: Hermes tools can read or attach the file without binary bytes entering the transcript. Original names are labels only and are never joined into filesystem paths.

The control protocol should stream or length-frame file claims to a private Unix-socket client; it must not base64 a 42 MiB payload into one newline-delimited JSON response. Metadata may remain JSON, followed by exact-length binary frames. A failed/truncated transfer must leave the broker payload claimable until the client acknowledges a fully verified receive; this requires a two-phase `begin_file_claim` → transfer → `commit_file_claim` contract (or equivalent single connection with final ACK).

## Lifecycle changes

The existing state machine stays conceptually intact, but file claim needs an explicit lossless transfer substate:

```text
submitted -> transferring -> claimed
                 |
                 +-- disconnect / verify failure --> submitted
```

- Only one transfer lease may exist at a time.
- A bounded lease timeout returns `transferring` to `submitted`.
- `commit` is accepted only on the same authenticated local connection/lease after all advertised bytes were sent.
- Broker retirement happens only after commit.
- Identical browser-envelope retries retain current idempotent receipt behavior.
- Broker restart still destroys all in-memory drops and plugin reconciliation marks them expired.

## Filename and content safety

- Normalize browser names to Unicode NFC for display.
- Strip `/`, `\\`, NUL, control characters, leading/trailing whitespace, and Windows drive prefixes.
- Replace an empty result with `unnamed`.
- Cap display names at 255 UTF-8 bytes.
- Duplicate names are allowed because storage names are generated.
- Never execute, import, render, or auto-open a claimed file.
- MIME is not trusted; consumers should sniff only when needed.
- No server-side decompression in MVP.

## Compatibility

- Existing text drops and envelope v1 remain unchanged.
- Broker and plugin advertise protocol capabilities; a plugin must refuse file creation before posting a link if the broker lacks file-drop support.
- Public endpoints keep uniform `unavailable` behavior for malformed, expired, consumed, or wrong-capability submissions.
- File-specific size/count errors shown before submission come only from already-authorized metadata and local browser checks; post-submit failures stay generic publicly.

## Implementation slices

1. **Contract and binary container** — v2 codec, manifest/path validation, test vectors, malformed-container tests. *Delivered as `src/file-container.js`: encode/decode, sanitization, limits and ceilings only. It is imported by nothing yet, and the decoded file views alias the container buffer, so whoever holds them owns zeroization and must re-verify digests before writing bytes out.*
2. **Broker file mode** — create metadata, limits, live-memory reservation, file envelope acceptance, lifecycle tests. *Includes the envelope-v2 binding above: `buildInfo` version threading on both sides and the broker's `envelope.v` allowlist.*
3. **Lossless local transfer protocol** — framed streaming, transfer lease/ACK, disconnect and size-boundary tests. *Delivered as `begin_file_claim` → (frame → `ack_frame`)* per file *→ `commit_file_claim` on one connection (`src/control-server.js`), the lease and the `transferring` substate in `src/broker.js`, and receivers in both languages (`src/file-claim-client.js`, `integrations/hermes-drop/drop/file_claim.py`). Additive to protocol v2, advertised as `file_claim_protocol` on `create`. Six things the next slice inherits:*
   - *the connection **is** the lease — there is no token to present, and a commit is only ever accepted from the connection that streamed;*
   - *frames go out **one at a time**, each acked by the receiver with the digest it computed, and the broker checks that ack before writing the next. This is what makes "the receiver has the bytes" independent of the socket send buffer: an earlier revision totalled write completions and so accepted an early commit below ~208 KiB and refused it above;*
   - *the broker does **not** send per-file digests. The receiver computes them over received bytes, so the broker's `ok` on commit is the verification verdict, and a spool must publish on that rather than on a self-check;*
   - *a commit written with no answer read is `transfer_indeterminate`, not a failure. Publish nothing, retry nothing, mark nothing spent (`contract/control-protocol.json` → `file_claim.client_verdicts`);*
   - *the Python receiver streams **per chunk** (`ChunkSink`), which is the only shape that can write 42 MiB to a spool without a second copy — and the shape whose per-file predecessor silently delivered zero bytes while its digests still verified;*
   - *the frames are views into the broker's container, so the receiver owns every byte it retains, and `destroy()`'s release-before-zeroize ordering is load-bearing.*
4. **Plugin spool boundary** — private atomic writes, hash verification, cleanup/recovery, durable-safe tool result.
5. **Tools and origin binding** — request/claim schemas and `/drop-file`, with the existing forbidden-destination tests extended.
6. **Browser UX** — picker, multi-file list, limits, container assembly, exact-envelope retry.
7. **End-to-end/security pass** — browser → broker → plugin spool, restart/expiry/race tests, README/SECURITY/deployment docs.

## Acceptance criteria

- One to five files totaling at most 42 MiB can be selected, encrypted in-browser, submitted, claimed once, and materialized under a private spool directory.
- A second claim cannot recover bytes.
- Binary contents never enter chat messages, Hermes `state.db`, FTS, JSON session logs, or model-provider payloads.
- Filenames never control filesystem paths and never appear in broker logs or public status messages.
- Wrong capability, malformed container, hash mismatch, over-limit input, duplicate submission, transfer disconnect, lease timeout, expiry, and broker restart are covered by tests.
- Existing text-drop tests and behavior remain green without configuration changes.

## Deliberately deferred

- Files larger than 42 MiB, resumable/chunked browser uploads, object storage, multi-recipient links, folders, compression, previews, malware scanning, outbound sharing, and permanent file storage.
