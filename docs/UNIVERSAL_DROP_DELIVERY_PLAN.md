# Universal text-or-files drop — delivery package

Status: **approved product direction; implementation plan**

## Product decision

Hermes Drop has one user-facing request flow, one link, and one browser form.

The sender chooses **at send time** between:

- plaintext text; or
- one to five files totaling at most 42 MiB.

There is no `/drop-file`, no file-only link, and no separate file-request tool in the primary UX. The internal payload types remain explicit because their envelopes, limits, broker storage, and local claim boundaries differ.

## User-facing contract

### Hermes

Existing interfaces become universal rather than adding parallel file variants:

- `request_private_input` creates a universal drop.
- `/drop` creates the same universal drop.
- The waiting notice and origin-bound routing stay unchanged.
- After submission, Hermes dispatches internally by the submitted payload kind:
  - text → existing private-text claim/vault path;
  - files → file claim protocol → private spool paths.

The model must not choose or predict the payload kind when requesting the drop. The sender decides in the browser.

### Browser

One form contains:

- the existing textarea;
- an **Add files** picker with multi-select;
- drag/drop as progressive enhancement;
- selected-file rows with label, size, remove action, and total size;
- one Send button.

Form rules:

1. Text and files are mutually exclusive in the MVP.
2. Typing text disables file selection only after a clear inline explanation; selecting files disables the textarea without deleting its draft. Switching mode requires an explicit action and preserves the other draft locally until send/expiry.
3. Empty submission is refused.
4. File constraints are checked before hashing/encryption: max 5 files, max 42 MiB per file, max 42 MiB total.
5. The receipt remains payload-neutral; filenames never appear in URLs, public status, notices, or logs.
6. Retry reuses the exact already-sealed envelope and payload-kind declaration. It never re-reads files or reseals.

## Wire contract

The public endpoint remains `POST /api/submit` for both modes.

Binary files are **not base64 encoded**. Base64 would add about one third to the body size and create avoidable large JS/string copies. The browser already seals bytes, so the file path is:

```text
File/Blob bytes → HDROP2 binary container → one HPKE v2 envelope → POST /api/submit
```

Text stays:

```text
UTF-8 text → one HPKE v1 envelope → POST /api/submit
```

### Pre-body admission

The broker must know which body ceiling and reservation gate apply before fully buffering a 42 MiB request. The submit request therefore carries a small non-secret declaration, bound to the encrypted envelope version:

- `X-Hermes-Drop-Payload: text | files` (exact final spelling may follow existing request conventions).

Rules:

- `text` permits only envelope v1 and the text body ceiling.
- `files` acquires a file-submit lease/reservation before body buffering and permits only envelope v2.
- Header/envelope mismatch is a uniform refusal and does not consume the drop.
- The declaration reveals only text-versus-files to the origin broker; filenames, sizes, MIME hints, hashes, and bytes remain encrypted.
- Identical retries must carry the same declaration and sealed envelope.

## Broker lifecycle migration

The current preselected `payloadKind: text | files` creation model becomes a universal creation model:

```text
pending(choice)
  ├─ accepted v1 text  → submitted(text)
  └─ accepted v2 files → submitted(files)
```

Creation advertises both capabilities and file limits but does **not** reserve 42 MiB for every text-capable link. File memory is reserved by the pre-body `files` submit lease and converted atomically into the live payload reservation after successful decrypt/container validation. It is released on abort, timeout, refusal, expiry, or failed validation.

Once one submission wins, the payload kind is immutable. Duplicate-envelope retry semantics remain unchanged. A competing submission of the other kind receives the same unavailable result as any different second submission.

Compatibility:

- Existing explicitly typed drops remain claimable during a rolling upgrade if their records exist in-process.
- Existing text clients that omit the declaration may be accepted as `text` only during a documented compatibility window; new universal metadata advertises the declaration requirement.
- Protocol capability advertisement must let an older plugin fail before posting a universal link it cannot claim safely.

## Hermes claim dispatch

The universal request has one durable journal entry and one origin authorization decision.

After the payload-ready event, the service obtains only non-secret submission metadata (`payload_kind`) and dispatches:

- `text`: existing `claim_private_input` behavior;
- `files`: existing reviewed `materialize_file_claim` service, returning only safe paths and metadata.

No file bytes enter the tool result, placeholder vault, `state.db`, transcript, FTS, logs, or provider request. File labels and MIME hints are untrusted display metadata and must be clearly delimited; they are never instructions or filesystem paths.

The implementation may retain an internal file-specific claim function, but it is not exposed as a separate user-facing request command. If a model-facing claim tool is necessary for lifecycle compatibility, it should be hidden behind the universal service dispatcher rather than requiring the model to choose it.

## Delivery slices

### U1 — Universal contract and broker choice state

Scope:

- replace preselected creation semantics with `pending(choice)`;
- advertise text + file capabilities and limits from one metadata response;
- add pre-body payload declaration and file reservation lease;
- bind declaration to envelope v1/v2;
- preserve exact retry, one-winner, expiry, and uniform refusal semantics;
- retain backwards-compatible text behavior where explicitly supported.

Acceptance:

- one created link accepts exactly one valid text or file envelope;
- parallel text/file race has exactly one winner;
- file reservation starts before body buffering and always releases correctly;
- universal text drops do not reserve 42 MiB at creation;
- old text regression suite remains green.

Independent security review required before commit.

### U2 — Universal Hermes service, schema, and `/drop`

Scope:

- make `request_private_input` and `/drop` create universal drops;
- keep destination fields forbidden and origin binding unchanged;
- make payload-ready wake metadata payload-free except for the non-secret kind;
- dispatch text claims to the vault and file claims to the spool internally;
- ensure journal state is one-shot and correct for success, retry-safe failure, spent failure, and indeterminate transfer;
- do not expose `/drop-file` or `request_private_files`.

Acceptance:

- same request command supports both sender choices;
- wrong lane/session/origin refuses before broker claim or spool staging;
- file results contain paths/labels/type/size/hash/expiry only;
- state DB and model-context canary tests prove no file bytes;
- existing text tool and command behavior remains compatible.

Independent security review required before commit.

### U3 — One browser form

Scope:

- add file picker, drag/drop, list/remove/total UI to the existing form;
- explicit mutually-exclusive text/files mode without a second page or URL;
- assemble HDROP2 directly from `File` bytes;
- hash files and seal one v2 envelope;
- submit through the existing endpoint with the payload declaration;
- preserve exact sealed-envelope retry and expiry behavior;
- provide accessible keyboard, error, progress, mobile, light/dark states.

Acceptance:

- text send is visually and behaviorally unchanged unless files are selected;
- 1–5 files, including empty and binary files, round-trip byte-exactly;
- over-limit input is rejected before encryption/network;
- no base64, ZIP, filename URL/log leakage, or second form;
- browser memory tests cover a maximal 42 MiB drop without accidental multiple full-size retained copies beyond the reviewed container+HPKE requirements.

Independent security and visual QA required before commit.

### U4 — End-to-end, deployment, and manual test gate

Scope:

- browser → broker → universal Hermes dispatch → text vault or private spool;
- restart, expiry, disconnect, commit-indeterminate, duplicate/race, and cleanup tests;
- README/SECURITY/operator configuration and migration notes;
- deploy broker + plugin/browser together using capability gating;
- smoke text and files on the real origin-bound Discord flow.

Acceptance:

- one live link visibly offers both textarea and file picker;
- text round-trip succeeds once;
- 1 file and 5-file mixed binary/empty set round-trip byte-exactly;
- second claim fails;
- spool permissions are 0700/0600 and cleanup occurs after 15 minutes/startup;
- canaries are absent from `state.db`, session JSON/FTS, logs, and model-provider payload;
- user is pinged for manual testing only after this gate passes.

## Explicit non-scope

- simultaneous text **and** files in one submission;
- folders, ZIP, compression, previews, antivirus guarantees;
- resumable/chunked uploads or object storage;
- permanent storage or outbound destination selection;
- separate `/drop-file` or file-only request UX;
- base64 file transport.

## Recommended execution order

```text
U1 broker choice state
  → U2 universal Hermes dispatch
  → U3 browser form
  → U4 E2E/deploy/manual gate
  → centralized Herdr watcher fix (separate project task)
```

Each slice uses RED → GREEN → REFACTOR, a fresh bounded Opus/high implementation session, a separate Opus/high security review, Hermes verification, then one focused commit/push.
