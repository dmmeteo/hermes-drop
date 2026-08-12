# Outbound secret drops — MVP product canon

Status: **approved product baseline**

## Goal

Allow Hermes to share a short private text value with the user through an origin-bound, short-lived, one-time drop instead of placing the value in chat.

This is the outbound direction of Hermes Drop: **Hermes → current conversation user**.

## Deliberate scope

This feature is only for sharing a secret that Hermes already has or has just generated.

The MVP does **not** include:

- a vault or permanent secret storage;
- `pass`, Bitwarden CLI, or another password-manager integration;
- browsing, copying from, writing to, or synchronizing a secret store;
- generic credential lifecycle or rotation management;
- outbound file sharing.

Those ideas may be considered independently later and must not enlarge this implementation.

## Invocation model

The primary interface remains natural language. When the user asks Hermes to provide, reveal, return, or generate a secret, Hermes should use the outbound-drop tool automatically instead of placing plaintext in chat.

The existing `/drop` command remains one shared entry point for both directions; do not add a second outbound-specific command:

- `/drop` with no arguments creates the ordinary inbound form so the user can privately send text or files to Hermes.
- `/drop <free-text request>` sends that request through the normal authenticated Hermes turn. Hermes interprets whether the user is asking to receive a secret or announcing that they intend to send something.
- A request such as `/drop дай мені ключ OpenRouter` therefore causes Hermes to obtain or generate the requested value and return it through an outbound secret drop.
- A phrase such as `/drop я зараз закину секрет` remains an inbound request and creates the ordinary form.

The argument is free text, not a TTL parser. Direction is determined from the user's meaning, not merely from whether arguments are present. An ambiguous request must not cause Hermes to disclose a secret; Hermes should ask a brief clarification or choose the safe inbound form.

The model-facing outbound tool exists because Hermes needs a safe execution boundary, but it exposes no destination fields and always delivers back to the authoritative origin conversation. The slash command is only a natural-language invocation surface; it must not accept a model- or user-selected destination.

## Expiry configuration

Expiry is an operator/user default in plugin configuration rather than a routine `/drop` argument. Most people will choose one policy and rarely vary it per request.

- Inbound and outbound defaults may be configured separately because receiving private input and revealing an already-held secret have different risk/UX trade-offs.
- This deployment's desired outbound default is **30 minutes**.
- A deployment may choose a shorter default such as 5 or 10 minutes.
- Per-request TTL syntax is not part of the normal `/drop` UX. Natural-language requests for exceptional lifetimes may be considered later, subject to configured hard bounds; they are not required for this MVP.

## Approved UX

Hermes posts an origin-bound message containing:

- a safe non-secret label;
- a link to the private drop;
- a separate **3-digit temporary code**;
- an indication of the configured expiry (30 minutes on this deployment) and that the drop can be revealed once.

The user opens the link, explicitly enters the code, and chooses to reveal the value. After the first successful reveal, the value cannot be opened again.

## Approved defaults

- Code length: **3 decimal digits**.
- Maximum incorrect code attempts: **3**.
- Default TTL: configurable; **30 minutes for this deployment**.
- Successful claims: **one**.
- A normal `GET` or `HEAD` never consumes or claims a drop.
- Claiming requires explicit user interaction and a state-changing request.

A 2-digit code is deliberately not the default. It may be reconsidered only as a clearly labelled convenience/anti-preview mode, not as strong authentication.

## Security meaning of the code

The temporary code is a human-presence and anti-preview gate. It prevents ordinary Telegram, Discord, Slack, antivirus, and unfurl requests from consuming the drop. It is not a true second factor when the link and code are delivered in the same conversation.

The code must not appear in the URL or page metadata. Server-side verification must be rate-limited and store only an appropriate keyed digest or equivalent verifier. Three failed attempts make the drop unavailable. This intentionally prefers denial of delivery over allowing online brute force.

## Delivery and lifecycle invariants

- Delivery remains bound to the conversation that invoked the tool; the model cannot select another destination.
- Secret plaintext must not be included in the chat message, URL, logs, analytics, OpenGraph metadata, or durable Hermes conversation output.
- The landing page must be safe for repeated scanner/preview `GET` and `HEAD` requests.
- Only a correct code submitted through the claim operation may reserve the drop.
- Claim reservation must be atomic so two browsers cannot both reveal it.
- A short same-claim retry/ack mechanism may be used to avoid losing the value on a network interruption, but it must not permit a second independent claimant.
- The payload is destroyed after successful reveal acknowledgement or the bounded claim timeout.
- Expired, consumed, malformed, and unknown drops should expose uniform public behavior where practical.

## Cryptographic transport baseline

The payload should be encrypted before storage. The public service stores ciphertext, while the decryption key is carried in the URL fragment so it is not sent in HTTP requests or server access logs. The browser claims the ciphertext only after the correct code and decrypts locally.

Production is HTTPS-only. Plain HTTP cannot protect browser-delivered decryption code against an active network attacker and is outside the secure MVP.

## Minimal states

```text
available
  -> claimed by one browser/claim id
  -> destroyed

available
  -> expired

available
  -> unavailable after 3 incorrect codes
```

Public UI should clearly distinguish a usable drop from a final unavailable state without disclosing sensitive internal details.

## Deferred decisions

- Platform identity binding (Telegram identity, Discord OAuth, passkeys, paired devices).
- Separate-channel codes or real multi-factor authentication.
- Configurable 2-, 4-, or 6-digit code modes.
- Vault and password-manager integrations.
- Permanent secret history, recovery, or re-opening.
