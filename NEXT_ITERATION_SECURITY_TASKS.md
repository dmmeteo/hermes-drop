# Next Iteration — Security MVP

## 1. Durable Secret Sanitization
Prevent claimed passwords and tokens from being persisted in Hermes `state.db`, FTS, and backups. First verify the exact Hermes tool-result lifecycle, then implement the earliest safe sanitization seam while still allowing the active turn to use the secret.

## 2. Secure Delivery Verification & HTTP Warning
Verify the existing browser-side HPKE flow end to end and keep plaintext out of the public API even over plain HTTP. Do not block HTTP: clearly document that it protects only against passive interception—not active JavaScript/key substitution—and strongly recommend HTTPS for authenticated delivery.

## 3. Lossless Claim Boundary
Remove the window where the broker can destroy a secret before the plugin has successfully received and recorded it. Define the response-size limit in the shared control protocol and fail safely before consuming an oversized or unreadable claim.

## 4. Lifecycle & FSM Verification
Lock the existing `pending → submitted → claimed/destroyed` behavior with state-sequence tests covering duplicate submit, duplicate claim, expiry, retries, and invalid transitions. Document the verified FSM and deletion guarantees without introducing a speculative enum/refactor.

## 5. Restart Recovery E2E
Add one real integration test for `create → broker restart → reconcile`. Confirm the visible message becomes expired, the old secret cannot be claimed, and no orphaned waiter or live status remains.

## Explicitly Out of Scope
- Extra TLS/PSK encryption around the local `0600` Unix socket
- Hardened memory deletion against swap, core dumps, or host snapshots
- Opaque external executor / destination adapters
- Making public plain HTTP safe against active MITM attacks
- Post-quantum crypto, clustering, file transfer, or multi-recipient delivery
