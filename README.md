# spectre-relay

The relay for [Spectre](../spectre) — a deliberately **dumb store-and-forward**
for encrypted blobs. It is **untrusted by design**: it never sees plaintext,
and with Sealed Sender it doesn't learn who sent a message either. Written in
Go, no database, env-var config only.

## What it does
- Ferries opaque, recipient-encrypted blobs between clients that may be offline
  at different times (AES-256-GCM-encrypted offline queue, 7-day TTL).
- Ed25519 challenge-response auth (signed nonce; no passwords/tokens).
- Public prekey-bundle directory (`GET /prekeys/{id}`) for X3DH bootstrap.
- Sealed-sender support: signs short-lived sender certificates bound to the
  authenticated user's registered identity key; publishes its CA pubkey at
  `GET /sealed-ca` for clients to pin.

## What it can / cannot see
- **Cannot:** message content, or (for sealed envelopes) the sender.
- **Can, by construction:** recipient ID, message size + timing, and the
  client IP / TCP-level identity (mitigate with Tor/onion transport + a
  separate anonymous upload channel — out of scope here).

> ⚠️ The relay also issues sealed-sender certificates, i.e. it is the CA. A
> malicious relay could forge sender attribution; clients defend with
> out-of-band safety-number verification. See
> [`../spectre/SEALED_SENDER_REVIEW.md`](../spectre/SEALED_SENDER_REVIEW.md).

## Endpoints
| Path | Auth | Purpose |
|------|------|---------|
| `/ws` | Ed25519 handshake | message delivery + control frames |
| `/prekeys/{userId}` | public | fetch a peer's prekey bundle (consumes one OTPK) |
| `/sealed-ca` | public | sealed-sender CA public key (pin on first use) |
| `/health` | public | returns `.` only — no fingerprint |

## Run

**Dev (no TLS):**
```bash
./run-dev.sh      # prints the LAN URL + ready-to-paste client commands
```

**Production (TLS required — refuses to start without it):**
```bash
SPECTRE_LISTEN_ADDR=":443" \
SPECTRE_TLS_CERT="/etc/ssl/spectre.crt" SPECTRE_TLS_KEY="/etc/ssl/spectre.key" \
SPECTRE_QUEUE_PATH="/data/offline_queue.enc" \
SPECTRE_PREKEY_PATH="/data/prekeys.enc" \
SPECTRE_SEALED_CA_PATH="/data/sealed_ca.key" \
./spectre-relay
```
TLS 1.3 only; compression disabled (CRIME); runs non-root in `scratch` via the
provided Dockerfile / docker-compose.

Key files under the data dir (`.key` siblings + `sealed_ca.key`) are secrets —
keep them out of git and back them up out of band. `sealed_ca.key` is
especially sensitive (it's the attribution-signing key; HSM it in production).

## Tests
```bash
go test ./...
```

## Status
Works for local/dev use. Not production-hardened — see the review package and
`../spectre/SPECTRE_DEVLOG.md`.
