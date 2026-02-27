# clawkeyring — Design Document

## Overview

`clawkeyring` is a security-critical service. It manages cryptographic keys that control block production and finalisation on a ClawChain validator node. A compromise of these keys can lead to equivocation (slashing) or complete loss of stake. This document describes the threat model, key lifecycle, and security architecture.

---

## Threat Model

### Assets

| Asset                  | Sensitivity | Impact if Compromised                         |
|-----------------------|-------------|-----------------------------------------------|
| BABE private key      | Critical    | Double-block-production → equivocation slash  |
| GRANDPA private key   | Critical    | Double-finalisation → equivocation slash      |
| ImOnline private key  | Medium      | Missed heartbeats → offline slash             |
| age identity key      | Critical    | Decryption of all stored session keys         |
| mTLS server key       | High        | MITM on key operation API                     |

### Threat Actors

1. **Local unprivileged attacker** — has shell access but not root; process isolation is the boundary.
2. **Remote attacker** — can reach the gRPC port; mTLS is the boundary.
3. **Supply chain attacker** — malicious dependency; pinned Go modules + `go mod verify` in CI.
4. **Insider/compromised CI** — malicious build artefact; reproducible builds + signed releases.

### Out of Scope

- Physical hardware attacks (HSM integration is a future milestone).
- OS kernel compromise (assumed trusted).
- Side-channel attacks on the host CPU.

---

## Key Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                       KEY LIFECYCLE                             │
│                                                                 │
│  GENERATE         STORE             INJECT           ROTATE     │
│                                                                 │
│  Substrate     age encrypt       author_insertKey   NewEra evt  │
│  rotate_keys ──────────────▶ ~/.clawkeyring/keys/ ──────────▶  │
│  (node RPC)    (age pubkey)   (age decrypt)        set_keys     │
│                                                                 │
│       │                              │               │          │
│       ▼                              ▼               ▼          │
│  [sr25519/ed25519]           [Substrate node]  [on-chain]      │
│  raw key bytes               keystore memory   next era         │
│                                                                 │
│  AUDIT                                                          │
│  Every operation ─────────────────────────────▶ agent-receipts │
│  (rotate, inject, status)                       pallet          │
└─────────────────────────────────────────────────────────────────┘
```

### Phase 1: Generation

Session keys are generated **by the Substrate node itself** via `author_rotateKeys` RPC. The node returns the raw public keys. `clawkeyring` then retrieves the private keys from the node's internal keystore via `author_insertKey` reverse flow — or the operator manually imports them.

### Phase 2: Encrypted Storage

Keys are encrypted at rest using [age](https://age-encryption.org/) (filippo.io/age):

```
~/.clawkeyring/
├── identity.age          # age X25519 private key (chmod 600)
├── identity.age.pub      # age X25519 public key
└── keys/
    ├── babe.age           # age-encrypted BABE sr25519 key
    ├── gran.age           # age-encrypted GRANDPA ed25519 key
    └── imon.age           # age-encrypted ImOnline sr25519 key
```

**Why age?**
- Modern, audited, minimal API surface.
- X25519 key agreement — no password KDF to brute-force.
- No legacy algorithms.
- Streaming encryption — suitable for future large key batches.

**File permissions enforced by clawkeyring:**
- Keystore directory: `0700`
- `identity.age`: `0600`
- `keys/*.age`: `0600`

### Phase 3: Injection

On `clawkeyring inject` (or at server startup):

1. Decrypt each `keys/*.age` file using the age identity key.
2. Call `author_insertKey(keyType, suri, publicKey)` JSON-RPC on the Substrate node.
3. Wipe decrypted bytes from memory (`runtime.KeepAlive` + explicit zeroing).
4. Log the inject event to the audit pallet.

**Key zeroing:** All `[]byte` buffers holding plaintext key material are explicitly zeroed after use. Go's GC does not guarantee memory will be collected quickly; zeroing is mandatory.

### Phase 4: Rotation

Rotation is triggered by:
- Manual `clawkeyring rotate` command.
- Automatic detection of `NewEra` event via substrate-rpc-client WebSocket subscription.

Rotation sequence:

```
1. Generate new session keys on node (author_rotateKeys)
2. Encrypt and store new keys (overwrites old .age files)
3. Inject new keys into node (author_insertKey)
4. Submit set_keys extrinsic (takes effect next session)
5. Log rotation to agent-receipts pallet
6. Emit rotation event on gRPC stream
```

**Atomicity:** Key files are written to a `.tmp` suffix first, then `os.Rename`d to the final path. Rename is atomic on POSIX. If injection fails, old keys are preserved.

### Phase 5: Audit (agent-receipts pallet)

Every key operation (inject, rotate, import, delete) is submitted as an extrinsic to the `agentReceipts` pallet on ClawChain. The on-chain record includes:

```
AuditRecord {
    agent:     AccountId,   // clawkeyring's on-chain identity
    operation: Bytes,       // e.g. "rotate:babe,gran,imon"
    era:       u32,         // active era at time of operation
    timestamp: u64,         // Unix milliseconds
    hash:      H256,        // SHA-256 of operation metadata
}
```

---

## gRPC mTLS API

The local gRPC API is protected by mutual TLS. Both server and client present certificates signed by a shared CA.

### Why mTLS?

- Prevents unauthorised processes on the same host from calling key operations.
- Client certificate identifies the caller (supports access control per-certificate CN).
- Certificates can be rotated independently of the service.

### API Surface

```protobuf
service KeyringService {
    rpc RotateKeys (RotateRequest)  returns (RotateResponse);
    rpc ListKeys   (ListRequest)    returns (ListResponse);
    rpc GetStatus  (StatusRequest)  returns (StatusResponse);
    rpc StreamEvents (StreamRequest) returns (stream KeyEvent);
}
```

See [pkg/keyring/proto/keyring.proto](../pkg/keyring/proto/keyring.proto).

---

## Dependency Pinning

All Go module checksums are locked via `go.sum`. CI runs `go mod verify` to detect tampering. Dependencies are minimised:

| Dependency                                      | Version | Purpose                    |
|------------------------------------------------|---------|----------------------------|
| filippo.io/age                                  | v1.x    | Key encryption             |
| github.com/spf13/cobra                          | v1.x    | CLI framework              |
| google.golang.org/grpc                          | v1.x    | gRPC server                |
| github.com/centrifuge/go-substrate-rpc-client/v4| v0.x    | Chain subscription + extrinsics |
| github.com/stretchr/testify                     | v1.x    | Test assertions            |

---

## Key Compromise Response

If a session key is believed compromised:

1. **Immediately** call `clawkeyring rotate` — generates new keys, submits set_keys for next session.
2. Monitor `NewEra` event — new keys take effect at session boundary.
3. If equivocation has already occurred — cooperate with on-chain governance for slash mitigation.
4. Rotate age identity key — re-encrypt all stored keys with a new identity.
5. Revoke compromised mTLS client certificates.

---

## Future Work

- **HSM backend** — Plug in YubiHSM2 or AWS CloudHSM via PKCS#11.
- **Remote attestation** — Prove key operations occurred in a TEE (SGX/TDX).
- **Threshold signatures** — Shamir secret sharing for age identity key.
- **Audit log verification** — CLI command to verify on-chain audit records match local logs.
