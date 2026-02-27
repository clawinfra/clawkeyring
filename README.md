# clawkeyring

**Agent-native validator key management for ClawChain.**

`clawkeyring` is a production-grade service that manages BABE, GRANDPA, and ImOnline session keys for ClawChain validators. Keys are stored encrypted at rest using [age](https://age-encryption.org/) and automatically injected into a running Substrate node on startup. Every key operation is logged as an on-chain audit trail via the `agent-receipts` pallet.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     clawkeyring                          │
│                                                         │
│  ┌──────────┐  decrypt  ┌───────────┐  insertKey RPC   │
│  │ keystore │──────────▶│  injector │─────────────────▶ Substrate Node
│  │ (age enc)│           └───────────┘                  │
│  └──────────┘                                           │
│       ▲                 ┌───────────┐  set_keys extrinsic│
│       │ rotate          │ rotation  │─────────────────▶ ClawChain
│       └─────────────────│ (NewEra)  │                  │
│                         └───────────┘                  │
│                         ┌───────────┐  agent-receipts  │
│                         │   audit   │─────────────────▶ ClawChain
│                         └───────────┘                  │
│                         ┌───────────┐                  │
│                         │  server   │◀── mTLS gRPC ────  Clients
│                         │ (mTLS)    │                  │
│                         └───────────┘                  │
└─────────────────────────────────────────────────────────┘
```

## Key Types

| Key Type   | Substrate Type | Purpose                              |
|-----------|---------------|--------------------------------------|
| BABE      | `babe`        | Block production (sr25519)            |
| GRANDPA   | `gran`        | Block finalisation (ed25519)          |
| ImOnline  | `imon`        | Liveness heartbeats (sr25519)         |

---

## Quickstart

### Prerequisites

- Go 1.22+
- A running ClawChain/Substrate node (default RPC: `ws://127.0.0.1:9944`)
- mTLS certificates (see [scripts/gen-certs.sh](scripts/gen-certs.sh))

### Install

```bash
go install github.com/clawinfra/clawkeyring/cmd/clawkeyring@latest
```

Or build from source:

```bash
git clone https://github.com/clawinfra/clawkeyring
cd clawkeyring
make build
```

### Initialise Keystore

```bash
# Generate a new age keypair and initialise the keystore directory
clawkeyring init --keystore ~/.clawkeyring
```

This creates:
- `~/.clawkeyring/identity.age`  — age private key (keep secret!)
- `~/.clawkeyring/identity.age.pub` — age public key
- `~/.clawkeyring/keys/` — directory for encrypted session keys

### Store Session Keys

After generating session keys on your node:

```bash
# Import a session key into the encrypted keystore
clawkeyring import --type babe --hex 0xabc123... --keystore ~/.clawkeyring
clawkeyring import --type gran --hex 0xdef456... --keystore ~/.clawkeyring
clawkeyring import --type imon --hex 0xghi789... --keystore ~/.clawkeyring
```

### Inject Keys into Node

```bash
# Decrypt and inject all session keys into the running node
clawkeyring inject \
  --node ws://127.0.0.1:9944 \
  --keystore ~/.clawkeyring
```

### Rotate Keys

```bash
# Generate new session keys, inject into node, submit set_keys extrinsic
clawkeyring rotate \
  --node ws://127.0.0.1:9944 \
  --keystore ~/.clawkeyring \
  --account //Alice
```

### Start gRPC Server

```bash
# Generate mTLS certs first
./scripts/gen-certs.sh ~/.clawkeyring/certs

# Start the mTLS gRPC server
clawkeyring serve \
  --keystore ~/.clawkeyring \
  --cert ~/.clawkeyring/certs/server.crt \
  --key  ~/.clawkeyring/certs/server.key \
  --ca   ~/.clawkeyring/certs/ca.crt \
  --addr 127.0.0.1:9090
```

### Check Status

```bash
clawkeyring status --keystore ~/.clawkeyring
```

### View Audit Log

```bash
clawkeyring audit --node ws://127.0.0.1:9944 --account 5GrwvaEF...
```

---

## Configuration

All flags can be set via environment variables or a config file (`~/.clawkeyring/config.yaml`):

| Flag           | Env Var                | Default                     |
|---------------|------------------------|-----------------------------|
| `--keystore`  | `CLAWKEYRING_KEYSTORE` | `~/.clawkeyring`            |
| `--node`      | `CLAWKEYRING_NODE`     | `ws://127.0.0.1:9944`       |
| `--addr`      | `CLAWKEYRING_ADDR`     | `127.0.0.1:9090`            |
| `--log-level` | `CLAWKEYRING_LOG`      | `info`                      |

---

## Security

See [docs/DESIGN.md](docs/DESIGN.md) for full threat model and key lifecycle documentation.

**Never** run `clawkeyring` as root. The keystore directory should be `chmod 700`.

---

## Development

```bash
make test        # run tests with race detector
make coverage    # generate HTML coverage report
make lint        # run golangci-lint
make proto       # regenerate gRPC protobuf stubs
```

### Test Coverage

Coverage ≥ 90% is enforced in CI. Check locally:

```bash
make coverage
```

---

## CI/CD

GitHub Actions runs on every push and PR:

- `go test -race -coverprofile=coverage.out ./...`
- Coverage gate: ≥ 90%
- `golangci-lint`
- Build for `linux/amd64` and `linux/arm64`

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
