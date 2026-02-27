# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-02-27

### Added
- Initial release of `clawkeyring` — agent-native validator key management for ClawChain.
- `age`-encrypted keystore for BABE, GRANDPA, and ImOnline session keys.
- `clawkeyring init` command: initialise keystore, generate age X25519 keypair.
- `clawkeyring inject` command: decrypt and inject session keys into Substrate node via `author_insertKey` JSON-RPC.
- `clawkeyring rotate` command: generate new session keys, inject, submit `set_keys` extrinsic.
- `clawkeyring serve` command: start mTLS gRPC server for remote key operations.
- `clawkeyring status` command: show current key set and last rotation era.
- `clawkeyring audit` command: dump on-chain audit log from `agent-receipts` pallet.
- `internal/keystore`: age-backed encrypted key storage with atomic writes and strict file permissions.
- `internal/injector`: Substrate `author_insertKey` JSON-RPC client with plaintext zeroing.
- `internal/rotation`: on-chain `NewEra` subscription and automated key rotation.
- `internal/audit`: `agent-receipts` pallet extrinsic submitter.
- `internal/server`: mTLS gRPC server with `KeyringService` (Rotate, List, Status, StreamEvents).
- `pkg/keyring`: public API types and protobuf definitions.
- GitHub Actions CI: `go test -race -coverprofile=coverage.out ./...` with ≥90% coverage gate.
- `scripts/gen-certs.sh`: mTLS CA, server, and client certificate generation helper.
- Full threat model and key lifecycle documentation in `docs/DESIGN.md`.

[v0.1.0]: https://github.com/clawinfra/clawkeyring/releases/tag/v0.1.0
