// Package keyring defines the public API types for clawkeyring.
package keyring

import "time"

// KeyType represents a Substrate session key type.
type KeyType string

const (
	// KeyTypeBABE is the BABE block production key (sr25519).
	KeyTypeBABE KeyType = "babe"
	// KeyTypeGRANDPA is the GRANDPA finality key (ed25519).
	KeyTypeGRANDPA KeyType = "gran"
	// KeyTypeImOnline is the ImOnline liveness key (sr25519).
	KeyTypeImOnline KeyType = "imon"
	// KeyTypeAura is the Aura block production key (sr25519).
	// Used by Aura-based Substrate chains (e.g. ClawChain staging).
	KeyTypeAura KeyType = "aura"
)

// AllKeyTypes returns all supported session key types.
func AllKeyTypes() []KeyType {
	return []KeyType{KeyTypeBABE, KeyTypeGRANDPA, KeyTypeImOnline, KeyTypeAura}
}

// Valid reports whether k is a recognised KeyType.
func (k KeyType) Valid() bool {
	switch k {
	case KeyTypeBABE, KeyTypeGRANDPA, KeyTypeImOnline, KeyTypeAura:
		return true
	default:
		return false
	}
}

// String implements fmt.Stringer.
func (k KeyType) String() string { return string(k) }

// CryptoScheme returns the cryptographic scheme for the key type.
func (k KeyType) CryptoScheme() string {
	switch k {
	case KeyTypeGRANDPA:
		return "ed25519"
	default:
		return "sr25519"
	}
}

// KeyEntry holds the metadata and ciphertext of a stored session key.
type KeyEntry struct {
	// Type is the session key type.
	Type KeyType `json:"type"`
	// PublicKey is the hex-encoded public key.
	PublicKey string `json:"public_key"`
	// EncryptedAt is when the key was encrypted and stored.
	EncryptedAt time.Time `json:"encrypted_at"`
	// Era is the era when this key was last rotated (0 = never).
	Era uint32 `json:"era"`
}

// RotationRecord captures the result of a key rotation operation.
type RotationRecord struct {
	// Era is the era when rotation was triggered.
	Era uint32 `json:"era"`
	// Timestamp is when the rotation occurred.
	Timestamp time.Time `json:"timestamp"`
	// Keys are the new key entries after rotation.
	Keys []KeyEntry `json:"keys"`
	// TxHash is the on-chain transaction hash of the set_keys extrinsic.
	TxHash string `json:"tx_hash,omitempty"`
}

// AuditRecord is an on-chain audit log entry from the agent-receipts pallet.
type AuditRecord struct {
	// Agent is the AccountId of the clawkeyring agent.
	Agent string `json:"agent"`
	// Operation describes what was done (e.g. "inject:babe,gran,imon").
	Operation string `json:"operation"`
	// Era is the active era at the time of the operation.
	Era uint32 `json:"era"`
	// Timestamp is the Unix millisecond timestamp.
	Timestamp int64 `json:"timestamp"`
	// Hash is the hex-encoded SHA-256 of the operation metadata.
	Hash string `json:"hash"`
	// BlockNumber is the block in which this record was included.
	BlockNumber uint64 `json:"block_number"`
}

// OperationKind enumerates the types of auditable operations.
type OperationKind string

const (
	// OperationInject records a key injection into the node.
	OperationInject OperationKind = "inject"
	// OperationRotate records a key rotation.
	OperationRotate OperationKind = "rotate"
	// OperationImport records a manual key import.
	OperationImport OperationKind = "import"
	// OperationDelete records key deletion.
	OperationDelete OperationKind = "delete"
)
