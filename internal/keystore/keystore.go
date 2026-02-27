// Package keystore manages age-encrypted session key storage.
package keystore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/clawinfra/clawkeyring/pkg/keyring"
)

const (
	identityFile    = "identity.age"
	identityPubFile = "identity.age.pub"
	keysDir         = "keys"
	keyFileSuffix   = ".age"
	dirPerm         = 0o700
	filePerm        = 0o600
)

// ErrNotFound is returned when a key is not present in the keystore.
var ErrNotFound = errors.New("keystore: key not found")

// ErrKeystoreNotInit is returned when the keystore has not been initialised.
var ErrKeystoreNotInit = errors.New("keystore: not initialised; run 'clawkeyring init'")

// Keystore is an age-encrypted session key store backed by the filesystem.
type Keystore struct {
	dir      string
	identity *age.X25519Identity
}

// New opens an existing keystore at dir. Returns ErrKeystoreNotInit if
// the keystore has not been initialised.
func New(dir string) (*Keystore, error) {
	idPath := filepath.Join(dir, identityFile)
	data, err := os.ReadFile(idPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrKeystoreNotInit
		}
		return nil, fmt.Errorf("keystore: read identity: %w", err)
	}

	ids, err := age.ParseIdentities(strings.NewReader(string(data)))
	if err != nil {
		return nil, fmt.Errorf("keystore: parse identity: %w", err)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("keystore: no identities found in %s", idPath)
	}

	x25519id, ok := ids[0].(*age.X25519Identity)
	if !ok {
		return nil, fmt.Errorf("keystore: expected X25519 identity, got %T", ids[0])
	}

	return &Keystore{dir: dir, identity: x25519id}, nil
}

// Init creates a new keystore at dir, generating a fresh age X25519 keypair.
// Returns an error if the keystore already exists.
func Init(dir string) (*Keystore, error) {
	idPath := filepath.Join(dir, identityFile)
	if _, err := os.Stat(idPath); err == nil {
		return nil, fmt.Errorf("keystore: already initialised at %s", dir)
	}

	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("keystore: mkdir %s: %w", dir, err)
	}
	if err := os.MkdirAll(filepath.Join(dir, keysDir), dirPerm); err != nil {
		return nil, fmt.Errorf("keystore: mkdir keys: %w", err)
	}

	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("keystore: generate identity: %w", err)
	}

	// Write private key.
	if err := writeFile(idPath, []byte(id.String()+"\n"), filePerm); err != nil {
		return nil, fmt.Errorf("keystore: write identity: %w", err)
	}
	// Write public key.
	pubPath := filepath.Join(dir, identityPubFile)
	if err := writeFile(pubPath, []byte(id.Recipient().String()+"\n"), filePerm); err != nil {
		return nil, fmt.Errorf("keystore: write pubkey: %w", err)
	}

	return &Keystore{dir: dir, identity: id}, nil
}

// StoreKey encrypts rawKey and stores it for the given key type.
// rawKey bytes are zeroed after encryption.
func (ks *Keystore) StoreKey(kt keyring.KeyType, rawKey []byte, publicKey string) error {
	if !kt.Valid() {
		return fmt.Errorf("keystore: invalid key type %q", kt)
	}
	defer zeroBytes(rawKey)

	recipient := ks.identity.Recipient()

	var sb strings.Builder
	w, err := age.Encrypt(&sb, recipient)
	if err != nil {
		return fmt.Errorf("keystore: age encrypt: %w", err)
	}
	if _, err := w.Write(rawKey); err != nil {
		return fmt.Errorf("keystore: age write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("keystore: age close: %w", err)
	}

	path := ks.keyPath(kt)
	if err := atomicWriteFile(path, []byte(sb.String()), filePerm); err != nil {
		return fmt.Errorf("keystore: write key file: %w", err)
	}

	// Store metadata alongside (unencrypted public key + timestamp is not secret).
	meta := fmt.Sprintf("public_key=%s\nencrypted_at=%s\ntype=%s\n",
		publicKey, time.Now().UTC().Format(time.RFC3339), kt)
	metaPath := ks.keyPath(kt) + ".meta"
	if err := atomicWriteFile(metaPath, []byte(meta), filePerm); err != nil {
		return fmt.Errorf("keystore: write meta file: %w", err)
	}

	return nil
}

// DecryptKey decrypts and returns the raw key bytes for kt.
// The caller is responsible for zeroing the returned bytes after use.
func (ks *Keystore) DecryptKey(kt keyring.KeyType) ([]byte, error) {
	if !kt.Valid() {
		return nil, fmt.Errorf("keystore: invalid key type %q", kt)
	}

	path := ks.keyPath(kt)
	ciphertext, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keystore: read key file %s: %w", path, err)
	}

	r, err := age.Decrypt(strings.NewReader(string(ciphertext)), ks.identity)
	if err != nil {
		return nil, fmt.Errorf("keystore: age decrypt: %w", err)
	}

	var buf strings.Builder
	n := make([]byte, 4096)
	for {
		read, rerr := r.Read(n)
		if read > 0 {
			buf.Write(n[:read])
		}
		if rerr != nil {
			break
		}
	}

	return []byte(buf.String()), nil
}

// ListKeys returns the metadata for all stored keys.
func (ks *Keystore) ListKeys() ([]keyring.KeyEntry, error) {
	var entries []keyring.KeyEntry
	for _, kt := range keyring.AllKeyTypes() {
		path := ks.keyPath(kt)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		}
		entry := keyring.KeyEntry{Type: kt}
		// Try to read metadata.
		metaPath := path + ".meta"
		if metaData, err := os.ReadFile(metaPath); err == nil {
			parseMeta(metaData, &entry)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// HasKey reports whether a key of the given type is stored.
func (ks *Keystore) HasKey(kt keyring.KeyType) bool {
	_, err := os.Stat(ks.keyPath(kt))
	return err == nil
}

// Dir returns the keystore directory.
func (ks *Keystore) Dir() string { return ks.dir }

// PublicKey returns the age public key (recipient) as a string.
func (ks *Keystore) PublicKey() string {
	return ks.identity.Recipient().String()
}

// ---- helpers ----------------------------------------------------------------

func (ks *Keystore) keyPath(kt keyring.KeyType) string {
	return filepath.Join(ks.dir, keysDir, string(kt)+keyFileSuffix)
}

func writeFile(path string, data []byte, perm os.FileMode) error {
	return os.WriteFile(path, data, perm)
}

// atomicWriteFile writes data to path atomically using a temp file + rename.
func atomicWriteFile(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func parseMeta(data []byte, entry *keyring.KeyEntry) {
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "public_key":
			entry.PublicKey = parts[1]
		case "encrypted_at":
			t, err := time.Parse(time.RFC3339, parts[1])
			if err == nil {
				entry.EncryptedAt = t
			}
		}
	}
}
