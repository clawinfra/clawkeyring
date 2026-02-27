package keystore_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInitCreatesKeysDir verifies keys subdirectory is created.
func TestInitCreatesKeysDir(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	assert.DirExists(t, filepath.Join(ks.Dir(), "keys"))
}

// TestStoreKeyZeroesInput verifies that raw key bytes are zeroed.
func TestStoreKeyZeroesInputAllTypes(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	for _, kt := range keyring.AllKeyTypes() {
		raw := []byte("some-key-material-to-be-zeroed!!")
		_ = ks.StoreKey(kt, raw, "0xpub")
		for i, b := range raw {
			assert.Equal(t, byte(0), b, "byte %d not zeroed for %s", i, kt)
		}
	}
}

// TestDecryptAfterReopen verifies that decryption works after reopening keystore.
func TestDecryptAfterReopen(t *testing.T) {
	dir := t.TempDir()
	ks1, err := keystore.Init(dir)
	require.NoError(t, err)

	original := []byte("original-babe-material-32bytesxx")
	expected := make([]byte, len(original))
	copy(expected, original)

	err = ks1.StoreKey(keyring.KeyTypeBABE, original, "0xpub")
	require.NoError(t, err)

	// Reopen.
	ks2, err := keystore.New(dir)
	require.NoError(t, err)

	decrypted, err := ks2.DecryptKey(keyring.KeyTypeBABE)
	require.NoError(t, err)
	assert.Equal(t, expected, decrypted)
}

// TestListKeysAllThreeKeys verifies all 3 key types are listed.
func TestListKeysAllThreeKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	for _, kt := range keyring.AllKeyTypes() {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte(i + 10)
		}
		err = ks.StoreKey(kt, raw, "0x"+string(kt))
		require.NoError(t, err)
	}

	entries, err := ks.ListKeys()
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

// TestInitWritesPublicKeyFile verifies the pub key file contains an age-format pubkey.
func TestInitWritesPublicKeyFile(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	pubContent, err := os.ReadFile(filepath.Join(dir, "identity.age.pub"))
	require.NoError(t, err)
	assert.Contains(t, string(pubContent), "age1")
	assert.Equal(t, ks.PublicKey()+"\n", string(pubContent))
}
