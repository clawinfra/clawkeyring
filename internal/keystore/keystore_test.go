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

func TestInit(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	assert.NotNil(t, ks)
	assert.NotEmpty(t, ks.PublicKey())
	assert.Equal(t, dir, ks.Dir())

	// Identity files should exist.
	assert.FileExists(t, dir+"/identity.age")
	assert.FileExists(t, dir+"/identity.age.pub")

	// Keys directory should exist.
	assert.DirExists(t, filepath.Join(dir, "keys"))

	// Permissions.
	info, err := os.Stat(dir + "/identity.age")
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestInitAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Init(dir)
	require.NoError(t, err)

	_, err = keystore.Init(dir)
	assert.Error(t, err)
}

func TestNewNotInit(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.New(dir)
	assert.ErrorIs(t, err, keystore.ErrKeystoreNotInit)
}

func TestNew(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Init(dir)
	require.NoError(t, err)

	ks, err := keystore.New(dir)
	require.NoError(t, err)
	assert.NotNil(t, ks)
}

func TestNewCorruptedIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Init(dir)
	require.NoError(t, err)

	// Corrupt the identity file.
	err = os.WriteFile(filepath.Join(dir, "identity.age"), []byte("not valid age"), 0o600)
	require.NoError(t, err)

	_, err = keystore.New(dir)
	assert.Error(t, err)
}

func TestNewEmptyIdentity(t *testing.T) {
	dir := t.TempDir()
	_, err := keystore.Init(dir)
	require.NoError(t, err)

	// Write an empty identity file (valid but no identities).
	err = os.WriteFile(filepath.Join(dir, "identity.age"), []byte(""), 0o600)
	require.NoError(t, err)

	_, err = keystore.New(dir)
	assert.Error(t, err)
}

func TestStoreAndDecryptKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	rawKey := []byte("super-secret-babe-key-material-32b")
	pubKey := "0xabc123"

	err = ks.StoreKey(keyring.KeyTypeBABE, rawKey, pubKey)
	require.NoError(t, err)

	// rawKey should be zeroed after store.
	allZero := true
	for _, b := range rawKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	assert.True(t, allZero, "raw key should be zeroed after storage")

	decrypted, err := ks.DecryptKey(keyring.KeyTypeBABE)
	require.NoError(t, err)
	assert.Equal(t, "super-secret-babe-key-material-32b", string(decrypted))
}

func TestDecryptKeyNotFound(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_, err = ks.DecryptKey(keyring.KeyTypeGRANDPA)
	assert.ErrorIs(t, err, keystore.ErrNotFound)
}

func TestDecryptKeyInvalidType(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_, err = ks.DecryptKey(keyring.KeyType("bad"))
	assert.Error(t, err)
}

func TestStoreKeyInvalidType(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	err = ks.StoreKey(keyring.KeyType("bad"), []byte("key"), "pub")
	assert.Error(t, err)
}

func TestListKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	entries, err := ks.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, entries)

	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("babe-key-material-padding-32bytes"), "0xbabe")
	_ = ks.StoreKey(keyring.KeyTypeGRANDPA, []byte("gran-key-material-padding-32bytes"), "0xgran")

	entries, err = ks.ListKeys()
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	types := map[keyring.KeyType]bool{}
	for _, e := range entries {
		types[e.Type] = true
		assert.NotEmpty(t, e.PublicKey)
	}
	assert.True(t, types[keyring.KeyTypeBABE])
	assert.True(t, types[keyring.KeyTypeGRANDPA])
}

func TestListKeysEncryptedAtParsed(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_ = ks.StoreKey(keyring.KeyTypeImOnline, []byte("imon-key-material-padding-32bytes"), "0ximon")

	entries, err := ks.ListKeys()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.False(t, entries[0].EncryptedAt.IsZero(), "EncryptedAt should be set")
}

func TestHasKey(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	assert.False(t, ks.HasKey(keyring.KeyTypeBABE))
	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("babe-key-material-padding-32bytes"), "0xbabe")
	assert.True(t, ks.HasKey(keyring.KeyTypeBABE))
}

func TestStoreAllKeyTypes(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	for _, kt := range keyring.AllKeyTypes() {
		raw := make([]byte, 32)
		for i := range raw {
			raw[i] = byte(i + 1)
		}
		expected := make([]byte, 32)
		copy(expected, raw)

		err = ks.StoreKey(kt, raw, "0xpub"+string(kt))
		require.NoError(t, err, "store %s", kt)

		decrypted, err := ks.DecryptKey(kt)
		require.NoError(t, err, "decrypt %s", kt)
		assert.Equal(t, expected, decrypted, "roundtrip %s", kt)
	}
}

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("original-babe-material-32bytesxx"), "0xold")
	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("updated--babe-material-32bytesxx"), "0xnew")

	decrypted, err := ks.DecryptKey(keyring.KeyTypeBABE)
	require.NoError(t, err)
	assert.Equal(t, "updated--babe-material-32bytesxx", string(decrypted))
}

func TestPublicKey(t *testing.T) {
	dir := t.TempDir()
	ks1, err := keystore.Init(dir)
	require.NoError(t, err)

	pub1 := ks1.PublicKey()
	assert.NotEmpty(t, pub1)
	assert.Contains(t, pub1, "age1") // age public keys start with age1

	// New open of same keystore should have same public key.
	ks2, err := keystore.New(dir)
	require.NoError(t, err)
	assert.Equal(t, pub1, ks2.PublicKey())
}

func TestListKeysNoMetaFile(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("babe-key-material-padding-32bytes"), "0xbabe")

	// Remove meta file to test fallback.
	metaPath := filepath.Join(dir, "keys", "babe.age.meta")
	os.Remove(metaPath)

	entries, err := ks.ListKeys()
	require.NoError(t, err)
	// Should still return the entry, just without metadata.
	assert.Len(t, entries, 1)
}
