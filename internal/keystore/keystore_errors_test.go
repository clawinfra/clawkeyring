package keystore_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInitMkdirFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows")
	}
	// Use a file where a directory is expected — MkdirAll fails.
	parent := t.TempDir()
	// Create a file at the path where we want a directory.
	blockPath := filepath.Join(parent, "blocked")
	require.NoError(t, os.WriteFile(blockPath, []byte("I am a file"), 0o600))

	// Try to init a keystore inside a path that's actually a file.
	_, err := keystore.Init(filepath.Join(blockPath, "ks"))
	assert.Error(t, err)
}

func TestInitKeysDirFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows")
	}
	parent := t.TempDir()
	// Create the base dir but put a file where "keys" subdir should go.
	ksDir := filepath.Join(parent, "ks")
	require.NoError(t, os.MkdirAll(ksDir, 0o700))
	keysPath := filepath.Join(ksDir, "keys")
	// Write a file at the keys path to block directory creation.
	require.NoError(t, os.WriteFile(keysPath, []byte("I am a file"), 0o600))

	_, err := keystore.Init(ksDir)
	// Init should fail: already-exists check won't trigger (no identity.age),
	// but MkdirAll for keys/ will fail because keys is a file.
	assert.Error(t, err)
}

func TestNewUnreadableIdentityFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; chmod restrictions don't apply")
	}
	if runtime.GOOS == "windows" {
		t.Skip("skip on Windows")
	}

	dir := t.TempDir()
	_, err := keystore.Init(dir)
	require.NoError(t, err)

	// Make identity file unreadable.
	idPath := filepath.Join(dir, "identity.age")
	require.NoError(t, os.Chmod(idPath, 0o000))
	t.Cleanup(func() { _ = os.Chmod(idPath, 0o600) })

	_, err = keystore.New(dir)
	assert.Error(t, err)
	assert.NotErrorIs(t, err, keystore.ErrKeystoreNotInit)
}
