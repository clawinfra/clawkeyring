package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServeCmdRunENoKeystore tests that serve fails when keystore doesn't exist.
func TestServeCmdRunENoKeystore(t *testing.T) {
	dir := t.TempDir()
	cmd := rootCmd()
	cmd.SetArgs([]string{"serve",
		"--keystore", dir + "/noexist",
		"--addr", "127.0.0.1:0",
	})
	err := cmd.Execute()
	assert.Error(t, err)
}

// TestServeCmdFlagsConfiguration tests that serve flags are configured correctly.
func TestServeCmdFlagsConfiguration(t *testing.T) {
	cmd2 := serveCmd()
	f := cmd2.Flags()

	// Verify flag defaults.
	keystoreFlag := f.Lookup("keystore")
	require.NotNil(t, keystoreFlag)

	addrFlag := f.Lookup("addr")
	require.NotNil(t, addrFlag)
	assert.Equal(t, "127.0.0.1:9090", addrFlag.DefValue)

	assert.NotNil(t, f.Lookup("cert"))
	assert.NotNil(t, f.Lookup("key"))
	assert.NotNil(t, f.Lookup("ca"))
}

// TestServeCmdRunEWithTLSError tests that serve fails when TLS files don't exist.
func TestServeCmdRunEWithTLSError(t *testing.T) {
	dir := t.TempDir()
	// Init keystore.
	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--keystore", dir + "/ks"})
	require.NoError(t, cmd.Execute())

	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"serve",
		"--keystore", dir + "/ks",
		"--addr", "127.0.0.1:0",
		"--cert", dir + "/nonexistent.crt",
		"--key", dir + "/nonexistent.key",
		"--ca", dir + "/nonexistent-ca.crt",
	})
	err := cmd2.Execute()
	assert.Error(t, err)
}

// TestInjectCmdWithKeysAndFailingNode tests inject when keys exist but node is down.
func TestInjectCmdWithKeysAndFailingNode(t *testing.T) {
	dir := t.TempDir()
	// Init keystore.
	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--keystore", dir + "/ks"})
	require.NoError(t, cmd.Execute())

	// Import a key.
	cmd2 := rootCmd()
	cmd2.SetArgs([]string{"import",
		"--keystore", dir + "/ks",
		"--type", "babe",
		"--hex", "0xdeadbeefdeadbeefdeadbeefdeadbeef",
		"--pub", "0xabc123",
	})
	require.NoError(t, cmd2.Execute())

	// Inject — node is not running, should fail.
	cmd3 := rootCmd()
	cmd3.SetArgs([]string{"inject",
		"--keystore", dir + "/ks",
		"--node", "http://127.0.0.1:19999", // port nobody is listening on
	})
	err := cmd3.Execute()
	assert.Error(t, err)
}
