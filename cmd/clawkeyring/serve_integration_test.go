package main

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestServeCmdInsecurePath exercises the serve command's insecure (no-TLS) code path
// by sending SIGTERM to self after a short delay.
func TestServeCmdInsecurePath(t *testing.T) {
	dir := t.TempDir()

	// Init keystore.
	cmd := rootCmd()
	cmd.SetArgs([]string{"init", "--keystore", dir + "/ks"})
	require.NoError(t, cmd.Execute())

	// Send SIGTERM to ourselves after 150ms to unblock the serve command.
	self, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		cmd2 := rootCmd()
		cmd2.SetArgs([]string{"serve",
			"--keystore", dir + "/ks",
			"--addr", "127.0.0.1:0",
		})
		done <- cmd2.Execute()
	}()

	time.Sleep(200 * time.Millisecond)
	_ = self.Signal(syscall.SIGTERM)

	select {
	case err := <-done:
		// Context cancel due to signal is expected.
		t.Logf("serve exited: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("serve did not exit after SIGTERM")
	}
}
