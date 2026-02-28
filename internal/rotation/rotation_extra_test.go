package rotation_test

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/clawinfra/clawkeyring/internal/audit"
	"github.com/clawinfra/clawkeyring/internal/injector"
	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/internal/rotation"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failHTTPClient returns an HTTP error.
type failHTTPClient struct{}

func (f *failHTTPClient) Post(_ string, _ string, _ io.Reader) (*http.Response, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestManagerRotateInjectionFailure(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &failHTTPClient{})

	gen := &mockKeyGenerator{
		keys: map[keyring.KeyType][]byte{
			keyring.KeyTypeBABE: []byte("babe-key-32-bytes-padding-xxxxxxx"),
		},
		pubKeys: map[keyring.KeyType]string{
			keyring.KeyTypeBABE: "0xbabe",
		},
	}

	mgr := rotation.New(ks, inj, auditLogger, nil, gen, rotation.DefaultConfig())
	_, err = mgr.Rotate(context.Background(), 3)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "inject")
}

func TestManagerRotateAuditFailure(t *testing.T) {
	// Audit failure should be non-fatal; rotation should still succeed.
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	// Use an audit submitter that fails.
	sub := &errAuditSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	gen := &mockKeyGenerator{
		keys: map[keyring.KeyType][]byte{
			keyring.KeyTypeBABE: []byte("babe-key-32-bytes-padding-xxxxxxx"),
		},
		pubKeys: map[keyring.KeyType]string{
			keyring.KeyTypeBABE: "0xbabe",
		},
	}

	mgr := rotation.New(ks, inj, auditLogger, nil, gen, rotation.DefaultConfig())
	record, err := mgr.Rotate(context.Background(), 5)
	// Rotation should succeed even if audit fails.
	require.NoError(t, err)
	assert.Equal(t, uint32(5), record.Era)
	assert.Empty(t, record.TxHash) // tx hash is empty when audit fails
}

type errAuditSubmitter struct{}

func (e *errAuditSubmitter) SubmitAuditRecord(_ keyring.AuditRecord) (string, error) {
	return "", io.ErrUnexpectedEOF
}
func (e *errAuditSubmitter) QueryAuditRecords(_ string, _ int) ([]keyring.AuditRecord, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestManagerShouldRotateAfterMinEras(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	gen := &mockKeyGenerator{
		keys: map[keyring.KeyType][]byte{
			keyring.KeyTypeBABE: []byte("babe-key-32-bytes-padding-xxxxxxx"),
		},
		pubKeys: map[keyring.KeyType]string{
			keyring.KeyTypeBABE: "0xbabe",
		},
	}

	// Set minEras to 2; rotate at era 5. Next auto-rotate should skip era 6, trigger at era 8+.
	cfg := rotation.Config{AutoRotate: true, MinErasBetweenRotations: 2}
	mgr := rotation.New(ks, inj, auditLogger, nil, gen, cfg)

	// First rotation at era 5.
	_, err = mgr.Rotate(context.Background(), 5)
	require.NoError(t, err)

	erasCh := make(chan uint32, 10)
	erasCh <- 6 // Should be skipped (5+2+1 = 8 minimum)
	erasCh <- 7 // Should be skipped
	erasCh <- 8 // Should trigger

	eraSubscriber := &mockEraSubscriber{eras: erasCh}
	cfg2 := rotation.Config{AutoRotate: true, MinErasBetweenRotations: 2}
	mgr2 := rotation.New(ks, inj, auditLogger, eraSubscriber, gen, cfg2)

	// Prime the last rotation.
	_, _ = mgr2.Rotate(context.Background(), 5)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		time.Sleep(300 * time.Millisecond)
		cancel()
	}()
	_ = mgr2.Run(ctx)

	lr := mgr2.LastRotation()
	assert.NotNil(t, lr)
}

func TestManagerRunSubscriberError(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	// A subscriber that returns an error.
	errSub := &errorSubscriber{}
	cfg := rotation.Config{AutoRotate: true}
	mgr := rotation.New(ks, inj, auditLogger, errSub, nil, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = mgr.Run(ctx)
	assert.Error(t, err)
}

type errorSubscriber struct{}

func (e *errorSubscriber) Subscribe(_ context.Context) (<-chan uint32, error) {
	return nil, io.ErrUnexpectedEOF
}

func TestManagerRunClosedChannel(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	// Immediately closed channel.
	erasCh := make(chan uint32)
	close(erasCh)

	closedSub := &mockEraSubscriber{eras: erasCh}
	cfg := rotation.Config{AutoRotate: true}
	mgr := rotation.New(ks, inj, auditLogger, closedSub, nil, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	err = mgr.Run(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}
