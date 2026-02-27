package rotation_test

import (
	"context"
	"fmt"
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

// mockEraSubscriber emits eras from a channel.
type mockEraSubscriber struct {
	eras chan uint32
}

func (m *mockEraSubscriber) Subscribe(_ context.Context) (<-chan uint32, error) {
	return m.eras, nil
}

// mockKeyGenerator returns fixed key material.
type mockKeyGenerator struct {
	keys    map[keyring.KeyType][]byte
	pubKeys map[keyring.KeyType]string
	err     error
}

func (m *mockKeyGenerator) RotateKeys() (map[keyring.KeyType][]byte, map[keyring.KeyType]string, error) {
	if m.err != nil {
		return nil, nil, m.err
	}
	return m.keys, m.pubKeys, nil
}

// successHTTPClient returns a successful JSON-RPC response.
type successHTTPClient struct{}

func (s *successHTTPClient) Post(_ string, _ string, _ io.Reader) (*http.Response, error) {
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":null}`)),
	}, nil
}

func TestManagerRotate(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	gen := &mockKeyGenerator{
		keys: map[keyring.KeyType][]byte{
			keyring.KeyTypeBABE:    []byte("babe-key-32-bytes-padding-xxxxxxx"),
			keyring.KeyTypeGRANDPA: []byte("gran-key-32-bytes-padding-xxxxxxx"),
		},
		pubKeys: map[keyring.KeyType]string{
			keyring.KeyTypeBABE:    "0xbabe",
			keyring.KeyTypeGRANDPA: "0xgran",
		},
	}

	mgr := rotation.New(ks, inj, auditLogger, nil, gen, rotation.DefaultConfig())
	record, err := mgr.Rotate(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, uint32(5), record.Era)
	assert.NotEmpty(t, record.Keys)
	assert.Equal(t, record, mgr.LastRotation())
}

func TestManagerRotateNoGenerator(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	mgr := rotation.New(ks, inj, auditLogger, nil, nil, rotation.DefaultConfig())
	_, err = mgr.Rotate(context.Background(), 1)
	assert.Error(t, err)
}

func TestManagerRotateGeneratorError(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	gen := &mockKeyGenerator{err: fmt.Errorf("node unavailable")}
	mgr := rotation.New(ks, inj, auditLogger, nil, gen, rotation.DefaultConfig())
	_, err = mgr.Rotate(context.Background(), 1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "node unavailable")
}

func TestManagerRunAutoDisabled(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	cfg := rotation.Config{AutoRotate: false}
	mgr := rotation.New(ks, inj, auditLogger, nil, nil, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err = mgr.Run(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestManagerRunEraSubscription(t *testing.T) {
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

	erasCh := make(chan uint32, 3)
	erasCh <- 1

	eraSubscriber := &mockEraSubscriber{eras: erasCh}
	cfg := rotation.Config{AutoRotate: true, MinErasBetweenRotations: 0}
	mgr := rotation.New(ks, inj, auditLogger, eraSubscriber, gen, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()

	_ = mgr.Run(ctx)
	// Should have rotated at least once (era 1).
	assert.NotNil(t, mgr.LastRotation())
}

func TestManagerLastEra(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)
	sub := &audit.NoopSubmitter{}
	auditLogger := audit.New(sub, "test-agent")
	inj := injector.NewWithClient("http://localhost:9933", &successHTTPClient{})

	mgr := rotation.New(ks, inj, auditLogger, nil, nil, rotation.DefaultConfig())
	assert.Equal(t, uint32(0), mgr.LastEra())
}
