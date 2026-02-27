package server_test

import (
	"context"
	"testing"
	"time"

	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/internal/server"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRotation struct {
	lastRotation *keyring.RotationRecord
	lastEra      uint32
}

func (m *mockRotation) LastRotation() *keyring.RotationRecord { return m.lastRotation }
func (m *mockRotation) LastEra() uint32                       { return m.lastEra }

func TestNewInvalidConfigEmptyAddr(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	// Missing addr.
	_, err = server.New(server.Config{}, ks, nil)
	assert.Error(t, err)
}

func TestNewInvalidConfigPartialTLS(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	// Partial TLS config (cert but no key).
	_, err = server.New(server.Config{Addr: "127.0.0.1:9090", CertFile: "c.pem"}, ks, nil)
	assert.Error(t, err)
}

func TestNewValidConfigNoTLS(t *testing.T) {
	// A config with addr only (no TLS) should fail on New() because
	// buildTLSConfig won't be called (no cert files), but New requires TLS.
	// Per current implementation, without TLS files, New fails at TLS loading.
	// Use NewInsecure for non-TLS.
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	// Addr-only config with no TLS files causes TLS build to be skipped,
	// but validateConfig passes. New then tries to build TLS and fails on missing files.
	_, err = server.New(server.Config{Addr: "127.0.0.1:9090", CertFile: "a.pem", KeyFile: "b.pem", CAFile: "c.pem"}, ks, nil)
	// Files don't exist — should fail.
	assert.Error(t, err)
}

func TestNewInsecure(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	s := server.NewInsecure("127.0.0.1:0", ks, &mockRotation{})
	assert.NotNil(t, s)
	assert.Equal(t, "127.0.0.1:0", s.Addr())
}

func TestServeAndStop(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	s := server.NewInsecure("127.0.0.1:0", ks, &mockRotation{})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Serve(ctx)
	}()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("server did not stop after context cancellation")
	}
}

func TestListKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	s := server.NewInsecure("127.0.0.1:0", ks, &mockRotation{})

	resp, err := s.ListKeys(context.Background(), &server.ListKeysRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Keys)
}

func TestListKeysWithKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("babe-key-32-bytes-padding-xxxxxxx"), "0xbabe")

	s := server.NewInsecure("127.0.0.1:0", ks, &mockRotation{})
	resp, err := s.ListKeys(context.Background(), &server.ListKeysRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 1)
	assert.Equal(t, keyring.KeyTypeBABE, resp.Keys[0].Type)
}

func TestGetStatus(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	rotation := &mockRotation{
		lastEra: 42,
		lastRotation: &keyring.RotationRecord{
			Era:       42,
			Timestamp: time.Now(),
		},
	}

	s := server.NewInsecure("127.0.0.1:0", ks, rotation)
	resp, err := s.GetStatus(context.Background(), &server.StatusRequest{})
	require.NoError(t, err)
	assert.Equal(t, uint32(42), resp.LastEra)
	assert.NotNil(t, resp.LastRotation)
	assert.NotEmpty(t, resp.AgentPubKey)
}

func TestGetStatusNoRotation(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	s := server.NewInsecure("127.0.0.1:0", ks, nil)
	resp, err := s.GetStatus(context.Background(), &server.StatusRequest{})
	require.NoError(t, err)
	assert.Nil(t, resp.LastRotation)
	assert.Equal(t, uint32(0), resp.LastEra)
}

func TestGRPCServer(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	s := server.NewInsecure("127.0.0.1:0", ks, &mockRotation{})
	assert.NotNil(t, s.GRPCServer())
}

func TestNoopRotation(t *testing.T) {
	noop := &server.NoopRotation{}
	assert.Nil(t, noop.LastRotation())
	assert.Equal(t, uint32(0), noop.LastEra())
}

func TestNewWithValidTLSCerts(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	certDir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, certDir)

	s, err := server.New(server.Config{
		Addr:     "127.0.0.1:0",
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, ks, &mockRotation{})
	require.NoError(t, err)
	assert.NotNil(t, s)
}

func TestNewWithTLSCertsAndServe(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	certDir := t.TempDir()
	certFile, keyFile, caFile := generateTestCerts(t, certDir)

	s, err := server.New(server.Config{
		Addr:     "127.0.0.1:0",
		CertFile: certFile,
		KeyFile:  keyFile,
		CAFile:   caFile,
	}, ks, &mockRotation{})
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- s.Serve(ctx) }()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.DeadlineExceeded)
	case <-time.After(1 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestValidateConfigMissingCAFile(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	// cert + key but no CA
	_, err = server.New(server.Config{Addr: "127.0.0.1:9090", CertFile: "c.pem", KeyFile: "k.pem"}, ks, nil)
	assert.Error(t, err)
}

func TestGetStatusWithRotationAndKeys(t *testing.T) {
	dir := t.TempDir()
	ks, err := keystore.Init(dir)
	require.NoError(t, err)

	_ = ks.StoreKey(keyring.KeyTypeBABE, []byte("babe-key-32-bytes-padding-xxxxxxx"), "0xbabe")
	_ = ks.StoreKey(keyring.KeyTypeGRANDPA, []byte("gran-key-32-bytes-padding-xxxxxxx"), "0xgran")

	rot := &mockRotation{
		lastEra: 7,
		lastRotation: &keyring.RotationRecord{
			Era:       7,
			Timestamp: time.Now(),
			Keys:      []keyring.KeyEntry{{Type: keyring.KeyTypeBABE}},
			TxHash:    "0xdeadbeef",
		},
	}
	s := server.NewInsecure("127.0.0.1:0", ks, rot)
	resp, err := s.GetStatus(context.Background(), &server.StatusRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 2)
	assert.Equal(t, uint32(7), resp.LastEra)
	assert.Equal(t, "0xdeadbeef", resp.LastRotation.TxHash)
}
