// Package server implements the mTLS gRPC server for key operations.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
)

// KeyringServiceServer is the gRPC service handler interface.
// Implementations provide key operation endpoints.
type KeyringServiceServer interface {
	// ListKeys returns metadata for all stored keys.
	ListKeys(ctx context.Context, req *ListKeysRequest) (*ListKeysResponse, error)
	// GetStatus returns the current keyring status.
	GetStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error)
}

// ListKeysRequest is the request for ListKeys.
type ListKeysRequest struct{}

// ListKeysResponse is the response for ListKeys.
type ListKeysResponse struct {
	Keys []keyring.KeyEntry `json:"keys"`
}

// StatusRequest is the request for GetStatus.
type StatusRequest struct{}

// StatusResponse is the response for GetStatus.
type StatusResponse struct {
	Keys        []keyring.KeyEntry      `json:"keys"`
	LastRotation *keyring.RotationRecord `json:"last_rotation,omitempty"`
	LastEra     uint32                  `json:"last_era"`
	AgentPubKey string                  `json:"agent_pub_key"`
}

// Config holds server configuration.
type Config struct {
	// Addr is the listen address, e.g. "127.0.0.1:9090".
	Addr string
	// CertFile is the path to the server TLS certificate.
	CertFile string
	// KeyFile is the path to the server TLS private key.
	KeyFile string
	// CAFile is the path to the CA certificate for client verification.
	CAFile string
}

// RotationProvider provides rotation state to the server.
type RotationProvider interface {
	LastRotation() *keyring.RotationRecord
	LastEra() uint32
}

// Server is the mTLS gRPC server.
type Server struct {
	cfg      Config
	ks       *keystore.Keystore
	rotation RotationProvider
	grpc     *grpc.Server
	logger   *slog.Logger
}

// New creates a new Server. Call Serve to start listening.
func New(cfg Config, ks *keystore.Keystore, rotation RotationProvider) (*Server, error) {
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("server: TLS config: %w", err)
	}

	creds := credentials.NewTLS(tlsCfg)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	reflection.Register(grpcServer)

	s := &Server{
		cfg:      cfg,
		ks:       ks,
		rotation: rotation,
		grpc:     grpcServer,
		logger:   slog.Default(),
	}

	return s, nil
}

// NewInsecure creates a server without TLS (for testing only).
func NewInsecure(addr string, ks *keystore.Keystore, rotation RotationProvider) *Server {
	grpcServer := grpc.NewServer()
	reflection.Register(grpcServer)
	return &Server{
		cfg:      Config{Addr: addr},
		ks:       ks,
		rotation: rotation,
		grpc:     grpcServer,
		logger:   slog.Default(),
	}
}

// Serve starts accepting gRPC connections. Blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:9090"
	}

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("server: listen %s: %w", addr, err)
	}

	s.logger.Info("gRPC server listening", "addr", addr)

	errCh := make(chan error, 1)
	go func() {
		if err := s.grpc.Serve(lis); err != nil {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		s.grpc.GracefulStop()
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// ListKeys returns metadata for all stored keys.
func (s *Server) ListKeys(_ context.Context, _ *ListKeysRequest) (*ListKeysResponse, error) {
	entries, err := s.ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("server: list keys: %w", err)
	}
	return &ListKeysResponse{Keys: entries}, nil
}

// GetStatus returns the current keyring status.
func (s *Server) GetStatus(ctx context.Context, _ *StatusRequest) (*StatusResponse, error) {
	entries, err := s.ks.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("server: list keys: %w", err)
	}

	resp := &StatusResponse{
		Keys:        entries,
		AgentPubKey: s.ks.PublicKey(),
	}
	if s.rotation != nil {
		resp.LastRotation = s.rotation.LastRotation()
		resp.LastEra = s.rotation.LastEra()
	}
	return resp, nil
}

// GRPCServer returns the underlying gRPC server (for registration of additional services).
func (s *Server) GRPCServer() *grpc.Server { return s.grpc }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.cfg.Addr }

// ---- helpers ----------------------------------------------------------------

func validateConfig(cfg Config) error {
	if cfg.Addr == "" {
		return fmt.Errorf("server: addr must not be empty")
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" || cfg.CAFile != "" {
		// If any TLS file is set, all must be set.
		if cfg.CertFile == "" || cfg.KeyFile == "" || cfg.CAFile == "" {
			return fmt.Errorf("server: cert, key, and ca must all be set for mTLS")
		}
	}
	return nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load cert/key: %w", err)
	}

	caPEM, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// NoopRotation is a RotationProvider that always returns nil/0.
// Useful as a default when no rotation manager is configured.
type NoopRotation struct{}

// LastRotation always returns nil.
func (n *NoopRotation) LastRotation() *keyring.RotationRecord { return nil }

// LastEra always returns 0.
func (n *NoopRotation) LastEra() uint32 { return 0 }

// Ensure compile-time interface satisfaction.
var _ RotationProvider = (*NoopRotation)(nil)
var _ = time.Now // keep time import used
