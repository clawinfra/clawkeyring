// Package rotation handles on-chain NewEra event subscription and triggers
// automated session key rotation.
package rotation

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/clawinfra/clawkeyring/internal/audit"
	"github.com/clawinfra/clawkeyring/internal/injector"
	"github.com/clawinfra/clawkeyring/internal/keystore"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
)

// EraSubscriber is the interface for subscribing to on-chain era events.
type EraSubscriber interface {
	// Subscribe returns a channel that emits the current era number
	// whenever a new era begins. The channel is closed when ctx is done.
	Subscribe(ctx context.Context) (<-chan uint32, error)
}

// KeyGenerator generates new session keys on the Substrate node.
type KeyGenerator interface {
	// RotateKeys asks the node to generate new session keys and returns
	// the raw key material per key type.
	RotateKeys() (map[keyring.KeyType][]byte, map[keyring.KeyType]string, error)
}

// Config holds the configuration for the rotation manager.
type Config struct {
	// AutoRotate enables automatic rotation on NewEra events.
	AutoRotate bool
	// MinErasBetweenRotations is the minimum number of eras between rotations.
	// 0 means rotate every era.
	MinErasBetweenRotations uint32
}

// DefaultConfig returns a sensible default rotation config.
func DefaultConfig() Config {
	return Config{
		AutoRotate:              true,
		MinErasBetweenRotations: 1,
	}
}

// Manager watches for NewEra events and rotates session keys.
type Manager struct {
	ks           *keystore.Keystore
	inj          *injector.Injector
	auditLogger  *audit.Logger
	subscriber   EraSubscriber
	generator    KeyGenerator
	cfg          Config
	mu           sync.RWMutex
	lastEra      uint32
	lastRotation *keyring.RotationRecord
	logger       *slog.Logger
}

// New creates a new rotation Manager.
func New(
	ks *keystore.Keystore,
	inj *injector.Injector,
	auditLogger *audit.Logger,
	subscriber EraSubscriber,
	generator KeyGenerator,
	cfg Config,
) *Manager {
	return &Manager{
		ks:          ks,
		inj:         inj,
		auditLogger: auditLogger,
		subscriber:  subscriber,
		generator:   generator,
		cfg:         cfg,
		logger:      slog.Default(),
	}
}

// Run starts watching for NewEra events and triggers rotation when appropriate.
// It blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if !m.cfg.AutoRotate {
		m.logger.Info("auto-rotation disabled; waiting for ctx cancellation")
		<-ctx.Done()
		return ctx.Err()
	}

	ch, err := m.subscriber.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("rotation: subscribe: %w", err)
	}

	m.logger.Info("rotation manager started; waiting for NewEra events")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case era, ok := <-ch:
			if !ok {
				return fmt.Errorf("rotation: era subscription closed")
			}
			m.mu.Lock()
			m.lastEra = era
			m.mu.Unlock()

			if m.shouldRotate(era) {
				m.logger.Info("NewEra: triggering key rotation", "era", era)
				if _, err := m.Rotate(ctx, era); err != nil {
					m.logger.Error("rotation failed", "era", era, "err", err)
				}
			} else {
				m.logger.Info("NewEra: skipping rotation (too soon)", "era", era)
			}
		}
	}
}

// Rotate performs a full key rotation: generate new keys, store, inject, audit.
func (m *Manager) Rotate(ctx context.Context, era uint32) (*keyring.RotationRecord, error) {
	if m.generator == nil {
		return nil, fmt.Errorf("rotation: no key generator configured")
	}

	rawKeys, pubKeys, err := m.generator.RotateKeys()
	if err != nil {
		return nil, fmt.Errorf("rotation: generate keys: %w", err)
	}

	var stored []keyring.KeyType
	for kt, raw := range rawKeys {
		pub := pubKeys[kt]
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)

		if err := m.ks.StoreKey(kt, rawCopy, pub); err != nil {
			return nil, fmt.Errorf("rotation: store %s: %w", kt, err)
		}
		stored = append(stored, kt)
	}

	// Inject new keys into node.
	for kt, raw := range rawKeys {
		pub := pubKeys[kt]
		rawCopy := make([]byte, len(raw))
		copy(rawCopy, raw)

		if err := m.inj.InsertKey(string(kt), pub, rawCopy); err != nil {
			return nil, fmt.Errorf("rotation: inject %s: %w", kt, err)
		}
	}

	// Zero original raw keys.
	for _, raw := range rawKeys {
		for i := range raw {
			raw[i] = 0
		}
	}

	// Log on-chain.
	txHash, err := m.auditLogger.LogOperation(keyring.OperationRotate, stored, era)
	if err != nil {
		// Non-fatal: rotation succeeded; audit failure is logged but not fatal.
		m.logger.Error("audit log failed", "err", err)
		txHash = ""
	}

	entries, _ := m.ks.ListKeys()
	record := &keyring.RotationRecord{
		Era:       era,
		Timestamp: time.Now().UTC(),
		Keys:      entries,
		TxHash:    txHash,
	}

	m.mu.Lock()
	m.lastRotation = record
	m.mu.Unlock()

	m.logger.Info("rotation complete", "era", era, "txHash", txHash, "keys", len(stored))
	return record, nil
}

// LastRotation returns the most recent rotation record, or nil if no rotation has occurred.
func (m *Manager) LastRotation() *keyring.RotationRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastRotation
}

// LastEra returns the most recently observed era.
func (m *Manager) LastEra() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastEra
}

func (m *Manager) shouldRotate(era uint32) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.lastRotation == nil {
		return true
	}
	return era >= m.lastRotation.Era+m.cfg.MinErasBetweenRotations+1
}
