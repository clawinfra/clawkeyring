package audit_test

import (
	"fmt"
	"testing"

	"github.com/clawinfra/clawkeyring/internal/audit"
	"github.com/clawinfra/clawkeyring/pkg/keyring"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogOperation(t *testing.T) {
	sub := &audit.NoopSubmitter{}
	logger := audit.New(sub, "5GrwvaEF...")

	txHash, err := logger.LogOperation(keyring.OperationInject,
		[]keyring.KeyType{keyring.KeyTypeBABE, keyring.KeyTypeGRANDPA}, 42)
	require.NoError(t, err)
	assert.NotEmpty(t, txHash)
	assert.Contains(t, txHash, "0x")

	require.Len(t, sub.Records, 1)
	record := sub.Records[0]
	assert.Equal(t, "5GrwvaEF...", record.Agent)
	assert.Contains(t, record.Operation, "inject")
	assert.Contains(t, record.Operation, "babe")
	assert.Contains(t, record.Operation, "gran")
	assert.Equal(t, uint32(42), record.Era)
	assert.NotEmpty(t, record.Hash)
	assert.Greater(t, record.Timestamp, int64(0))
}

func TestLogRotate(t *testing.T) {
	sub := &audit.NoopSubmitter{}
	logger := audit.New(sub, "alice")

	_, err := logger.LogOperation(keyring.OperationRotate, keyring.AllKeyTypes(), 10)
	require.NoError(t, err)

	require.Len(t, sub.Records, 1)
	assert.Contains(t, sub.Records[0].Operation, "rotate")
}

func TestGetAuditLog(t *testing.T) {
	sub := &audit.NoopSubmitter{}
	logger := audit.New(sub, "agent1")

	for i := 0; i < 5; i++ {
		_, err := logger.LogOperation(keyring.OperationInject, []keyring.KeyType{keyring.KeyTypeBABE}, uint32(i))
		require.NoError(t, err)
	}

	records, err := logger.GetAuditLog(3)
	require.NoError(t, err)
	assert.Len(t, records, 3)
}

func TestGetAuditLogDefaultLimit(t *testing.T) {
	sub := &audit.NoopSubmitter{}
	logger := audit.New(sub, "agent1")

	records, err := logger.GetAuditLog(0)
	require.NoError(t, err)
	assert.Empty(t, records)
}

func TestGetAuditLogFiltersAgent(t *testing.T) {
	sub := &audit.NoopSubmitter{}

	logger1 := audit.New(sub, "agent1")
	logger2 := audit.New(sub, "agent2")

	_, _ = logger1.LogOperation(keyring.OperationInject, []keyring.KeyType{keyring.KeyTypeBABE}, 1)
	_, _ = logger2.LogOperation(keyring.OperationInject, []keyring.KeyType{keyring.KeyTypeBABE}, 2)
	_, _ = logger1.LogOperation(keyring.OperationRotate, []keyring.KeyType{keyring.KeyTypeGRANDPA}, 3)

	records, err := logger1.GetAuditLog(100)
	require.NoError(t, err)
	assert.Len(t, records, 2)
	for _, r := range records {
		assert.Equal(t, "agent1", r.Agent)
	}
}

func TestAgent(t *testing.T) {
	sub := &audit.NoopSubmitter{}
	logger := audit.New(sub, "my-agent")
	assert.Equal(t, "my-agent", logger.Agent())
}

func TestNoopSubmitterError(t *testing.T) {
	// Test with a custom submitter that returns an error.
	sub := &errSubmitter{err: fmt.Errorf("chain unavailable")}
	logger := audit.New(sub, "agent1")

	_, err := logger.LogOperation(keyring.OperationInject, []keyring.KeyType{keyring.KeyTypeBABE}, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chain unavailable")
}

type errSubmitter struct{ err error }

func (e *errSubmitter) SubmitAuditRecord(_ keyring.AuditRecord) (string, error) {
	return "", e.err
}
func (e *errSubmitter) QueryAuditRecords(_ string, _ int) ([]keyring.AuditRecord, error) {
	return nil, e.err
}
