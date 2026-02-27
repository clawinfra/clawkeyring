// Package audit submits key operation records to the agent-receipts pallet
// on ClawChain, providing an immutable on-chain audit trail.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/clawinfra/clawkeyring/pkg/keyring"
)

// Submitter is the interface for submitting audit records on-chain.
// In production this wraps go-substrate-rpc-client; in tests it can be mocked.
type Submitter interface {
	// SubmitAuditRecord sends the record to the agent-receipts pallet.
	// Returns the transaction hash or an error.
	SubmitAuditRecord(record keyring.AuditRecord) (string, error)

	// QueryAuditRecords returns audit records for the given agent account.
	QueryAuditRecords(agent string, limit int) ([]keyring.AuditRecord, error)
}

// Logger records key operations to the on-chain agent-receipts pallet.
type Logger struct {
	submitter Submitter
	agent     string
}

// New creates a new Logger using the given submitter and agent account ID.
func New(submitter Submitter, agent string) *Logger {
	return &Logger{submitter: submitter, agent: agent}
}

// LogOperation records a key operation on-chain.
// keyTypes is the list of key types affected; operation is the OperationKind.
// Returns the transaction hash.
func (l *Logger) LogOperation(op keyring.OperationKind, keyTypes []keyring.KeyType, era uint32) (string, error) {
	names := make([]string, len(keyTypes))
	for i, kt := range keyTypes {
		names[i] = string(kt)
	}

	opStr := string(op) + ":" + joinStrings(names, ",")
	now := time.Now().UTC()

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s:%s:%d:%d", l.agent, opStr, era, now.UnixMilli())))
	hash := hex.EncodeToString(h.Sum(nil))

	record := keyring.AuditRecord{
		Agent:     l.agent,
		Operation: opStr,
		Era:       era,
		Timestamp: now.UnixMilli(),
		Hash:      hash,
	}

	txHash, err := l.submitter.SubmitAuditRecord(record)
	if err != nil {
		return "", fmt.Errorf("audit: submit record: %w", err)
	}
	return txHash, nil
}

// GetAuditLog returns the audit log for the logger's agent account.
func (l *Logger) GetAuditLog(limit int) ([]keyring.AuditRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	records, err := l.submitter.QueryAuditRecords(l.agent, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: query records: %w", err)
	}
	return records, nil
}

// Agent returns the on-chain account ID used for audit records.
func (l *Logger) Agent() string { return l.agent }

// NoopSubmitter is a Submitter that discards all records (for testing/offline use).
type NoopSubmitter struct {
	Records []keyring.AuditRecord
}

// SubmitAuditRecord stores the record in memory and returns a fake tx hash.
func (n *NoopSubmitter) SubmitAuditRecord(record keyring.AuditRecord) (string, error) {
	n.Records = append(n.Records, record)
	h := sha256.Sum256([]byte(record.Hash))
	return "0x" + hex.EncodeToString(h[:]), nil
}

// QueryAuditRecords returns the in-memory records.
func (n *NoopSubmitter) QueryAuditRecords(agent string, limit int) ([]keyring.AuditRecord, error) {
	var out []keyring.AuditRecord
	for _, r := range n.Records {
		if r.Agent == agent {
			out = append(out, r)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func joinStrings(ss []string, sep string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += sep
		}
		result += s
	}
	return result
}
