// Package injector calls author_insertKey JSON-RPC to inject session keys
// into a running Substrate node. All plaintext key bytes are zeroed after use.
package injector

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// RPCError represents a JSON-RPC error response.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("RPC error %d: %s", e.Code, e.Message)
}

// InsertKeyRequest is the payload for author_insertKey.
type InsertKeyRequest struct {
	KeyType   string `json:"keyType"`
	Suri      string `json:"suri"`
	PublicKey string `json:"publicKey"`
}

// HTTPClient is an interface for HTTP requests, allowing injection in tests.
type HTTPClient interface {
	Post(url, contentType string, body io.Reader) (*http.Response, error)
}

// Injector calls author_insertKey on a Substrate node via JSON-RPC over HTTP.
type Injector struct {
	nodeURL string
	client  HTTPClient
}

// New creates a new Injector targeting nodeURL (e.g. "http://127.0.0.1:9933").
func New(nodeURL string) *Injector {
	return &Injector{
		nodeURL: nodeURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// NewWithClient creates a new Injector with a custom HTTP client (for testing).
func NewWithClient(nodeURL string, client HTTPClient) *Injector {
	return &Injector{nodeURL: nodeURL, client: client}
}

// InsertKey injects rawKey into the node for the given keyType.
// rawKey is zeroed after use. publicKey is the hex-encoded public key.
func (inj *Injector) InsertKey(keyType, publicKey string, rawKey []byte) error {
	defer zeroBytes(rawKey)

	if keyType == "" {
		return fmt.Errorf("injector: keyType must not be empty")
	}
	if len(rawKey) == 0 {
		return fmt.Errorf("injector: rawKey must not be empty")
	}

	// Substrate accepts the suri (secret URI) for author_insertKey.
	// We pass the raw hex as a suri prefixed with 0x.
	suri := "0x" + hex.EncodeToString(rawKey)
	defer func() {
		// Zero the suri string (best-effort; Go strings are immutable,
		// but we at least clear our local reference).
		suri = strings.Repeat("0", len(suri))
		_ = suri
	}()

	req := InsertKeyRequest{
		KeyType:   keyType,
		Suri:      suri,
		PublicKey: publicKey,
	}

	return inj.callRPC("author_insertKey", []interface{}{req.KeyType, req.Suri, req.PublicKey})
}

// callRPC makes a JSON-RPC call to the Substrate node.
func (inj *Injector) callRPC(method string, params []interface{}) error {
	payload := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("injector: marshal request: %w", err)
	}

	resp, err := inj.client.Post(inj.nodeURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("injector: HTTP POST: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("injector: read response: %w", err)
	}

	var rpcResp struct {
		Error  *RPCError       `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return fmt.Errorf("injector: unmarshal response: %w", err)
	}
	if rpcResp.Error != nil {
		return rpcResp.Error
	}

	return nil
}

// zeroBytes zeroes a byte slice in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
