package injector_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/clawinfra/clawkeyring/internal/injector"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHTTPClient records requests and returns preconfigured responses.
type mockHTTPClient struct {
	requests  []mockRequest
	responses []mockResponse
	callCount int
}

type mockRequest struct {
	url         string
	contentType string
	body        []byte
}

type mockResponse struct {
	body       string
	statusCode int
	err        error
}

func (m *mockHTTPClient) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	b, _ := io.ReadAll(body)
	m.requests = append(m.requests, mockRequest{url: url, contentType: contentType, body: b})

	if m.callCount >= len(m.responses) {
		return nil, io.EOF
	}

	resp := m.responses[m.callCount]
	m.callCount++

	if resp.err != nil {
		return nil, resp.err
	}

	return &http.Response{
		StatusCode: resp.statusCode,
		Body:       io.NopCloser(strings.NewReader(resp.body)),
	}, nil
}

func successResponse() string {
	return `{"jsonrpc":"2.0","id":1,"result":null}`
}

func errorResponse(code int, msg string) string {
	return `{"jsonrpc":"2.0","id":1,"error":{"code":` +
		string(rune('0'+code%10)) + `,"message":"` + msg + `"}}`
}

func TestInsertKeySuccess(t *testing.T) {
	mock := &mockHTTPClient{
		responses: []mockResponse{
			{body: successResponse(), statusCode: 200},
		},
	}

	inj := injector.NewWithClient("http://localhost:9933", mock)
	rawKey := []byte("babe-secret-key-32bytesxxxxxxxxx")
	err := inj.InsertKey("babe", "0xpublic", rawKey)
	require.NoError(t, err)

	// rawKey should be zeroed.
	assert.Equal(t, make([]byte, len(rawKey)), rawKey)

	// Verify one request was made.
	require.Len(t, mock.requests, 1)
	assert.Equal(t, "http://localhost:9933", mock.requests[0].url)
	assert.Equal(t, "application/json", mock.requests[0].contentType)

	// Verify request body contains expected fields.
	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(mock.requests[0].body, &payload))
	assert.Equal(t, "author_insertKey", payload["method"])
}

func TestInsertKeyEmptyKeyType(t *testing.T) {
	mock := &mockHTTPClient{}
	inj := injector.NewWithClient("http://localhost:9933", mock)
	err := inj.InsertKey("", "0xpub", []byte("key"))
	assert.Error(t, err)
}

func TestInsertKeyEmptyRawKey(t *testing.T) {
	mock := &mockHTTPClient{}
	inj := injector.NewWithClient("http://localhost:9933", mock)
	err := inj.InsertKey("babe", "0xpub", []byte{})
	assert.Error(t, err)
}

func TestInsertKeyRPCError(t *testing.T) {
	mock := &mockHTTPClient{
		responses: []mockResponse{
			{body: `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"key already exists"}}`, statusCode: 200},
		},
	}
	inj := injector.NewWithClient("http://localhost:9933", mock)
	err := inj.InsertKey("babe", "0xpub", []byte("somekey"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "key already exists")
}

func TestInsertKeyHTTPError(t *testing.T) {
	mock := &mockHTTPClient{
		responses: []mockResponse{
			{err: io.ErrUnexpectedEOF},
		},
	}
	inj := injector.NewWithClient("http://localhost:9933", mock)
	err := inj.InsertKey("babe", "0xpub", []byte("somekey"))
	assert.Error(t, err)
}

func TestInsertKeyMalformedResponse(t *testing.T) {
	mock := &mockHTTPClient{
		responses: []mockResponse{
			{body: "not json", statusCode: 200},
		},
	}
	inj := injector.NewWithClient("http://localhost:9933", mock)
	err := inj.InsertKey("babe", "0xpub", bytes.Repeat([]byte{1}, 10))
	assert.Error(t, err)
}

func TestNew(t *testing.T) {
	inj := injector.New("http://localhost:9933")
	assert.NotNil(t, inj)
}
