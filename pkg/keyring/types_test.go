package keyring_test

import (
	"testing"

	"github.com/clawinfra/clawkeyring/pkg/keyring"
	"github.com/stretchr/testify/assert"
)

func TestKeyTypeValid(t *testing.T) {
	assert.True(t, keyring.KeyTypeBABE.Valid())
	assert.True(t, keyring.KeyTypeGRANDPA.Valid())
	assert.True(t, keyring.KeyTypeImOnline.Valid())
	assert.False(t, keyring.KeyType("unknown").Valid())
	assert.False(t, keyring.KeyType("").Valid())
}

func TestKeyTypeCryptoScheme(t *testing.T) {
	assert.Equal(t, "sr25519", keyring.KeyTypeBABE.CryptoScheme())
	assert.Equal(t, "ed25519", keyring.KeyTypeGRANDPA.CryptoScheme())
	assert.Equal(t, "sr25519", keyring.KeyTypeImOnline.CryptoScheme())
}

func TestKeyTypeString(t *testing.T) {
	assert.Equal(t, "babe", keyring.KeyTypeBABE.String())
	assert.Equal(t, "gran", keyring.KeyTypeGRANDPA.String())
	assert.Equal(t, "imon", keyring.KeyTypeImOnline.String())
}

func TestAllKeyTypes(t *testing.T) {
	all := keyring.AllKeyTypes()
	assert.Len(t, all, 3)
	for _, kt := range all {
		assert.True(t, kt.Valid())
	}
}
