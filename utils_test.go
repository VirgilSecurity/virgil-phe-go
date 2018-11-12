package phe

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncrypt(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 365)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	plaintext, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, data)

}

func TestEncrypt_empty(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 0)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	plaintext, err := Decrypt(ciphertext, key)
	require.NoError(t, err)

	require.Equal(t, plaintext, data)

}

func TestEncrypt_badKey(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	data := make([]byte, 365)

	ciphertext, err := Encrypt(data, key)

	require.NoError(t, err)

	key[0]++

	plaintext, err := Decrypt(ciphertext, key)
	require.Error(t, err)
	require.Nil(t, plaintext)
}

func TestDecrypt_badLength(t *testing.T) {
	ct := make([]byte, 32+15)
	key := make([]byte, 32)
	rand.Read(key)
	plaintext, err := Decrypt(ct, key)

	require.Error(t, err)
	require.Equal(t, err.Error(), "invalid ciphertext length")
	require.Nil(t, plaintext)
}
