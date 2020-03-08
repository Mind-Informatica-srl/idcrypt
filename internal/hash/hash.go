/*
Package hash implements the function relative to the one-way hashing features
needed by the crypto engine, using the PBKDF2 key derivation function
*/
package hash

import (
	"bytes"
	"errors"

	"bitbucket.org/leonardoce/idcrypt/internal/keygen"
	"bitbucket.org/leonardoce/idcrypt/internal/utils"
)

const (
	pbkdf2KeyLen = 32
	saltLen      = 16
)

var (
	// ErrorInvalidHash is returned when the passed hash isn't in the right
	// format
	ErrorInvalidHash = errors.New("invalid hash")
)

// Crypt one-way crypt the proposed data, returning it encrypted. 'Check' can
// then be used to verify if the hash is correct or not. The first section of
// the output bytes are the salt, the other one is the encrypted data
func Crypt(data []byte) ([]byte, error) {
	salt, err := utils.GenerateSalt(saltLen)
	if err != nil {
		return nil, err
	}

	key := keygen.GenerateKey(data, pbkdf2KeyLen, salt)

	result := make([]byte, saltLen+pbkdf2KeyLen)
	copy(result, salt)
	copy(result[saltLen:], key)
	return result, nil
}

// Check checks if the passed data corresponds to the one that was previously
// hashed via the Hash function
func Check(data []byte, hash []byte) (bool, error) {
	if len(hash) != (saltLen + pbkdf2KeyLen) {
		return false, ErrorInvalidHash
	}

	salt := hash[:saltLen]
	key := hash[saltLen:]
	providedKey := keygen.GenerateKey(data, pbkdf2KeyLen, salt)
	return bytes.Equal(key, providedKey), nil
}
