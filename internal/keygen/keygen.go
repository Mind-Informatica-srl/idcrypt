/*
Package keygen implement a key generator feature, basing it on the
PBKDF2 scheme using SHA1 hash function
*/
package keygen

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

const (
	pbkdf2Iterations = 4096
)

// GenerateKey generate a session key for a certain password
func GenerateKey(password []byte, keyLen int, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keyLen, sha1.New)
}
