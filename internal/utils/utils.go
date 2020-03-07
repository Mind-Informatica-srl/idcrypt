// Package utils collects some random crypt-related functions
// that are useful during the normal operation of the package
package utils

import (
	"crypto/rand"
	"io"
)

// GenerateSalt generate a cryptographically secure byte slice with the
// given len
func GenerateSalt(len int) ([]byte, error) {
	salt := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, salt)

	if err != nil {
		return nil, err
	}

	return salt[:], nil
}
