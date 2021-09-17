package idcrypt

import "github.com/Mind-Informatica-srl/idcrypt/internal/cryptico"

// Encrypt encrypts data via a master key
func Encrypt(data []byte, masterKey []byte) ([]byte, error) {
	return cryptico.Encrypt(data, masterKey)
}

// Decrypt encrypts data via a master key
func Decrypt(data []byte, masterKey []byte) ([]byte, error) {
	return cryptico.Decrypt(data, masterKey)
}
