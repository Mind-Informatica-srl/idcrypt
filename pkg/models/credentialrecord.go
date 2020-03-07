/*
Package models implement the models for the data needed by the
encryption/decryption engine.
*/
package models

import (
	"encoding/hex"
	"fmt"

	"bitbucket.org/leonardoce/idcrypt/internal/cryptico"
	"bitbucket.org/leonardoce/idcrypt/internal/hash"
	"bitbucket.org/leonardoce/idcrypt/internal/keygen"
	"bitbucket.org/leonardoce/idcrypt/internal/utils"
)

/*
CredentialRecord is the record containing the information about
the password of a certain user. There could be many passwords for
an user, and this is useful to prevent reusing of an old password
while implementing a password change facility.

Every system should also implement a password expiry mechanism and
also a temporary password mechanism too.
*/
type CredentialRecord struct {
	// This is the hash of the password, hexadecimal encoded
	EncryptedPassword string

	// This is the system master key, encrypted using the current
	// password
	EncryptedMasterKey string

	// The salt used to generate the encryption key for the master key
	EncryptedMasterKeySalt string
}

// NewCredentialRecord generates a new CredentialRecord given the passed
// parameters, encrypting the credentials as needed
func NewCredentialRecord(password string, masterKey []byte) (*CredentialRecord, error) {
	encryptedPassword, err := hash.Crypt([]byte(password))
	if err != nil {
		return nil, fmt.Errorf("NewCredentialRecord: %v", err)
	}

	salt, err := utils.GenerateSalt(12)
	if err != nil {
		return nil, fmt.Errorf("NewCredentialRecord: %v", err)
	}

	sessionKey := keygen.GenerateKey([]byte(password), 32, salt)
	if err != nil {
		return nil, fmt.Errorf("NewCredentialRecord: %v", err)
	}

	encryptedMasterKey, err := cryptico.Encrypt([]byte(masterKey), sessionKey)
	if err != nil {
		return nil, fmt.Errorf("NewCredentialRecord: %v", err)
	}

	return &CredentialRecord{
		EncryptedPassword:      hex.EncodeToString(encryptedPassword),
		EncryptedMasterKey:     hex.EncodeToString(encryptedMasterKey),
		EncryptedMasterKeySalt: hex.EncodeToString(salt),
	}, nil
}

// IsPasswordValid check if a certain password is valid and can be used to
// decrypt the master key
func (credential *CredentialRecord) IsPasswordValid(password string) (bool, error) {
	encryptedPassword, err := hex.DecodeString(credential.EncryptedPassword)
	if err != nil {
		return false, fmt.Errorf("IsPasswordValid, invalid hash. %v", err)
	}

	return hash.Check([]byte(password), encryptedPassword)
}

// RecoverMasterKey get the master key given the user's password, it the
// password is valid. The user is supposed to call IsPasswordValid before
// calling this function
func (credential *CredentialRecord) RecoverMasterKey(password string) ([]byte, error) {
	salt, err := hex.DecodeString(credential.EncryptedMasterKeySalt)
	if err != nil {
		return nil, fmt.Errorf("RecoverMasterKey, wrong salt in credential: %v", err)
	}

	encryptedMasterKey, err := hex.DecodeString(credential.EncryptedMasterKey)
	if err != nil {
		return nil, fmt.Errorf("RecoverMasterKey, cannot decode encrypted master key: %v", err)
	}

	sessionKey := keygen.GenerateKey([]byte(password), 32, salt)
	masterKey, err := cryptico.Decrypt(encryptedMasterKey, sessionKey)
	if err != nil {
		return nil, fmt.Errorf("RecoverMasterKey, cannot decode master key: %v", err)
	}

	return masterKey, nil
}
