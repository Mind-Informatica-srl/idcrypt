/*
Package models implement the models for the data needed by the
encryption/decryption engine.
*/
package models

/*
CredentialRecord is the record containing the information about
the password of a certain user. There could be many passwords for
an user, and this is useful to prevent reusing of an old password
while implementing a password change facility.
*/
type CredentialRecord struct {
	// This is reference to the actual user
	UserID int

	// This is the hash of the password, hexadecimal encoded
	EncryptedPasswordKey string

	// This is the salt of the password, hexadecimal encoded
	EncryptedPasswordSalt string

	// This is the system master key, encrypted using the current
	// password
	EncryptedMasterKey string
}

// NewCredentialRecord generates a new CredentialRecord given the passed
// parameters, encrypting the credentials as needed
func NewCredentialRecord(userID int, password string, masterKey string) {

}
