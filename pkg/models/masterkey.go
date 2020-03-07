package models

import "bitbucket.org/leonardoce/idcrypt/internal/utils"

// GenerateMasterKey create a new crypto space.
func GenerateMasterKey() ([]byte, error) {
	return utils.GenerateSalt(32)
}
