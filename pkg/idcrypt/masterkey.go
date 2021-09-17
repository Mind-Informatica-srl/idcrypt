package idcrypt

import "github.com/Mind-Informatica-srl/idcrypt/internal/utils"

// GenerateMasterKey create a new crypto space.
func GenerateMasterKey() ([]byte, error) {
	return utils.GenerateSalt(32)
}
