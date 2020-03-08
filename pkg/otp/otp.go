/*
Package otp is a simple fecade over the `github.com/xlzd/gotp` library, which
implement the HOTP and TOPT standard
*/
package otp

import (
	"strings"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
)

// TOTP represent an TOTP account
type TOTP struct {
	gotp.TOTP
}

// NewTOTP create a new TOTP engine. `secret` is the OTP device secret and is
// unique for every account
func NewTOTP(secret string) *TOTP {
	return &TOTP{
		*gotp.NewDefaultTOTP(secret),
	}
}

// Verify control is the passed `otp` is valid or not
func (totp *TOTP) Verify(otp string) bool {
	cleanOtp := strings.ReplaceAll(otp, " ", "")
	return totp.Now() == cleanOtp
}

// GetQRCodeAsPNG create a new PNG file (256x256) with the QR code that should
// be read by a mobile device to create the account
func (totp *TOTP) GetQRCodeAsPNG(accountName string, issuerName string) ([]byte, error) {
	return qrcode.Encode(totp.ProvisioningUri(accountName, issuerName), qrcode.Medium, 256)
}

// CreateRandomSecret create a secret that can be used to power a TOTP device
func CreateRandomSecret() string {
	return gotp.RandomSecret(32)
}
