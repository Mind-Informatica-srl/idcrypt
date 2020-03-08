/*
Package jwt implement a JWT facility that can be used to safely pass session
authentication information. This implementation is focused on a two-secret
authentication scheme.

The session is viewed as a temporary credential, generated from the masterKey
recovered from the main account, which username is stored in the database.

The password is passed to the client, called "sharedSecret", and is used to
recover the master key from the credential record.
*/
package jwt

import (
	"crypto/rsa"
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// Engine represent a JWT signing configuration
type Engine struct {
	// The function to use to extract the current timestamp, stored here since
	// it's useful to inject a mock one during the unit tests
	NowFunc func() time.Time

	// The private key, used to sign a token
	PrivateKey *rsa.PrivateKey

	// The public key, used to verify a token
	PublicKey *rsa.PublicKey

	// The token duration
	TokenDuration time.Duration
}

// CreateEngine create a new JWT signing engine with a key pair encoded in PEM
// format. Beware that the private key must have no passphrase protection, and
// need to be stored securely.
func CreateEngine(privateKeyBytes []byte, publicKeyBytes []byte, tokenDuration time.Duration) (*Engine, error) {
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CreateEngine, error decoding private key: %v", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("CreateEngine, error decoding public key: %v", err)
	}

	return &Engine{
		NowFunc:       time.Now,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		TokenDuration: tokenDuration,
	}, nil
}

// CustomClaims is the structure with the claims inside this JWT token.
type CustomClaims struct {
	SharedSecret string `json:"sharedSecret"`
	jwt.StandardClaims
}

// CreateCustomClaims create our custom set of claims
func (e *Engine) CreateCustomClaims(subject string, sharedSecret string) *CustomClaims {
	expiration := e.NowFunc().Add(e.TokenDuration).Unix()
	return &CustomClaims{
		SharedSecret: sharedSecret,
		StandardClaims: jwt.StandardClaims{
			Subject:   subject,
			ExpiresAt: expiration,
		},
	}
}

// CreateJWT create a new JWT and sign it with the given parameters
func (e *Engine) CreateJWT(subject string, sharedSecret string) (string, error) {
	claims := e.CreateCustomClaims(subject, sharedSecret)
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(e.PrivateKey)
}

// ParseJWT parse and validate a token and gets the claims
func (e *Engine) ParseJWT(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, e.keyFunc)
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("wrong claims")
}

func (e *Engine) keyFunc(token *jwt.Token) (interface{}, error) {
	var method *jwt.SigningMethodRSA
	var ok bool

	if method, ok = token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("token has wrong signing method")
	}

	if method != jwt.SigningMethodRS512 {
		return nil, fmt.Errorf("signing method has wrong density")
	}

	return e.PublicKey, nil
}
