/*
Package crypto implements a symmetric encryption scheme to be used by the
engine.

The algorithm used is AES-256, and for this reason we need a 32 bit key length
to operate correctly.

As far as the CBC implementation is concerned, you can look here:

https://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64

Stackoverflow? Really? Yes.

IMPORTANT: this package don't implement any soft of HMAC-based message signing,
meaning that if the key is not correct, your decoded text simply will not be
correct. No error detected in that case.
*/
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypt the proposed data with the given key. The output string
// will be hex encoded
func Encrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Encrypt cipher allocation: %v", err)
	}

	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, fmt.Errorf("Encrypt IV generation: %v", err)
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(cipherText[aes.BlockSize:], []byte(data))
	return cipherText, nil
}

// Decrypt works on the proposed data, returning an error is the proposed
// key is not correct
func Decrypt(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("Decrypt cipher allocation: %v", err)
	}

	if len(data) < aes.BlockSize {
		return nil, fmt.Errorf("Decrypt: too small ciphertext, no space for the initial vector")
	}

	iv := data[:aes.BlockSize]
	text := data[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)

	destination := make([]byte, len(data)-aes.BlockSize)
	cfb.XORKeyStream(destination, text)

	return destination, nil
}
