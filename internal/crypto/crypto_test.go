package crypto

import (
	"bytes"
	"crypto/aes"
	"testing"
)

var (
	testKey = []byte("this is a very really great keyz")
)

func TestEncryptionInvalidKeyLen(t *testing.T) {
	_, err := Encrypt([]byte("ehi"), []byte("key"))
	if err == nil {
		t.Fail()
	}
}

func TestEncryption(t *testing.T) {
	plainText := []byte("my good data")
	data, err := Encrypt(plainText, testKey)
	if err != nil {
		t.Error(err)
	}

	if len(data) != (len(plainText) + aes.BlockSize) {
		t.Errorf("Invalid initial vector allocation %v", data)
	}
}

func TestEncryptDecrypt(t *testing.T) {
	plainText := []byte("my good data")
	cipherText, err := Encrypt(plainText, testKey)
	if err != nil {
		t.Error(err)
	}

	decodedText, err := Decrypt(cipherText, testKey)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(plainText, decodedText) {
		t.Errorf("Uff, I lost something: %v vs %v", plainText, cipherText)
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	plainText := []byte("my good data")
	cipherText, err := Encrypt(plainText, testKey)
	if err != nil {
		t.Error(err)
	}

	decodedText, err := Decrypt(cipherText, []byte("this key is not so nice, even so"))
	if err != nil {
		t.Error(err)
	}

	if bytes.Equal(plainText, decodedText) {
		t.Errorf("Uff, I decoded with a different key? %v", plainText)
	}
}

func BenchmarkEncrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		plainText := []byte("my good data")
		_, _ = Encrypt(plainText, testKey)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		cipherText := []byte("my ciphered data")
		_, _ = Decrypt(cipherText, testKey)
	}
}
