package hash

import (
	"testing"
)

var (
	testPassword     = []byte("thi$isAReally$afeP@ssw0rd")
	testPasswordHash = []byte{189, 61, 179, 116, 137, 178, 104, 10, 155, 70, 95, 127, 69, 82, 248, 150, 248, 6, 183, 215, 234, 0, 9, 62, 61, 111, 226, 197, 22, 157, 105, 59, 1, 114, 129, 203, 216, 55, 193, 169, 156, 65, 239, 81, 170, 112, 142, 140}
)

func TestCrypt(t *testing.T) {
	hash, err := Crypt(testPassword)
	if err != nil {
		t.Error(err)
	}

	if len(hash) != (saltLen + pbkdf2KeyLen) {
		t.Errorf("This hash doesn't work: %v", hash)
	}
}

func TestCheckInvalidHash(t *testing.T) {
	_, err := Check(testPassword, []byte("wronghashhere"))
	if err == nil {
		t.Fail()
	}

	_, err = Check(testPassword, []byte("ASDASS"))
	if err == nil {
		t.Fail()
	}
}

func TestWrongHash(t *testing.T) {
	res, err := Check([]byte("anotherPassword"), testPasswordHash)
	if err != nil {
		t.Error(err)
	}

	if res {
		t.Fail()
	}
}

func TestValidHash(t *testing.T) {
	res, err := Check(testPassword, testPasswordHash)
	if err != nil {
		t.Error(err)
	}

	if !res {
		t.Fail()
	}
}

func TestCryptCheck(t *testing.T) {
	hash, err := Crypt(testPassword)
	if err != nil {
		t.Error(err)
	}

	if len(hash) != (saltLen + pbkdf2KeyLen) {
		t.Errorf("This hash doesn't work: %v", hash)
	}

	res, err := Check(testPassword, hash)
	if err != nil {
		t.Error(err)
	}

	if !res {
		t.Fail()
	}
}

func BenchmarkCrypt(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Crypt(testPassword)
	}
}

func BenchmarkCheck(b *testing.B) {
	for n := 0; n < b.N; n++ {
		Check(testPassword, testPasswordHash)
	}
}
