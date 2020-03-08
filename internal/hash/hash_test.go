package hash

import (
	"testing"
)

var (
	testPassword = []byte("thi$isAReally$afeP@ssw0rd")
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
	passwordHash, err := Crypt([]byte("foobar123"))
	if err != nil {
		t.Error(err)
	}

	res, err := Check([]byte("anotherPassword"), passwordHash)
	if err != nil {
		t.Error(err)
	}

	if res {
		t.Fail()
	}
}

func TestValidHash(t *testing.T) {
	passwordHash, err := Crypt(testPassword)
	if err != nil {
		t.Error(err)
	}

	res, err := Check(testPassword, passwordHash)
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
		_, _ = Crypt(testPassword)
	}
}

func BenchmarkCheck(b *testing.B) {
	passwordHash, err := Crypt([]byte("foobar123"))
	if err != nil {
		b.Error(err)
	}

	for n := 0; n < b.N; n++ {
		_, _ = Check(testPassword, passwordHash)
	}
}
