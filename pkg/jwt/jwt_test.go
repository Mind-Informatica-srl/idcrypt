package jwt

import (
	"io/ioutil"
	"testing"
	"time"
)

func createTestEngine() (*Engine, error) {
	privateKey, err := ioutil.ReadFile("testdata/signing.key")
	if err != nil {
		return nil, err
	}

	publicKey, err := ioutil.ReadFile("testdata/signing.pub")
	if err != nil {
		return nil, err
	}

	data, err := CreateEngine(privateKey, publicKey, time.Hour*24)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func TestCreateEngine(t *testing.T) {
	_, err := createTestEngine()
	if err != nil {
		t.Fail()
	}
}

func TestGenerateToken(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	_, err = engine.CreateJWT("myself", "mygreatpassword")
	if err != nil {
		t.Error("Cannot create token", err)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	engine, err := createTestEngine()
	if err != nil {
		b.Fail()
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		_, _ = engine.CreateJWT("myself", "mygreatpassword")
	}
}

func TestClaims(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	claims := engine.CreateCustomClaims("subject", "sharedSecret")
	if claims.Subject != "subject" {
		t.Errorf("Wrong username: %v", claims.Subject)
	}
	if claims.SharedSecret != "sharedSecret" {
		t.Errorf("Wrong shared secret: %v", claims.SharedSecret)
	}
}

func TestParseJWT(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	tokenString, err := engine.CreateJWT("myself", "mygreatpassword")
	if err != nil {
		t.Error("Cannot create token", err)
	}

	claims, err := engine.ParseJWT(tokenString)
	if err != nil {
		t.Error("Cannot decode token", err)
	}

	if claims.SharedSecret != "mygreatpassword" {
		t.Errorf("Shared secret isn't preserved: %v", claims.SharedSecret)
	}

	if claims.Subject != "myself" {
		t.Errorf("Subject isn't preserved: %v", claims.Subject)
	}
}

func TestParseInvalidJWT(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	tokenString := "thisjwtisincredible"
	_, err = engine.ParseJWT(tokenString)
	if err == nil {
		t.Fail()
	}
}

func TestParseJWTInvalidAlgorithm(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	tokenString := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	_, err = engine.ParseJWT(tokenString)
	if err == nil {
		t.Fail()
	}
}

func TestParseJWTInvalidSigningInfo(t *testing.T) {
	engine, err := createTestEngine()
	if err != nil {
		t.Fail()
	}

	tokenString, err := engine.CreateJWT("myself", "mygreatpassword")
	if err != nil {
		t.Error("Cannot create token", err)
	}

	// Let's invalidate this token
	tokenString += "babbababba"
	_, err = engine.ParseJWT(tokenString)
	if err == nil {
		t.Fail()
	}
}
