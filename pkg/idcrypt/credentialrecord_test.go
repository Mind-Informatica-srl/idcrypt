package idcrypt

import (
	"bytes"
	"testing"
)

var (
	masterKey = []byte("this is my master key,  is nice?")
)

func TestIsPasswordValid(t *testing.T) {
	cred, err := NewCredentialRecord("this is my password", masterKey)
	if err != nil {
		t.Error(err)
	}

	status, err := cred.IsPasswordValid("this is my password")
	if err != nil {
		t.Error(err)
	}

	if !status {
		t.Error("Password non valid?")
	}
}

func TestRecoverMasterKey(t *testing.T) {
	cred, err := NewCredentialRecord("this is my password", masterKey)
	if err != nil {
		t.Error(err)
	}

	key, err := cred.RecoverMasterKey("this is my password")
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(key, masterKey) {
		t.Errorf("I haven't recovered my master key. %v vs %v", key, masterKey)
	}
}
