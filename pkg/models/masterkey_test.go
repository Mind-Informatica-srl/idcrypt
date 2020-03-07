package models

import "testing"

func TestGenerateMasterKey(t *testing.T) {
	key, err := GenerateMasterKey()
	if err != nil {
		t.Error(err)
	}

	if len(key) != 32 {
		t.Errorf("Wrong key len: %v", len(key))
	}
}
