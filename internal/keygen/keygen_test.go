package keygen

import (
	"testing"

	"github.com/Mind-Informatica-srl/idcrypt/internal/utils"
)

func TestGenerateKey(t *testing.T) {
	salt, err := utils.GenerateSalt(256)
	if err != nil {
		t.Error(err)
	}

	key := GenerateKey([]byte("this is a really long and strange password, it seems"), 32, salt)
	if key == nil {
		t.Fail()
	}

	if len(key) != 32 {
		t.Errorf("Wrong key len: %v", len(key))
	}
}
