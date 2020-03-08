package utils

import "testing"

func TestGenerateSalt(t *testing.T) {
	result, err := GenerateSalt(256)

	if err != nil {
		t.Fail()
	}

	if len(result) != 256 {
		t.Fail()
	}
}

func BenchmarkGenerateSalt256(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, _ = GenerateSalt(256)
	}
}
