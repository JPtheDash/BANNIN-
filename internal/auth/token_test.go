package auth_test

import (
	"testing"

	"github.com/jyotidash/bannin/internal/auth"
)

func TestGenerateTokenIsRandomAndHex(t *testing.T) {
	a, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := auth.GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("GenerateToken produced the same token twice")
	}
	if len(a) != 64 { // 32 bytes hex-encoded
		t.Errorf("len(token) = %d, want 64", len(a))
	}
}

func TestVerify(t *testing.T) {
	cases := []struct {
		name            string
		want, presented string
		ok              bool
	}{
		{"match", "secret-token", "secret-token", true},
		{"mismatch", "secret-token", "wrong-token", false},
		{"different length", "secret-token", "secret-token-longer", false},
		{"empty presented", "secret-token", "", false},
	}
	for _, c := range cases {
		if got := auth.Verify(c.want, c.presented); got != c.ok {
			t.Errorf("%s: Verify() = %v, want %v", c.name, got, c.ok)
		}
	}
}
