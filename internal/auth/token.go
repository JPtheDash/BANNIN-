// Package auth guards api/server's dashboard endpoints with a single
// bearer token — enough to stop the local API from being open to
// anyone who can reach the port, without inventing accounts or
// sessions for a single-operator CLI tool. Multi-user identity, if it
// ever becomes worth it, is a different milestone.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// GenerateToken returns a random 32-byte token, hex-encoded — suitable
// for server.auth_token in bannin.yaml or the BANNIN_AUTH_TOKEN env
// var. Used by `bannin serve --generate-token`.
func GenerateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: generating token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// Verify reports whether presented matches want. It runs in constant
// time regardless of where the strings first differ, so a client
// can't learn the token byte-by-byte from response timing.
func Verify(want, presented string) bool {
	// subtle.ConstantTimeCompare requires equal-length inputs to stay
	// constant-time; unequal lengths already leak nothing worth timing
	// (the token length itself isn't secret), so compare directly.
	if len(want) != len(presented) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(presented)) == 1
}
