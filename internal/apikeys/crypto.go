package apikeys

import (
	"crypto/sha256"
)

// Sha256Finger returns SHA-256 fingerprint of plaintext key for cache lookups (not reversible).
func Sha256Finger(full string) [32]byte {
	return sha256.Sum256([]byte(NormalizeKey(full)))
}
