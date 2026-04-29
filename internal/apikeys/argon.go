package apikeys

import "github.com/alexedwards/argon2id"

// Argon2Params matches PRD: m=64MiB, t=3, p=2.
var Argon2Params = argon2id.Params{
	Memory:      65536, // 64 MiB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// HashSecret stores the plaintext API key with Argon2id.
func HashSecret(plaintext string) (string, error) {
	return argon2id.CreateHash(NormalizeKey(plaintext), &Argon2Params)
}

// VerifySecret performs constant-time hash comparison via the library.
func VerifySecret(plaintext, encodedHash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(NormalizeKey(plaintext), encodedHash)
}
