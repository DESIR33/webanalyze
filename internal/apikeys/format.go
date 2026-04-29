package apikeys

import (
	"bytes"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"strings"
)

const (
	KeyPrefix = "wa_live_"
	KeyLen    = len(KeyPrefix) + 24 + 4 // prefix + entropy + checksum
)

var base62Alphabet = []byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

// ErrMalformedKey signals invalid syntax or checksum mismatch.
var ErrMalformedKey = errors.New("malformed api key")

// NormalizeKey trims spaces; does not validate.
func NormalizeKey(s string) string {
	return strings.TrimSpace(s)
}

// ValidateFormat checks prefix and 4-char CRC32-based checksum over prefix+24 entropy chars.
func ValidateFormat(full string) error {
	full = NormalizeKey(full)
	if len(full) != KeyLen {
		return ErrMalformedKey
	}
	if !strings.HasPrefix(full, KeyPrefix) {
		return ErrMalformedKey
	}
	body := full[len(KeyPrefix):]
	if len(body) != 28 {
		return ErrMalformedKey
	}
	entropy := []byte(body[:24])
	check := body[24:]
	want, err := checksum4(entropy)
	if err != nil {
		return ErrMalformedKey
	}
	if !constantTimeEqASCII(check, string(want)) {
		return ErrMalformedKey
	}
	return nil
}

// Prefix12 returns the indexed lookup prefix (first 12 chars: "wa_live_" + 4 base62).
func Prefix12(full string) string {
	full = NormalizeKey(full)
	if len(full) < 12 {
		return ""
	}
	return full[:12]
}

// GenerateKey returns a plaintext key wa_live_<24><checksum4>.
func GenerateKey() (string, error) {
	entropy := make([]byte, 24)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	for i := range entropy {
		entropy[i] = base62Alphabet[int(entropy[i])%62]
	}
	cs, err := checksum4(entropy)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(KeyPrefix)
	b.Write(entropy)
	b.Write(cs)
	return b.String(), nil
}

func checksum4(entropy24 []byte) ([]byte, error) {
	if len(entropy24) != 24 {
		return nil, ErrMalformedKey
	}
	payload := append(append([]byte{}, KeyPrefix...), entropy24...)
	sum := crc32.ChecksumIEEE(payload)
	mod := uint32(62 * 62 * 62 * 62)
	idx := sum % mod
	out := make([]byte, 4)
	var v uint32 = idx
	for i := 0; i < 4; i++ {
		out[3-i] = base62Alphabet[v%62]
		v /= 62
	}
	return out, nil
}

func constantTimeEqASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// Equal compares two byte slices in constant time when lengths match.
func Equal(a, b []byte) bool {
	return len(a) == len(b) && bytes.Equal(a, b)
}
