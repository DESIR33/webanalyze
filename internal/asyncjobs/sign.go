package asyncjobs

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// WebhookSignatureHeader builds Webanalyze-Signature: t=<ts>,v1=<hex_hmac>.
func WebhookSignatureHeader(secret []byte, tsUnix int64, jsonBody []byte) string {
	mac := hmac.New(sha256.New, secret)
	fmt.Fprintf(mac, "%d.", tsUnix)
	mac.Write(jsonBody)
	return fmt.Sprintf("t=%d,v1=%s", tsUnix, hex.EncodeToString(mac.Sum(nil)))
}

// VerifyWebhookSignature checks HMAC and timestamp skew (maxSkew from now).
func VerifyWebhookSignature(secret []byte, tsUnix int64, jsonBody []byte, sigHeader string, nowUnix int64, maxSkewSec int64) error {
	tsStr, hexSig, ok := parseSigHeader(sigHeader)
	if !ok {
		return fmt.Errorf("invalid signature header format")
	}
	gotTS, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp in signature")
	}
	if gotTS != tsUnix {
		return fmt.Errorf("timestamp mismatch")
	}
	if nowUnix-gotTS > maxSkewSec || gotTS-nowUnix > maxSkewSec {
		return fmt.Errorf("timestamp outside tolerance window")
	}
	want := WebhookSignatureHeader(secret, tsUnix, jsonBody)
	// Constant-time compare of v1= hex portion
	_, wantV1, ok1 := parseSigHeader(want)
	if !ok1 {
		return fmt.Errorf("internal signature build failed")
	}
	if !hmac.Equal([]byte(strings.ToLower(hexSig)), []byte(strings.ToLower(wantV1))) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

func parseSigHeader(s string) (ts, v1 string, ok bool) {
	s = strings.TrimSpace(s)
	var tPart, vPart string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "t=") {
			tPart = strings.TrimPrefix(part, "t=")
		}
		if strings.HasPrefix(part, "v1=") {
			vPart = strings.TrimPrefix(part, "v1=")
		}
	}
	if tPart == "" || vPart == "" {
		return "", "", false
	}
	return tPart, vPart, true
}
