package asyncjobs_test

import (
	"testing"

	"github.com/rverton/webanalyze/internal/asyncjobs"
)

func TestWebhookSignatureRoundTrip(t *testing.T) {
	secret := []byte("whsec_test_16bytes!!")
	body := []byte(`{"id":"evt_1","type":"job.succeeded"}`)
	ts := int64(1745955200)
	sig := asyncjobs.WebhookSignatureHeader(secret, ts, body)
	if err := asyncjobs.VerifyWebhookSignature(secret, ts, body, sig, ts, 300); err != nil {
		t.Fatal(err)
	}
	if err := asyncjobs.VerifyWebhookSignature(secret, ts, body, sig, ts+400, 300); err == nil {
		t.Fatal("expected skew failure")
	}
}
