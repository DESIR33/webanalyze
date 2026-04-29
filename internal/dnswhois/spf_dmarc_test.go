package dnswhois

import (
	"testing"
)

func TestParseSPF(t *testing.T) {
	r := ParseSPF(`v=spf1 include:_spf.google.com ~all`)
	if !r.Present || r.Policy != "soft_fail" {
		t.Fatalf("got %+v", r)
	}
	if len(r.Includes) != 1 || r.Includes[0] != "_spf.google.com" {
		t.Fatalf("includes %+v", r.Includes)
	}
}

func TestParseDMARC(t *testing.T) {
	txts := []string{`v=DMARC1; p=quarantine; pct=100; rua=mailto:a@ex.com,mailto:b@ex.com`}
	r := ParseDMARC(txts)
	if !r.Present || r.Policy != "quarantine" || r.Pct == nil || *r.Pct != 100 {
		t.Fatalf("got %+v", r)
	}
	if len(r.RUA) < 2 {
		t.Fatalf("rua %+v", r.RUA)
	}
}

func TestGlobPatternMatchRoute53(t *testing.T) {
	const pat = "*.awsdns-*."
	ex := "ns-123.awsdns-12.com."
	p := MatchDNSProvider(ex, []patternRule{{Pattern: pat, Provider: "route53"}})
	if p != "route53" {
		t.Fatalf("got %s", p)
	}
}
