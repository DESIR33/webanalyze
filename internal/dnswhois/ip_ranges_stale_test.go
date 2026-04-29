package dnswhois

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBundledIPRangesNotStale(t *testing.T) {
	b, err := embeddedFS.ReadFile("data/ip_ranges.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		GeneratedAt string `json:"generated_at"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	gen, err := time.Parse(time.RFC3339, f.GeneratedAt)
	if err != nil {
		t.Fatalf("generated_at: %v", err)
	}
	if time.Since(gen) > 14*24*time.Hour {
		t.Fatalf("ip_ranges snapshot older than 14 days: %s", f.GeneratedAt)
	}
}
