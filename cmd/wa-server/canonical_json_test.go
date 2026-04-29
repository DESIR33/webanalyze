package main

import (
	"testing"
)

func TestCanonicalJSONHash_KeyOrderAndWhitespace(t *testing.T) {
	a := []byte(`{
  "b": 2,
  "a": {"z": 1, "y": 2}
}`)
	b := []byte(`{"a":{"y":2,"z":1},"b":2}`)
	ha, _, err := canonicalJSONHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, _, err := canonicalJSONHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("digests differ: %s vs %s", ha, hb)
	}
}

func TestCanonicalJSONHash_DifferentBodies(t *testing.T) {
	x, _, _ := canonicalJSONHash([]byte(`{"url":"https://a.example"}`))
	y, _, _ := canonicalJSONHash([]byte(`{"url":"https://b.example"}`))
	if x == y {
		t.Fatal("expected different digests")
	}
}

func TestCanonicalJSONHash_TrailingJSONRejected(t *testing.T) {
	_, _, err := canonicalJSONHash([]byte(`{}[]`))
	if err == nil {
		t.Fatal("expected error")
	}
}
