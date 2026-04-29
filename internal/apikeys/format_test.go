package apikeys

import "testing"

func TestGenerateValidate(t *testing.T) {
	for i := 0; i < 100; i++ {
		k, err := GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		if len(k) != KeyLen {
			t.Fatalf("len %d", len(k))
		}
		if err := ValidateFormat(k); err != nil {
			t.Fatalf("valid key rejected: %v", err)
		}
		if Prefix12(k) != k[:12] {
			t.Fatal("prefix12")
		}
	}
}

func TestValidateFormat_RejectsGarbage(t *testing.T) {
	cases := []string{
		"",
		"wa_live_",
		"bearer blah",
		"wa_live_0123456789012345678901234xxxx", // wrong checksum length
	}
	for _, c := range cases {
		if err := ValidateFormat(c); err != ErrMalformedKey {
			t.Errorf("want ErrMalformedKey for %q got %v", c, err)
		}
	}
}
