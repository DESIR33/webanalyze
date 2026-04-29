package dnswhois

import (
	"fmt"
	"net/mail"
	"strings"
)

type SPFResult struct {
	Policy   string // pass | soft_fail | fail | none
	Includes []string
	Present  bool
}

type DMARCResult struct {
	Policy  string // none | quarantine | reject
	Present bool
	Pct     *int
	RUA     []string
	RUF     []string
}

func parseSPFIncludes(txt string) []string {
	parts := strings.Fields(txt)
	var out []string
	for _, p := range parts {
		if v, ok := spfMechanism(p, "include"); ok {
			out = append(out, v)
			continue
		}
		if v, ok := spfMechanism(p, "redirect"); ok {
			out = append(out, v)
		}
	}
	return out
}

func spfMechanism(token, name string) (string, bool) {
	prefix := name + ":"
	if len(token) >= len(prefix) && strings.EqualFold(token[:len(prefix)], prefix) {
		return strings.TrimSpace(token[len(prefix):]), true
	}
	return "", false
}

func ParseSPF(txt string) SPFResult {
	txt = strings.TrimSpace(txt)
	r := SPFResult{Policy: "none"}
	if txt == "" {
		return r
	}
	if !strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
		return r
	}
	r.Present = true
	low := strings.ToLower(txt)
	switch {
	case strings.Contains(low, " -all"):
		r.Policy = "fail"
	case strings.Contains(low, " ~all"):
		r.Policy = "soft_fail"
	case strings.Contains(low, " ?all"):
		r.Policy = "none"
	case strings.Contains(low, " +all"):
		r.Policy = "pass"
	default:
		r.Policy = "none"
	}
	r.Includes = parseSPFIncludes(txt)
	return r
}

func ParseDMARC(txts []string) DMARCResult {
	var raw string
	for _, t := range txts {
		t = strings.TrimSpace(strings.Trim(t, `"`))
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(t)), "v=dmarc1") {
			raw = t
			break
		}
	}
	r := DMARCResult{Policy: "none"}
	if raw == "" {
		return r
	}
	r.Present = true
	parts := strings.Split(raw, ";")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		kv := strings.SplitN(p, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(strings.ToLower(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "p":
			switch strings.ToLower(v) {
			case "none", "quarantine", "reject":
				r.Policy = strings.ToLower(v)
			}
		case "pct":
			var n int
			if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n >= 0 && n <= 100 {
				r.Pct = &n
			}
		case "rua":
			r.RUA = splitDMARCURIList(v)
		case "ruf":
			r.RUF = splitDMARCURIList(v)
		}
	}
	return r
}

func splitDMARCURIList(s string) []string {
	var out []string
	for _, chunk := range strings.Split(s, ",") {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}
		uri := chunk
		if idx := strings.IndexByte(chunk, '!'); idx >= 0 {
			uri = strings.TrimSpace(chunk[:idx])
		}
		lu := strings.ToLower(uri)
		if strings.HasPrefix(lu, "mailto:") {
			addr := uri[len("mailto:"):]
			if at, err := mail.ParseAddress(addr); err == nil {
				out = append(out, at.Address)
				continue
			}
		}
		out = append(out, uri)
	}
	return out
}
