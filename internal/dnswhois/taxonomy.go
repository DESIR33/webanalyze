package dnswhois

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

type Taxonomy struct {
	Version        string
	MailPatterns   []patternRule
	DNSPatterns    []patternRule
	VerifyPrefixes []verifyRule
}

type patternRule struct {
	Pattern  string `json:"pattern"`
	Provider string `json:"provider"`
}

type verifyRule struct {
	Prefix string `json:"prefix"`
	Signal string `json:"signal"`
}

type providersFile struct {
	TaxonomyVersion string        `json:"taxonomy_version"`
	Mail            []patternRule `json:"mail"`
	DNS             []patternRule `json:"dns"`
}

type verificationFile struct {
	TaxonomyVersion string       `json:"taxonomy_version"`
	Prefixes        []verifyRule `json:"prefixes"`
}

func LoadTaxonomy(providersJSON, verificationJSON []byte) (*Taxonomy, error) {
	var pf providersFile
	if err := json.Unmarshal(providersJSON, &pf); err != nil {
		return nil, err
	}
	var vf verificationFile
	if err := json.Unmarshal(verificationJSON, &vf); err != nil {
		return nil, err
	}
	t := &Taxonomy{
		Version:        pf.TaxonomyVersion,
		MailPatterns:   pf.Mail,
		DNSPatterns:    pf.DNS,
		VerifyPrefixes: vf.Prefixes,
	}
	if t.Version == "" {
		t.Version = vf.TaxonomyVersion
	}
	return t, nil
}

func MatchMailProvider(exchange string, rules []patternRule) string {
	ex := strings.TrimSpace(strings.ToLower(exchange))
	if ex == "" {
		return "none"
	}
	for _, r := range rules {
		if globPatternMatch(r.Pattern, ex) {
			return r.Provider
		}
	}
	return "unknown"
}

func MatchDNSProvider(ns string, rules []patternRule) string {
	s := strings.TrimSpace(strings.ToLower(ns))
	if s == "" {
		return "unknown"
	}
	for _, r := range rules {
		if globPatternMatch(r.Pattern, s) {
			return r.Provider
		}
	}
	return "unknown"
}

// globPatternMatch supports wildcards using * segments (case insensitive).
func globPatternMatch(pattern, value string) bool {
	pattern = strings.TrimSpace(strings.ToLower(pattern))
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, ".")
	pattern = strings.TrimSuffix(pattern, ".")
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		pos += idx + len(part)
		if i == 0 && idx != 0 {
			return false
		}
	}
	return true
}

// ResolveDNSProvider picks strongest signal from NS set (first matching wins order in list).
func ResolveDNSProvider(nameservers []string, rules []patternRule) string {
	if len(nameservers) == 0 {
		return "unknown"
	}
	for _, ns := range nameservers {
		ns = strings.TrimSpace(strings.ToLower(ns))
		p := MatchDNSProvider(ns, rules)
		if p != "unknown" {
			return p
		}
	}
	return "unknown"
}

func ExtractVerificationSignals(txts []string, rules []verifyRule) []string {
	var out []string
	got := map[string]struct{}{}
	for _, raw := range txts {
		s := strings.TrimSpace(raw)
		s = strings.Trim(s, `"`)
		s = strings.TrimSpace(s)
		low := strings.ToLower(s)
		for _, vr := range rules {
			p := strings.ToLower(strings.TrimSpace(vr.Prefix))
			if p != "" && strings.HasPrefix(low, p) {
				if _, ok := got[vr.Signal]; !ok {
					got[vr.Signal] = struct{}{}
					out = append(out, vr.Signal)
				}
				break
			}
		}
	}
	return out
}

func HostingHintForIPs(ipStrings []string, ranges *IPRanges) string {
	if ranges == nil {
		return "unknown"
	}
	h := "unknown"
	for _, s := range ipStrings {
		p := ranges.Lookup(s)
		if p != "unknown" {
			h = p
			return h
		}
	}
	return h
}

// TaxonomyPaths resolves dns/providers.json next to executable or cwd.
func TaxonomyPaths(base string) (providers, verification string) {
	if base == "" {
		base = "dns"
	}
	return filepath.Join(base, "providers.json"), filepath.Join(base, "verification.json")
}
