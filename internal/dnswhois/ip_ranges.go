package dnswhois

import (
	"encoding/json"
	"net"
	"sort"
	"strings"
)

type IPRanges struct {
	Version string
	entries []ipEntry
}

type ipEntry struct {
	net      net.IPNet
	provider string
}

type ipRangesFile struct {
	TaxonomyVersion string `json:"taxonomy_version"`
	GeneratedAt     string `json:"generated_at"`
	Ranges          []struct {
		Provider string   `json:"provider"`
		CIDRs    []string `json:"cidrs"`
	} `json:"ranges"`
}

func ParseIPRangesJSON(data []byte) (*IPRanges, error) {
	var f ipRangesFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	r := &IPRanges{Version: f.TaxonomyVersion}
	for _, block := range f.Ranges {
		for _, cidr := range block.CIDRs {
			_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
			if err != nil {
				continue
			}
			r.entries = append(r.entries, ipEntry{net: *ipnet, provider: block.Provider})
		}
	}
	sort.Slice(r.entries, func(i, j int) bool {
		onesI, _ := r.entries[i].net.Mask.Size()
		onesJ, _ := r.entries[j].net.Mask.Size()
		return onesI > onesJ
	})
	return r, nil
}

func (r *IPRanges) Lookup(ipStr string) string {
	if r == nil {
		return "unknown"
	}
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "unknown"
	}
	for _, e := range r.entries {
		if e.net.Contains(ip) {
			return e.provider
		}
	}
	return "unknown"
}
