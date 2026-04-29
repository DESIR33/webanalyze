package asyncjobs

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// CallbackPin holds DNS-pinned delivery target: connect to IP with Host header.
type CallbackPin struct {
	CallbackURL    string // original https URL (for logging)
	ResolvedIP     string // for TLS we use hostname in URL but custom dial — store IP
	HostHeader     string // Host header value (port stripped unless non-default)
	AllowPlaintext bool   // if true, http was accepted
}

// CallbackValidationConfig controls SSRF checks for webhook URLs.
type CallbackValidationConfig struct {
	AllowPlaintextHTTP  bool
	AllowInternalTarget bool
	HostSuffixAllowlist []string // host must match suffix OR resolved IP must be public
}

// ValidateAndPinCallbackURL resolves host once and validates scheme + IP policy.
func ValidateAndPinCallbackURL(raw string, cfg CallbackValidationConfig) (*CallbackPin, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty callback url")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid url")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
	case "http":
		if !cfg.AllowPlaintextHTTP {
			return nil, fmt.Errorf("http callback not allowed")
		}
	default:
		return nil, fmt.Errorf("unsupported scheme")
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("missing host")
	}
	if strings.ReplaceAll(host, ".", "") == "" {
		return nil, fmt.Errorf("invalid host")
	}

	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("dns resolution failed: %w", err)
	}
	ip := ips[0]
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}

	if !cfg.AllowInternalTarget {
		if !hostMatchesSuffixAllowlist(host, cfg.HostSuffixAllowlist) && isForbiddenTargetIP(ip) {
			return nil, fmt.Errorf("callback host resolves to forbidden address space")
		}
	}

	port := u.Port()
	hostHeader := host
	if port != "" {
		hostHeader = net.JoinHostPort(host, port)
	}

	return &CallbackPin{
		CallbackURL:    raw,
		ResolvedIP:     ip.String(),
		HostHeader:     hostHeader,
		AllowPlaintext: scheme == "http",
	}, nil
}

func hostMatchesSuffixAllowlist(host string, rules []string) bool {
	h := strings.ToLower(host)
	for _, r := range rules {
		r = strings.TrimSpace(strings.ToLower(r))
		if r == "" {
			continue
		}
		r = strings.TrimPrefix(r, "*.")
		if strings.HasPrefix(r, ".") {
			if strings.HasSuffix(h, r) || h == strings.TrimPrefix(r, ".") {
				return true
			}
			continue
		}
		if h == r || strings.HasSuffix(h, "."+r) {
			return true
		}
	}
	return false
}

func isForbiddenTargetIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if v4 := ip.To4(); v4 != nil && v4[0] == 0 {
		return true // 0.0.0.0/8
	}
	return false
}
