package dnswhois

import (
	"errors"
	"time"
)

// Sentinel errors for programmatic checks (JSON codes remain string constants below).
var (
	ErrRDAPNotAvailableErr = errors.New("RDAP_NOT_AVAILABLE")
)

// Error codes for dns.errors / whois.errors (spec R10).
const (
	ErrTimeout          = "TIMEOUT"
	ErrNXDOMAIN         = "NXDOMAIN"
	ErrSERVFAIL         = "SERVFAIL"
	ErrRefused          = "REFUSED"
	ErrMalformed        = "MALFORMED"
	ErrRDAPRateLimited  = "RDAP_RATE_LIMITED"
	ErrWhoisParseFail   = "WHOIS_PARSE_FAIL"
	ErrRDAPNotAvailable = "RDAP_NOT_AVAILABLE"
)

// SideEnvelope is optional dns/whois block on analyze responses.
type SideEnvelope struct {
	DNS   *DNSBlock   `json:"dns,omitempty"`
	WHOIS *WHOISBlock `json:"whois,omitempty"`
}

// DNSBlock matches OpenAPI stable schema (R1).
type DNSBlock struct {
	QueriedAt   time.Time        `json:"queried_at"`
	DurationMS  int64            `json:"duration_ms"`
	Host        string           `json:"host"`
	Apex        string           `json:"apex"`
	TaxonomyVer string           `json:"taxonomy_version,omitempty"`
	Records     DNSRecords       `json:"records"`
	Derived     DNSDerived       `json:"derived"`
	Errors      []TypedSideError `json:"errors"`
	RecordDurMS map[string]int64 `json:"record_duration_ms,omitempty"`
}

// DNSRecords holds typed DNS answers (empty slices when none).
type DNSRecords struct {
	A         []string    `json:"a"`
	AAAA      []string    `json:"aaaa"`
	NS        []string    `json:"ns"`
	MX        []MXRecord  `json:"mx"`
	TXT       []string    `json:"txt"`
	CNAMEApex *string     `json:"cname_apex"`
	CNAMEWWW  *string     `json:"cname_www"`
	CAA       []CAARecord `json:"caa"`
	DNSSEC    bool        `json:"dnssec"`
}

type MXRecord struct {
	Preference int    `json:"preference"`
	Exchange   string `json:"exchange"`
}

type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// DNSDerived holds taxonomy-derived fields.
type DNSDerived struct {
	MailProvider        string   `json:"mail_provider"`
	DNSProvider         string   `json:"dns_provider"`
	HostingProviderHint string   `json:"hosting_provider_hint"`
	SPFPresent          bool     `json:"spf_present"`
	SPFPolicy           string   `json:"spf_policy,omitempty"`
	SPFIncludes         []string `json:"spf_includes,omitempty"`
	DMARCPresent        bool     `json:"dmarc_present"`
	DMARCPolicy         string   `json:"dmarc_policy,omitempty"`
	DMARCPct            *int     `json:"dmarc_pct,omitempty"`
	DMARCrua            []string `json:"dmarc_rua,omitempty"`
	DMARCruf            []string `json:"dmarc_ruf,omitempty"`
	VerificationSignals []string `json:"verification_signals"`
	MxObserved          []string `json:"mx_observed,omitempty"`
}

// WHOISBlock typed WHOIS/RDAP output.
type WHOISBlock struct {
	QueriedAt       time.Time        `json:"queried_at"`
	DurationMS      int64            `json:"duration_ms"`
	Source          string           `json:"source"`
	Registrar       *string          `json:"registrar"`
	RegistrarIANAID *int             `json:"registrar_iana_id,omitempty"`
	CreatedAt       *string          `json:"created_at"`
	UpdatedAt       *string          `json:"updated_at"`
	ExpiresAt       *string          `json:"expires_at"`
	DomainAgeDays   *int             `json:"domain_age_days,omitempty"`
	Status          []string         `json:"status"`
	Nameservers     []string         `json:"nameservers"`
	Registrant      *string          `json:"registrant"`
	Privacy         bool             `json:"privacy"`
	Errors          []TypedSideError `json:"errors"`
	Cached          bool             `json:"cached,omitempty"`
	TaxonomyVer     string           `json:"taxonomy_version,omitempty"`
}

type TypedSideError struct {
	Record  string `json:"record,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
