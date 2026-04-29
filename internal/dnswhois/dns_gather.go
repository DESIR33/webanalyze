package dnswhois

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// GatherDNS resolves records for apex and host in parallel; fills DNSBlock.
func GatherDNS(ctx context.Context, resolver *Resolver, hostLabel, apex string, tax *Taxonomy, ipRanges *IPRanges, webIPs []string) *DNSBlock {
	t0 := time.Now()
	hostFQDN := fqdn(hostLabel)
	apexFQDN := fqdn(apex)
	_ = hostFQDN

	rec := DNSRecords{
		A:    []string{},
		AAAA: []string{},
		NS:   []string{},
		MX:   []MXRecord{},
		TXT:  []string{},
		CAA:  []CAARecord{},
	}
	var errs []TypedSideError
	recordDur := map[string]int64{}

	var wg sync.WaitGroup
	var mu sync.Mutex

	run := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st := time.Now()
			_ = fn(ctx)
			d := time.Since(st).Milliseconds()
			mu.Lock()
			recordDur[name] = d
			mu.Unlock()
		}()
	}

	run("a", func(c context.Context) error {
		return collectA(c, resolver, apexFQDN, &rec.A, &errs, &mu)
	})
	run("aaaa", func(c context.Context) error {
		return collectAAAA(c, resolver, apexFQDN, &rec.AAAA, &errs, &mu)
	})
	run("ns", func(c context.Context) error {
		return collectNS(c, resolver, apexFQDN, &rec.NS, &errs, &mu)
	})
	run("mx", func(c context.Context) error {
		return collectMX(c, resolver, apexFQDN, &rec.MX, &errs, &mu)
	})
	run("txt", func(c context.Context) error {
		return collectTXT(c, resolver, apexFQDN, &rec.TXT, &errs, &mu)
	})
	run("cname_apex", func(c context.Context) error {
		return collectCNAME(c, resolver, apexFQDN, &rec.CNAMEApex, "cname_apex", &errs, &mu)
	})
	run("cname_www", func(c context.Context) error {
		www := "www." + strings.TrimSuffix(apexFQDN, ".") + "."
		return collectCNAME(c, resolver, www, &rec.CNAMEWWW, "cname_www", &errs, &mu)
	})
	run("caa", func(c context.Context) error {
		return collectCAA(c, resolver, apexFQDN, &rec.CAA, &errs, &mu)
	})
	run("dnssec", func(c context.Context) error {
		ok, err := queryDNSSEC(c, resolver, apexFQDN)
		mu.Lock()
		rec.DNSSEC = ok
		if err != nil {
			errs = append(errs, TypedSideError{Record: "dnssec", Code: ErrTimeout, Message: err.Error()})
		}
		mu.Unlock()
		return nil
	})

	wg.Wait()

	sort.Slice(rec.MX, func(i, j int) bool {
		if rec.MX[i].Preference != rec.MX[j].Preference {
			return rec.MX[i].Preference < rec.MX[j].Preference
		}
		return rec.MX[i].Exchange < rec.MX[j].Exchange
	})

	derived := DNSDerived{
		MailProvider:        "unknown",
		DNSProvider:         "unknown",
		HostingProviderHint: "unknown",
		VerificationSignals: []string{},
		SPFIncludes:         []string{},
		DMARCrua:            []string{},
		DMARCruf:            []string{},
		MxObserved:          []string{},
	}
	if tax != nil {
		derived.MailProvider = classifyMail(rec.MX, apexFQDN, webIPs, tax.MailPatterns)
		if derived.MailProvider == "unknown" && len(rec.MX) > 0 {
			for _, mx := range rec.MX {
				derived.MxObserved = append(derived.MxObserved, mx.Exchange)
			}
		}
		derived.DNSProvider = ResolveDNSProvider(rec.NS, tax.DNSPatterns)
		derived.VerificationSignals = ExtractVerificationSignals(rec.TXT, tax.VerifyPrefixes)
	}

	allIPs := append(append([]string{}, rec.A...), rec.AAAA...)
	derived.HostingProviderHint = HostingHintForIPs(allIPs, ipRanges)

	var spfTxt string
	for _, t := range rec.TXT {
		lt := strings.ToLower(strings.TrimSpace(strings.Trim(t, `"`)))
		if strings.HasPrefix(lt, "v=spf1") {
			spfTxt = t
			break
		}
	}
	spf := ParseSPF(spfTxt)
	derived.SPFPresent = spf.Present
	derived.SPFPolicy = spf.Policy
	derived.SPFIncludes = spf.Includes

	dmarc := ParseDMARC(rec.TXT)
	derived.DMARCPresent = dmarc.Present
	if dmarc.Present {
		derived.DMARCPolicy = dmarc.Policy
		derived.DMARCPct = dmarc.Pct
		derived.DMARCrua = dmarc.RUA
		derived.DMARCruf = dmarc.RUF
		if dmarc.Policy != "none" {
			found := false
			for _, s := range derived.VerificationSignals {
				if s == "dmarc_configured" {
					found = true
					break
				}
			}
			if !found {
				derived.VerificationSignals = append(derived.VerificationSignals, "dmarc_configured")
			}
		}
	}

	block := &DNSBlock{
		QueriedAt:   t0.UTC().Truncate(time.Millisecond),
		DurationMS:  time.Since(t0).Milliseconds(),
		Host:        strings.TrimSuffix(strings.TrimSpace(strings.ToLower(hostLabel)), "."),
		Apex:        strings.TrimSuffix(strings.TrimSpace(strings.ToLower(apex)), "."),
		Records:     rec,
		Derived:     derived,
		Errors:      errs,
		RecordDurMS: recordDur,
	}
	if tax != nil {
		block.TaxonomyVer = tax.Version
	}
	return block
}

func classifyMail(mx []MXRecord, apexFQDN string, webIPs []string, rules []patternRule) string {
	_ = webIPs
	if len(mx) == 0 {
		return "none"
	}
	best := MatchMailProvider(mx[0].Exchange, rules)
	if best != "unknown" {
		return best
	}
	ex := strings.TrimSuffix(strings.ToLower(mx[0].Exchange), ".")
	apex := strings.TrimSuffix(strings.ToLower(apexFQDN), ".")
	if ex == apex || ex == "mail."+apex || ex == "smtp."+apex {
		return "self_hosted_likely"
	}
	return "unknown"
}

func appendErr(mu *sync.Mutex, errs *[]TypedSideError, rec string, code string, msg string) {
	mu.Lock()
	*errs = append(*errs, TypedSideError{Record: rec, Code: code, Message: msg})
	mu.Unlock()
}

type exchOutcome struct {
	resp *dns.Msg
	code string
	msg  string
	err  error
}

func exchangeSimple(ctx context.Context, r *Resolver, name string, qtype uint16) exchOutcome {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.SetEdns0(4096, true)
	resp, _, err := r.Exchange(ctx, msg)
	if err != nil {
		return exchOutcome{nil, ErrTimeout, err.Error(), err}
	}
	cm := dnsErrFromExchange2(resp.Rcode)
	if cm.code != "" {
		return exchOutcome{resp, cm.code, cm.msg, fmt.Errorf("%s", cm.msg)}
	}
	return exchOutcome{resp, "", "", nil}
}

func dnsErrFromExchange2(rcode int) struct{ code, msg string } {
	switch rcode {
	case dns.RcodeSuccess:
		return struct{ code, msg string }{"", ""}
	case dns.RcodeNameError:
		return struct{ code, msg string }{ErrNXDOMAIN, "NXDOMAIN"}
	case dns.RcodeServerFailure:
		return struct{ code, msg string }{ErrSERVFAIL, "SERVFAIL"}
	case dns.RcodeRefused:
		return struct{ code, msg string }{ErrRefused, "REFUSED"}
	default:
		return struct{ code, msg string }{ErrSERVFAIL, dns.RcodeToString[rcode]}
	}
}

func collectA(ctx context.Context, r *Resolver, name string, dst *[]string, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeA)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "a", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "a", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			*dst = append(*dst, a.A.String())
		}
	}
	return nil
}

func collectAAAA(ctx context.Context, r *Resolver, name string, dst *[]string, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeAAAA)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "aaaa", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "aaaa", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if a, ok := rr.(*dns.AAAA); ok {
			*dst = append(*dst, a.AAAA.String())
		}
	}
	return nil
}

func collectNS(ctx context.Context, r *Resolver, name string, dst *[]string, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeNS)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "ns", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "ns", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			*dst = append(*dst, ns.Ns)
		}
	}
	return nil
}

func collectMX(ctx context.Context, r *Resolver, name string, dst *[]MXRecord, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeMX)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "mx", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "mx", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			*dst = append(*dst, MXRecord{Preference: int(mx.Preference), Exchange: mx.Mx})
		}
	}
	return nil
}

func collectTXT(ctx context.Context, r *Resolver, name string, dst *[]string, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeTXT)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "txt", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "txt", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if tx, ok := rr.(*dns.TXT); ok {
			*dst = append(*dst, strings.Join(tx.Txt, ""))
		}
	}
	return nil
}

func collectCNAME(ctx context.Context, r *Resolver, name string, dst **string, recLabel string, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeCNAME)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, recLabel, out.code, out.msg)
		return out.err
	}
	if out.code == ErrNXDOMAIN {
		*dst = nil
		return nil
	}
	if out.code != "" {
		appendErr(mu, errs, recLabel, out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			t := cn.Target
			*dst = &t
			return nil
		}
	}
	*dst = nil
	return nil
}

func collectCAA(ctx context.Context, r *Resolver, name string, dst *[]CAARecord, errs *[]TypedSideError, mu *sync.Mutex) error {
	out := exchangeSimple(ctx, r, name, dns.TypeCAA)
	if out.err != nil && out.code == ErrTimeout {
		appendErr(mu, errs, "caa", out.code, out.msg)
		return out.err
	}
	if out.code != "" {
		appendErr(mu, errs, "caa", out.code, out.msg)
		return nil
	}
	for _, rr := range out.resp.Answer {
		if ca, ok := rr.(*dns.CAA); ok {
			*dst = append(*dst, CAARecord{Flag: ca.Flag, Tag: ca.Tag, Value: ca.Value})
		}
	}
	return nil
}

func queryDNSSEC(ctx context.Context, r *Resolver, name string) (bool, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeDNSKEY)
	msg.SetEdns0(4096, true)
	resp, _, err := r.Exchange(ctx, msg)
	if err != nil {
		return false, err
	}
	if resp.AuthenticatedData {
		return true, nil
	}
	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.DNSKEY); ok {
			return true, nil
		}
	}
	return false, nil
}

// ApexFromHost returns ICANN apex domain using public suffix list.
func ApexFromHost(host string) (string, error) {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return "", errors.New("empty host")
	}
	if strings.Contains(host, ":") {
		if hh, _, err := net.SplitHostPort(host); err == nil {
			host = hh
		}
	}
	host = strings.TrimSuffix(host, ".")
	eTLD, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host, nil
	}
	return eTLD, nil
}

// NormalizeHost strips port from host for DNS labels.
func NormalizeHost(hostPort string) string {
	h := strings.TrimSpace(hostPort)
	if strings.Contains(h, ":") {
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
	}
	return strings.TrimSuffix(strings.ToLower(h), ".")
}
