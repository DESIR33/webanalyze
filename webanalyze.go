package webanalyze

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/bobesa/go-domain-util/domainutil"
)

var (
	// ErrHTMLTooLarge is returned when the response body exceeds Job.MaxHTMLBytes.
	ErrHTMLTooLarge = errors.New("response body exceeds MaxHTMLBytes")
	// ErrBlocked403 indicates the server responded with HTTP 403.
	ErrBlocked403 = errors.New("http 403")
	// ErrEmptyPage indicates the response body was empty or whitespace only.
	ErrEmptyPage = errors.New("empty page")
	// ErrCaptchaBlocked indicates the response looks like a CAPTCHA or bot-check page.
	ErrCaptchaBlocked = errors.New("captcha or bot check page")
)

const VERSION = "0.3.9"

var (
	timeout = 8 * time.Second
	wa      *WebAnalyzer
)

// Result type encapsulates the result information from a given host
type Result struct {
	Host     string        `json:"host"`
	Matches  []Match       `json:"matches"`
	Duration time.Duration `json:"duration"`
	Error    error         `json:"error"`
	// FinalURL is the last URL after redirects when fetching (empty if offline or on fetch error before response).
	FinalURL string `json:"final_url,omitempty"`
	// FetchStatus is the HTTP status from the last response when fetching.
	FetchStatus int `json:"fetch_status,omitempty"`
	// HTMLBytes is the number of bytes read from the response body used for analysis.
	HTMLBytes int `json:"html_bytes,omitempty"`
	// FingerprintsEvaluated is the number of technology definitions considered for this scan.
	FingerprintsEvaluated int `json:"fingerprints_evaluated,omitempty"`
}

// Match type encapsulates the App information from a match on a document
type Match struct {
	App     `json:"app"`
	AppName string     `json:"app_name"`
	Matches [][]string `json:"matches"`
	Version string     `json:"version"`
}

// WebAnalyzer types holds an analyzation job
type WebAnalyzer struct {
	appDefs   *AppsDefinition
	scheduler chan *Job
	client    *http.Client
}

func (m *Match) updateVersion(version string) {
	if version != "" {
		m.Version = version
	}
}

// NewWebAnalyzer initializes webanalyzer by passing a reader of the
// app definition and an schedulerChan, which allows the scanner to
// add scan jobs on its own
func NewWebAnalyzer(apps io.Reader, client *http.Client) (*WebAnalyzer, error) {
	wa := new(WebAnalyzer)

	if err := wa.loadApps(apps); err != nil {
		return nil, err
	}

	wa.client = client

	return wa, nil
}

// Process runs analysis using the analyzer's default HTTP client.
func (wa *WebAnalyzer) Process(job *Job) (Result, []string) {
	return wa.ProcessWithClient(job, wa.client)
}

// ProcessWithClient runs analysis using the given HTTP client (nil uses the same default as fetchHost).
func (wa *WebAnalyzer) ProcessWithClient(job *Job, client *http.Client) (Result, []string) {
	u, err := url.Parse(job.URL)
	if err != nil {
		return Result{Host: job.URL, Error: err}, []string{}
	}

	if u.Scheme == "" {
		u.Scheme = "http"
	}
	job.URL = u.String()

	t0 := time.Now()
	matches, links, procErr, finalURL, fetchStatus, htmlBytes, fpEval := wa.process(job, wa.appDefs, client)
	t1 := time.Now()

	res := Result{
		Host:                  job.URL,
		Matches:               matches,
		Duration:              t1.Sub(t0),
		Error:                 procErr,
		FinalURL:              finalURL,
		FetchStatus:           fetchStatus,
		HTMLBytes:             htmlBytes,
		FingerprintsEvaluated: fpEval,
	}
	return res, links
}

func (wa *WebAnalyzer) CategoryById(cid string) string {
	if _, ok := wa.appDefs.Cats[cid]; !ok {
		return ""
	}

	return wa.appDefs.Cats[cid].Name
}

func defaultHTTPClient(initialURL string) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyFromEnvironment,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			u0, err := url.Parse(initialURL)
			if err != nil {
				return http.ErrUseLastResponse
			}
			if u0.Hostname() != req.URL.Hostname() {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func fetchHost(urlStr string, client *http.Client, userAgent string) (*http.Response, error) {
	if client == nil {
		client = defaultHTTPClient(urlStr)
	}
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "*/*")
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func readBodyLimited(body io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		return io.ReadAll(body)
	}
	lr := &io.LimitedReader{R: body, N: int64(maxBytes + 1)}
	b, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if len(b) > maxBytes {
		return nil, ErrHTMLTooLarge
	}
	return b, nil
}

func unique(strSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func sameUrl(u1, u2 *url.URL) bool {
	return u1.Hostname() == u2.Hostname() &&
		u1.Port() == u2.Port() &&
		u1.RequestURI() == u2.RequestURI()
}

func resolveLink(base *url.URL, val string, searchSubdomain bool) string {
	u, err := url.Parse(val)
	if err != nil {
		return ""
	}

	urlResolved := base.ResolveReference(u)

	if !searchSubdomain && urlResolved.Hostname() != base.Hostname() {
		return ""
	}

	if searchSubdomain && !isSubdomain(base, u) {
		return ""
	}

	if urlResolved.RequestURI() == "" {
		urlResolved.Path = "/"
	}

	if sameUrl(base, urlResolved) {
		return ""
	}

	// only allow http/https
	if urlResolved.Scheme != "http" && urlResolved.Scheme != "https" {
		return ""
	}

	return urlResolved.String()
}

func parseLinks(doc *goquery.Document, base *url.URL, searchSubdomain bool) []string {
	var links []string

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		val, ok := s.Attr("href")
		if !ok {
			return
		}

		u := resolveLink(base, val, searchSubdomain)
		if u != "" {
			links = append(links, u)
		}
	})

	return unique(links)
}

func isSubdomain(base, u *url.URL) bool {
	return domainutil.Domain(base.String()) == domainutil.Domain(u.String())
}

// do http request and analyze response
func (wa *WebAnalyzer) process(job *Job, appDefs *AppsDefinition, client *http.Client) (apps []Match, links []string, err error, finalURL string, fetchStatus int, htmlBytes int, fingerprintsEvaluated int) {
	fingerprintsEvaluated = len(appDefs.Apps)

	var cookies []*http.Cookie
	var cookiesMap = make(map[string]string)
	var body []byte
	var headers http.Header

	if job.forceNotDownload {
		body = job.Body
		headers = job.Headers
		cookies = job.Cookies
		htmlBytes = len(body)
		finalURL = job.URL
	} else {
		resp, ferr := fetchHost(job.URL, client, job.UserAgent)
		if ferr != nil {
			return nil, links, fmt.Errorf("Failed to retrieve: %w", ferr), "", 0, 0, fingerprintsEvaluated
		}
		defer resp.Body.Close()

		fetchStatus = resp.StatusCode
		if resp.Request != nil && resp.Request.URL != nil {
			finalURL = resp.Request.URL.String()
		} else {
			finalURL = job.URL
		}

		maxBytes := job.MaxHTMLBytes
		var rerr error
		body, rerr = readBodyLimited(resp.Body, maxBytes)
		if rerr != nil {
			return nil, links, rerr, finalURL, fetchStatus, 0, fingerprintsEvaluated
		}
		htmlBytes = len(body)

		if resp.StatusCode == http.StatusForbidden {
			return nil, links, ErrBlocked403, finalURL, fetchStatus, htmlBytes, fingerprintsEvaluated
		}

		if resp.StatusCode == http.StatusOK && looksLikeCaptchaPage(body) {
			return nil, links, ErrCaptchaBlocked, finalURL, fetchStatus, htmlBytes, fingerprintsEvaluated
		}

		headers = resp.Header
		if job.followRedirect {
			for k, v := range resp.Header {
				if k == "Location" {
					base, _ := url.Parse(job.URL)
					u := resolveLink(base, v[0], job.SearchSubdomain)
					if u != "" {
						links = append(links, v[0])
					}
				}
			}
		}
		cookies = resp.Cookies()
	}

	if len(bytes.TrimSpace(body)) == 0 {
		return nil, links, ErrEmptyPage, finalURL, fetchStatus, htmlBytes, fingerprintsEvaluated
	}

	for _, c := range cookies {
		cookiesMap[c.Name] = c.Value
	}

	doc, derr := goquery.NewDocumentFromReader(bytes.NewReader(body))
	if derr != nil {
		return nil, links, derr, finalURL, fetchStatus, htmlBytes, fingerprintsEvaluated
	}

	// handle crawling
	if job.Crawl > 0 {
		base, _ := url.Parse(job.URL)

		for c, link := range parseLinks(doc, base, job.SearchSubdomain) {
			if c >= job.Crawl {
				break
			}

			links = append(links, link)
		}
	}

	scripts := doc.Find("script")

	for appname, app := range appDefs.Apps {

		findings := Match{
			App:     app,
			AppName: appname,
			Matches: make([][]string, 0),
		}

		// check raw html
		if m, v := findMatches(string(body), app.HTMLRegex); len(m) > 0 {
			findings.Matches = append(findings.Matches, m...)
			findings.updateVersion(v)
		}

		// check response header
		headerFindings, version := app.FindInHeaders(headers)
		findings.Matches = append(findings.Matches, headerFindings...)
		findings.updateVersion(version)

		// check url
		if m, v := findMatches(job.URL, app.URLRegex); len(m) > 0 {
			findings.Matches = append(findings.Matches, m...)
			findings.updateVersion(v)
		}

		// check script tags
		scripts.Each(func(i int, s *goquery.Selection) {
			if script, exists := s.Attr("src"); exists {
				if m, v := findMatches(script, app.ScriptRegex); len(m) > 0 {
					findings.Matches = append(findings.Matches, m...)
					findings.updateVersion(v)
				}
			}
		})

		// check meta tags
		for _, h := range app.MetaRegex {
			selector := fmt.Sprintf("meta[name='%s']", h.Name)
			doc.Find(selector).Each(func(i int, s *goquery.Selection) {
				content, _ := s.Attr("content")
				if m, v := findMatches(content, []AppRegexp{h}); len(m) > 0 {
					findings.Matches = append(findings.Matches, m...)
					findings.updateVersion(v)
				}
			})
		}

		// check cookies
		for _, c := range app.CookieRegex {
			if _, ok := cookiesMap[c.Name]; ok {

				if c.Regexp != nil {

					if m, v := findMatches(cookiesMap[c.Name], []AppRegexp{c}); len(m) > 0 {
						findings.Matches = append(findings.Matches, m...)
						findings.updateVersion(v)
					}

				} else {
					findings.Matches = append(findings.Matches, []string{c.Name})
				}
			}

		}

		if len(findings.Matches) > 0 {
			apps = append(apps, findings)

			for _, implies := range app.Implies {
				for implyAppname, implyApp := range appDefs.Apps {
					if implies != implyAppname {
						continue
					}

					f2 := Match{
						App:     implyApp,
						AppName: implyAppname,
						Matches: make([][]string, 0),
					}
					apps = append(apps, f2)
				}

			}
		}
	}

	return apps, links, nil, finalURL, fetchStatus, htmlBytes, fingerprintsEvaluated
}

func looksLikeCaptchaPage(body []byte) bool {
	s := strings.ToLower(string(body))
	if strings.Contains(s, "<html") {
		return strings.Contains(s, "cf-turnstile") ||
			strings.Contains(s, "hcaptcha") ||
			strings.Contains(s, "g-recaptcha") ||
			strings.Contains(s, "/challenge-platform/")
	}
	return strings.Contains(s, "captcha")
}

// runs a list of regexes on content
func findMatches(content string, regexes []AppRegexp) ([][]string, string) {
	var m [][]string
	var version string

	for _, r := range regexes {
		matches := r.Regexp.FindAllStringSubmatch(content, -1)
		if matches == nil {
			continue
		}

		m = append(m, matches...)

		if r.Version != "" {
			version = findVersion(m, r.Version)
		}

	}
	return m, version
}

// parses a version against matches
func findVersion(matches [][]string, version string) string {
	var v string

	for _, matchPair := range matches {
		// replace backtraces (max: 3)
		for i := 1; i <= 3; i++ {
			bt := fmt.Sprintf("\\%v", i)
			if strings.Contains(version, bt) && len(matchPair) >= i {
				v = strings.Replace(version, bt, matchPair[i], 1)
			}
		}

		// return first found version
		if v != "" {
			return v
		}

	}

	return ""
}
