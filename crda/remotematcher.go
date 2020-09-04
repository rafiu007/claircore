package crda

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/libvuln/driver"
)

var (
	_ driver.Matcher       = (*Matcher)(nil)
	_ driver.RemoteMatcher = (*Matcher)(nil)

	defaultRepo = claircore.Repository{
		Name: "pypi",
		URI:  "https://pypi.org/simple",
	}
)

const (
	// Bounded concurrency limit.
	concurrencyLimit = 10
	defaultURL       = "https://f8a-analytics-preview-2445582058137.production.gw.apicast.io/?user_key=3e42fa66f65124e6b1266a23431e3d08"
)

// Matcher attempts to correlate discovered python packages with reported
// vulnerabilities.
type Matcher struct {
	client *http.Client
	url    *url.URL
	repo   *claircore.Repository
}

// Build struct to model CRDA V2 ComponentAnalysis response which
// delivers Snyk sourced Vulnerability information.
type Vulnerability struct {
	ID       string   `json:"vendor_cve_ids"`
	CVSS     string   `json:"cvss"`
	CVES     []string `json:"cve_ids"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	FixedIn  []string `json:"fixed_in"`
}

type Analyses struct {
	Vulnerabilities []Vulnerability `json:"vulnerability"`
}

type VulnReport struct {
	RecommendedVersion string   `json:"recommended_versions"`
	Message            string   `json:"message"`
	Analyses           Analyses `json:"component_analyses"`
}

// Option controls the configuration of a Matcher.
type Option func(*Matcher) error

// NewMatcher returns a configured Matcher or reports an error.
func NewMatcher(opt ...Option) (*Matcher, error) {
	m := Matcher{}
	for _, f := range opt {
		if err := f(&m); err != nil {
			return nil, err
		}
	}

	if m.url == nil {
		var err error
		m.url, err = url.Parse(defaultURL)
		if err != nil {
			return nil, err
		}
	}
	if m.client == nil {
		m.client = http.DefaultClient
	}
	if m.repo == nil {
		m.repo = &defaultRepo
	}

	return &m, nil
}

// WithClient sets the http.Client that the matcher should use for requests.
//
// If not passed to NewMatcher, http.DefaultClient will be used.
func WithClient(c *http.Client) Option {
	return func(m *Matcher) error {
		m.client = c
		return nil
	}
}

// WithHost sets the server host name that the matcher should use for requests.
//
// If not passed to NewMatcher, defaultHost will be used.
func WithURL(uri string) Option {
	u, err := url.Parse(uri)
	return func(m *Matcher) error {
		if err != nil {
			return err
		}
		m.url = u
		return nil
	}
}

// WithRepo sets the repository information that will be associated with all the
// vulnerabilites found.
//
// If not passed to NewMatcher, a default Repository will be used.
func WithRepo(r *claircore.Repository) Option {
	return func(m *Matcher) error {
		m.repo = r
		return nil
	}
}

// Name implements driver.Matcher.
func (*Matcher) Name() string { return "crda" }

// Filter implements driver.Matcher.
func (*Matcher) Filter(record *claircore.IndexRecord) bool {
	return record.Package.NormalizedVersion.Kind == "pep440"
}

// Query implements driver.Matcher.
func (*Matcher) Query() []driver.MatchConstraint {
	panic("unreachable")
}

// Vulnerable implements driver.Matcher.
func (*Matcher) Vulnerable(ctx context.Context, record *claircore.IndexRecord, vuln *claircore.Vulnerability) (bool, error) {
	// RemoteMatcher can match Package and Vulnerability.
	panic("unreachable")
}

// QueryRemoteMatcher implements driver.RemoteMatcher.
func (m *Matcher) QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/remotematcher/QueryRemoteMatcher").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("records", len(records)).
		Msg("packages")

	ctrlC, errorC := m.fetchVulnerabilities(ctx, records)
	results := make(map[string][]*claircore.Vulnerability)
	for r := range ctrlC {
		for _, vuln := range r {
			results[vuln.Package.ID] = append(results[vuln.Package.ID], &vuln)
			log.Debug().
				Str("package", vuln.Package.Name).
				Str("version", vuln.Package.Version).
				Str("id", vuln.ID).
				Msg("vulns")
		}
	}
	select {
	case err, ok := <-errorC:
		// Don't propagate error, log and move on.
		if ok {
			log.Error().Err(err).Msg("access to component analyses failed")
		}
	default:
	}
	log.Debug().
		Int("vulnerabilities", len(results)).
		Msg("query")
	return results, nil
}

func (m *Matcher) fetchVulnerabilities(ctx context.Context, records []*claircore.IndexRecord) (chan []claircore.Vulnerability, chan error) {
	inC := make(chan *claircore.IndexRecord, concurrencyLimit)
	ctrlC := make(chan []claircore.Vulnerability, concurrencyLimit)
	errorC := make(chan error, 1)
	go func() {
		defer close(ctrlC)
		defer close(errorC)
		var g errgroup.Group
		for _, record := range records {
			g.Go(func() error {
				vulns, err := m.componentAnalyses(ctx, <-inC)
				if err != nil {
					return err
				}
				ctrlC <- vulns
				return nil
			})
			inC <- record
		}
		close(inC)
		if err := g.Wait(); err != nil {
			errorC <- err
		}
	}()
	return ctrlC, errorC
}

func (m *Matcher) componentAnalyses(ctx context.Context, record *claircore.IndexRecord) ([]claircore.Vulnerability, error) {
	reqUrl := url.URL{
		Scheme:   m.url.Scheme,
		Host:     m.url.Host,
		Path:     fmt.Sprintf("/api/v2/component-analyses/pypi/%s/%s", record.Package.Name, record.Package.Version),
		RawQuery: m.url.RawQuery,
	}

	req := http.Request{
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {"claircore/crda/RemoteMatcher"}},
		URL:        &reqUrl,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       reqUrl.Host,
	}
	// A request shouldn't go beyound 10s.
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	res, err := m.client.Do(req.WithContext(tctx))
	if res != nil {
		defer res.Body.Close()
	}
	if err != nil {
		return nil, err
	} else {
		var vulnReport VulnReport
		data, _ := ioutil.ReadAll(res.Body)
		err = json.Unmarshal(data, &vulnReport)
		if err != nil {
			return nil, err
		}
		// A package can have 0 or more vulnerabilities for a version.
		var vulns []claircore.Vulnerability
		for _, vuln := range vulnReport.Analyses.Vulnerabilities {
			vulns = append(vulns, claircore.Vulnerability{
				ID:                 vuln.ID,
				Updater:            "CodeReadyAnalytics",
				Name:               vuln.ID,
				Description:        fmt.Sprintf("%s(cvss: %s)(cves: %s)\n%s", vuln.Title, vuln.CVSS, strings.Join(vuln.CVES, ","), vulnReport.Message),
				Links:              vuln.URL,
				Severity:           vuln.Severity,
				NormalizedSeverity: NormalizeSeverity(vuln.Severity),
				FixedInVersion:     strings.Join(vuln.FixedIn, ","),
				Package:            record.Package,
				Repo:               m.repo,
			})
		}
		return vulns, nil
	}
}
