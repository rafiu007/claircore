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
)

var (
	urlTemplate = url.URL{
		Scheme: "https",
		// TODO: Host must be configurable
		Host: "f8a-analytics-preview-2445582058137.production.gw.apicast.io",
		Path: "/api/v2/component-analyses/pypi/%s/%s",
		// TODO: Userkey must be configurable
		RawQuery: "user_key=3e42fa66f65124e6b1266a23431e3d08",
	}
)

// Bounded concurrency limit.
const concurrencyLimit = 10

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

func componentAnalyses(ctx context.Context, record *claircore.IndexRecord) ([]claircore.Vulnerability, error) {
	reqUrl := urlTemplate
	reqUrl.Path = fmt.Sprintf(reqUrl.Path, record.Package.Name, record.Package.Version)
	req := http.Request{
		Method:     http.MethodGet,
		Header:     http.Header{"User-Agent": {"claircore/crda/RemoteMatcher"}},
		URL:        &reqUrl,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Host:       reqUrl.Host,
	}
	// Per request shouldn't go beyound 10s.
	tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Fixme: Use configurable http client.
	res, err := http.DefaultClient.Do(req.WithContext(tctx))
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
		// A package can have multiple vulnerability for a version.
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
			})
		}
		return vulns, nil
	}
}

func QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/remotematcher/QueryRemoteMatcher").
		Logger()
	ctx = log.WithContext(ctx)
	log.Debug().
		Int("records", len(records)).
		Msg("packages")

	inC := make(chan *claircore.IndexRecord, concurrencyLimit)
	ctrlC := make(chan []claircore.Vulnerability, concurrencyLimit)
	errorC := make(chan error, 1)
	go func() {
		defer close(ctrlC)
		defer close(errorC)
		var g errgroup.Group
		for _, record := range records {
			g.Go(func() error {
				vulns, err := componentAnalyses(ctx, <-inC)
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
	case err := <-errorC:
		// log error and move on
		log.Error().Err(err).Msg("failure")
	default:
	}
	log.Debug().
		Int("vulnerabilities", len(results)).
		Msg("query")
	return results, nil
}
