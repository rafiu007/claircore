package crda_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/crda"
)

var (
	pypiRepo = claircore.Repository{
		Name: "python",
		URI:  "https://python.org",
	}
)

func checkVulnerabilitiesAreEqual(t *testing.T, expected []*claircore.Vulnerability, got []*claircore.Vulnerability) {
	if len(expected) != len(got) {
		t.Errorf("len %d != %d", len(expected), len(got))
		return
	}

	for i, expected := range expected {
		if *expected.Package != *got[i].Package {
			t.Errorf("Package %#v != %#v", expected.Package, got[i].Package)
		}
		if expected.Repo != nil && *expected.Repo != *got[i].Repo {
			t.Errorf("Repo %#v != %#v", expected.Repo, got[i].Repo)
		}
		if got[i].ID == "" {
			t.Errorf("ID must be a valid string")
		}
		if got[i].Description == "" {
			t.Errorf("Description must be a valid string")
		}
		if got[i].Updater != "CodeReadyAnalytics" {
			t.Errorf("Updater CodeReadyAnalytics != %s", got[i].Updater)
		}
		if got[i].Severity == "" {
			t.Errorf("Severity must be a valid string")
		}
		if got[i].NormalizedSeverity == 0 {
			t.Errorf("NormalizedSeverity must be valid")
		}
		if _, err := url.Parse(got[i].Links); err != nil {
			t.Errorf("URL is invalid %s, err %s", got[i].Links, err)
		}
	}
}

func (tc matcherTestcase) Run(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got, err := tc.Matcher.QueryRemoteMatcher(ctx, tc.R)
	// RemoteMatcher never throws error, it just logs it.
	if err != nil {
		t.Errorf("RemoteMatcher error %v", err)
	}
	for k, expectedVulns := range tc.Expected {
		got, ok := got[k]
		if !ok {
			t.Errorf("Expected key %s not found", k)
		}
		checkVulnerabilitiesAreEqual(t, expectedVulns, got)
	}
}

type matcherTestcase struct {
	Name     string
	R        []*claircore.IndexRecord
	Expected map[string][]*claircore.Vulnerability
	Matcher  *crda.Matcher
}

func newMatcher(t *testing.T, srv *httptest.Server, repo *claircore.Repository) *crda.Matcher {
	m, err := crda.NewMatcher(crda.WithClient(srv.Client()), crda.WithURL(srv.URL), crda.WithRepo(repo))
	if err != nil {
		t.Errorf("there should be no err %v", err)
	}
	return m
}

func TestRemoteMatcher(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathWithoutAPIPrefix := strings.Replace(r.URL.Path, "/api/v2/component-analyses/", "", 1)
		testLocalPath := filepath.Join("testdata", pathWithoutAPIPrefix) + ".json"
		t.Logf("serving request for %v", testLocalPath)
		http.ServeFile(w, r, testLocalPath)
	}))
	defer srv.Close()

	tt := []matcherTestcase{
		{
			Name:     "pypi/empty",
			R:        []*claircore.IndexRecord{},
			Expected: map[string][]*claircore.Vulnerability{},
			Matcher:  newMatcher(t, srv, &pypiRepo),
		},
		{
			Name: "pypi/{pyyaml-vuln,flask-novuln}",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3",
					},
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "1.1.0",
					},
				},
			},
			Expected: map[string][]*claircore.Vulnerability{
				"pyyaml": []*claircore.Vulnerability{
					{
						Package: &claircore.Package{
							ID:      "pyyaml",
							Name:    "pyyaml",
							Version: "5.3",
						},
						Repo: &pypiRepo,
					},
				},
			},
			Matcher: newMatcher(t, srv, &pypiRepo),
		},
		{
			Name: "pypi/{pyyaml-novuln,flask-novuln}",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3.1",
					},
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "1.1.0",
					},
				},
			},
			Expected: map[string][]*claircore.Vulnerability{},
			Matcher:  newMatcher(t, srv, nil),
		},
		{
			Name: "pypi/{pyyaml-vuln,flask-vuln}",
			R: []*claircore.IndexRecord{
				{
					Package: &claircore.Package{
						ID:      "pyyaml",
						Name:    "pyyaml",
						Version: "5.3",
					},
				},
				{
					Package: &claircore.Package{
						ID:      "flask",
						Name:    "flask",
						Version: "0.12",
					},
				},
			},
			Expected: map[string][]*claircore.Vulnerability{
				"pyyaml": []*claircore.Vulnerability{
					{
						Package: &claircore.Package{
							ID:      "pyyaml",
							Name:    "pyyaml",
							Version: "5.3",
						},
					},
				},
				"flask": []*claircore.Vulnerability{
					{
						Package: &claircore.Package{
							ID:      "flask",
							Name:    "flask",
							Version: "0.12",
						},
					},
					{
						Package: &claircore.Package{
							ID:      "flask",
							Name:    "flask",
							Version: "0.12",
						},
					},
				},
			},
			Matcher: newMatcher(t, srv, nil),
		}}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
