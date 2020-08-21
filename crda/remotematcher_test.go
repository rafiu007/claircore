package crda_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/crda"
)

func checkVulnerabilitiesAreEqual(t *testing.T, expected []*claircore.Vulnerability, got []*claircore.Vulnerability) {
	if len(expected) != len(got) {
		t.Errorf("len %d != %d", len(expected), len(got))
	}

	for i, expected := range expected {
		if expected.Package.ID != got[i].Package.ID {
			t.Errorf("Package.ID %s != %s", expected.Package.ID, got[i].Package.ID)
		}
		if expected.Package.Name != got[i].Package.Name {
			t.Errorf("Package.Name %s != %s", expected.Package.Name, got[i].Package.Name)
		}
		if expected.Package.Version != got[i].Package.Version {
			t.Errorf("Package.Version %s != %s", expected.Package.Version, got[i].Package.Version)
		}
		if got[i].ID == "" {
			t.Errorf("ID %s != %s", expected.ID, got[i].ID)
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

func newMatcher(t *testing.T, srv *httptest.Server) *crda.Matcher {
	m, err := crda.NewMatcher(crda.WithClient(srv.Client()), crda.WithURL(srv.URL))
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
			Matcher:  newMatcher(t, srv),
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
					},
				},
			},
			Matcher: newMatcher(t, srv),
		},
	}
	for _, tc := range tt {
		t.Run(tc.Name, tc.Run)
	}
}
