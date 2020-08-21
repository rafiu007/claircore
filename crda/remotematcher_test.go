package crda_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/quay/claircore"
	"github.com/quay/claircore/crda"
	"github.com/quay/claircore/libvuln/driver"
	"github.com/quay/claircore/test/log"
)

func (tc matcherTestcase) Run(t *testing.T) {
}

type matcherTestcase struct {
	Name    string
	R       []*claircore.IndexRecord
	V       []*claircore.Vulnerability
	Matcher driver.Matcher
}

func TestRemoteMatcher(t *testing.T) {
	t.Parallel()
	ctx, done := context.WithCancel(context.Background())
	defer done()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "testdata/CRDA_api_response_pypi_pyyaml.json")
	}))
	defer srv.Close()

	m, err := crda.NewMatcher(crda.WithClient(srv.Client()), crda.WithHost(srv.URL))
	if err != nil {
		t.Errorf("there should be no err %v", err)
	}

	t.Run("FetchContext", func(t *testing.T) {
		ctx, done := log.TestLogger(ctx, t)
		defer done()
		t.Logf("matcher %#+v err %#+v", m, err)
		vulns, err := m.QueryRemoteMatcher(ctx, []*claircore.IndexRecord{})
		t.Logf("vulns %#+v err %#+v", vulns, err)
	})
}
