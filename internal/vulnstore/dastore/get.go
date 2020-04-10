package dastore

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

func get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	log := zerolog.Ctx(ctx).With().
		Str("component", "internal/vulnstore/postgres/get").
		Logger()
	ctx = log.WithContext(ctx)

	results := make(map[string][]*claircore.Vulnerability)

	v := &claircore.Vulnerability{

		ID:                 "123",
		Updater:            "abc",
		Name:               "CVE-2020-00",
		Description:        "",
		Links:              "",
		Severity:           "",
		NormalizedSeverity: "unknown",
		FixedInVersion:     "0",
		Package: &claircore.Package{ID: "0",
			Name:    "xyz",
			Version: "v0.0"},
		Dist: &claircore.Distribution{},
		Repo: &claircore.Repository{},
	}

	results["0"] = append(results["0"], v)

	return results, nil

}
