package dastore

import (
	"context"
	"fmt"

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

	for _, j := range records {
		log.Print(j)

		if j.Package.Name == "flask" && j.Package.Version == "0.12" {

			fmt.Println("HEY.....................................................................................................................................................................................................................................................................................................................")

			v := &claircore.Vulnerability{

				ID:                 "123",
				Updater:            "abc",
				Name:               "dummy_flask",
				Description:        "dummy_flask",
				Links:              "dummy_flask",
				Severity:           "dummy_flask",
				NormalizedSeverity: "dummy_flask",
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

		fmt.Printf("%v %v", j.Package.Name, j.Package.Version)

	}

	return results, nil

}
