package da_store

import (
	"context"
	"fmt"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/vulnstore"
)

type Store interface {
	//implementing vulnstore.vulnerability
	vulnstore.Vulnerability
}

/*func (s Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) (map[string][]*claircore.Vulnerability, error) {
	// filter out the python packages by looping for the records

	vulns, err := get(ctx, records)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerabilites: %v", err)
	}
	return vulns, err
}*/

func (s Store) Get(ctx context.Context, records []*claircore.IndexRecord, opts vulnstore.GetOpts) int {
	fmt.Println("hi got connected")

	return 1
}
