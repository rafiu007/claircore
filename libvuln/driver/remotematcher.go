package driver

import (
	"context"

	"github.com/quay/claircore"
)

// RemoteMatcher is an additional interface that a Matcher can implement.

// When called the interface can invoke the remote matcher using the RESTful API
// to fetch new vulnerabilities associated with the given IndexRecords.

// The information retrieved from this interface won't be persisted into ClairCore database.
type RemoteMatcher interface {
	QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error)
}
