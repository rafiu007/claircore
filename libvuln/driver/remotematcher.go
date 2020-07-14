package driver

import (
	"context"

	"github.com/quay/claircore"
)

// RemoteMatcher is an additional interface that a Matcher can implement.
//
// When called the interface should call the remote matcher using the RESTful API
// to fetch new vulnerabilites associated with the given IndexRecords.
//
// The information retrived from this interface will not be persisted into ClairCore database.
type RemoteMatcher interface {
	QueryRemoteMatcher(ctx context.Context, records []*claircore.IndexRecord) (map[string][]*claircore.Vulnerability, error)
}
