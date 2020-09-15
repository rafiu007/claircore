package crda

import (
	"context"
	"fmt"

	"github.com/quay/claircore/libvuln/driver"
)

func MatcherSet(_ context.Context) (driver.MatcherSet, error) {
	us := driver.NewMatcherSet()
	url := "sjhsdksjdkjsjksjd"
	py, err := NewMatcher(WithParams(url))
	if err != nil {
		return us, fmt.Errorf("failed to create crda matcher: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}
