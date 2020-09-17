package crda

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/quay/claircore/libvuln/driver"
	"github.com/rs/zerolog"
)

type Factory struct {
	url    *url.URL
	client *http.Client
}

type FactoryConfig struct {
	URL string `json:"url", yaml:"url"`
}

func (f *Factory) Configure(ctx context.Context, cfg driver.MatcherConfigUnmarshaler, c *http.Client) error {
	log := zerolog.Ctx(ctx).With().
		Str("component", "crda/Factory.Configure").
		Logger()
	var fc FactoryConfig

	if err := cfg(&fc); err != nil {
		return err
	}
	log.Debug().Msg("loaded incoming config")

	if fc.URL != "" {
		u, err := url.Parse(fc.URL)
		if err != nil {
			return err
		}
		log.Info().
			Str("url", u.String()).
			Msg("configured manifest URL")
		f.url = u
	}

	if c != nil {
		log.Info().
			Msg("configured HTTP client")
		f.client = c
	}

	return nil
}

func MatcherSet(_ context.Context) (driver.MatcherSet, error) {
	us := driver.NewMatcherSet()
	url := "sjhsdksjdkjsjksjd"
	py, err := NewMatcher()
	if err != nil {
		return us, fmt.Errorf("failed to create crda matcher: %v", err)
	}
	err = us.Add(py)
	if err != nil {
		return us, err
	}
	return us, nil
}
