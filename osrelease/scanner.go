// Package osrelease provides an "os-release" distribution scanner.
package osrelease

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"runtime/trace"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/quay/claircore"
	"github.com/quay/claircore/internal/indexer"
)

const (
	scannerName    = "os-release"
	scannerVersion = "v0.0.1"
	scannerKind    = "distribution"
)

const fpath = `etc/os-release`

var _ indexer.DistributionScanner = (*Scanner)(nil)
var _ indexer.VersionedScanner = (*Scanner)(nil)

// Scanner implements a scanner.DistributionScanner that examines os-release
// files, as documented at
// https://www.freedesktop.org/software/systemd/man/os-release.html
type Scanner struct{}

// Name implements scanner.VersionedScanner.
func (*Scanner) Name() string { return scannerName }

// Version implements scanner.VersionedScanner.
func (*Scanner) Version() string { return scannerVersion }

// Kind implements scanner.VersionedScanner.
func (*Scanner) Kind() string { return scannerKind }

// Scan reports any found os-release Distribution information in the provided
// layer.
//
// It's an expected outcome to return (nil, nil) when the os-release file is not
// present in the layer.
func (s *Scanner) Scan(l *claircore.Layer) ([]*claircore.Distribution, error) {
	ctx := context.TODO()
	ctx = log.Logger.WithContext(ctx)
	defer trace.StartRegion(ctx, "Scanner.Scan").End()
	log := zerolog.Ctx(ctx).With().
		Str("component", "dist_scanner").
		Str("name", s.Name()).
		Str("version", s.Version()).
		Str("kind", s.Kind()).
		Str("layer", l.Hash).
		Logger()
	log.Debug().Msg("start")
	defer log.Debug().Msg("done")

	f, err := l.Files([]string{fpath})
	if err != nil {
		return nil, fmt.Errorf("osrelease: unable to open layer: %w", err)
	}
	b := f[fpath]
	if len(b) == 0 {
		log.Debug().Msg("didn't find an os-release file")
		return nil, nil
	}
	rd := bytes.NewReader(b)
	d, err := parse(ctx, &log, rd)
	if err != nil {
		return nil, err
	}
	return []*claircore.Distribution{d}, nil
}

// Parse returns the distribution information from the file contents provided on
// r.
func parse(ctx context.Context, log *zerolog.Logger, r io.Reader) (*claircore.Distribution, error) {
	defer trace.StartRegion(ctx, "parse").End()
	d := claircore.Distribution{
		Name: "Linux",
		DID:  "linux",
	}
	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	for s.Scan() && ctx.Err() == nil {
		b := s.Bytes()
		switch {
		case len(b) == 0:
			continue
		case b[0] == '#':
			continue
		}
		eq := bytes.IndexRune(b, '=')
		if eq == -1 {
			return nil, fmt.Errorf("osrelease: malformed line %q", s.Text())
		}
		key := strings.TrimSpace(string(b[:eq]))
		value := strings.TrimSpace(string(b[eq+1:]))

		// The value side is defined to follow shell-like quoting rules, which I
		// take to mean:
		//
		// * Within single quotes, no characters are special, and escaping is
		//   not possible. The only special case that needs to be handled is
		//   getting a single quote, which is done in shell by ending the
		//   string, escaping a single quote, then starting a new string.
		//
		// * Within double quotes, single quotes are not special, but double
		//   quotes and a handful of other characters are, and almost the entire
		//   lower-case ASCII alphabet can be escaped to produce various
		//   codepoints.
		//
		// With these in mind, the arms of the switch below implement the first
		// case and a limited version of the second.
		switch value[0] {
		case '\'':
			value = strings.TrimFunc(value, func(r rune) bool { return r == '\'' })
			value = strings.ReplaceAll(value, `'\''`, `'`)
		case '"':
			// This only implements the metacharacters that are called out in
			// the os-release documentation.
			value = strings.TrimFunc(value, func(r rune) bool { return r == '"' })
			value = strings.NewReplacer(
				"\\`", "`",
				`\\`, `\`,
				`\"`, `"`,
				`\$`, `$`,
			).Replace(value)
		default:
		}

		switch key {
		case "ID":
			log.Debug().Msg("found ID")
			d.DID = value
		case "VERSION_ID":
			log.Debug().Msg("found VERSION_ID")
			d.VersionID = value
		case "BUILD_ID":
		case "VARIANT_ID":
		case "CPE_NAME":
			log.Debug().Msg("found CPE_NAME")
			d.CPE = value
		case "NAME":
			log.Debug().Msg("found NAME")
			d.Name = value
		case "VERSION":
			log.Debug().Msg("found VERSION")
			d.Version = value
		case "ID_LIKE":
		case "VERSION_CODENAME":
			log.Debug().Msg("found VERISON_CODENAME")
			d.VersionCodeName = value
		case "PRETTY_NAME":
			log.Debug().Msg("found PRETTY_NAME")
			d.PrettyName = value
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	log.Debug().Str("name", d.Name).Msg("found dist")
	return &d, nil
}