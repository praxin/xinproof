package postgres

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/praxin/xinproof/internal/discover"
)

// Extensions returns the extensions a plain dump creates, sorted.
func (a *PlainAnalyzer) Extensions() []string {
	var out []string
	for e := range a.extensions {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// TOCExtensions returns the extensions an archive's TOC creates
// ("3; 3079 16385 EXTENSION - postgis"), sorted.
func TOCExtensions(toc string) []string {
	seen := map[string]bool{}
	for _, line := range strings.Split(toc, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 6 && f[3] == "EXTENSION" {
			seen[f[5]] = true
		}
	}
	var out []string
	for e := range seen {
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// missingExtensions returns the required extensions the sandbox image doesn't ship.
func (s *session) missingExtensions(ctx context.Context, required []string) ([]string, error) {
	if len(required) == 0 {
		return nil, nil
	}
	res, err := s.psql(ctx, restoreDB, "SELECT name FROM pg_available_extensions")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, errors.New(firstErrors(res.Stderr))
	}
	have := map[string]bool{}
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		have[strings.TrimSpace(l)] = true
	}
	var missing []string
	for _, e := range required {
		if !have[e] {
			missing = append(missing, e)
		}
	}
	return missing, nil
}

// extensionImages suggests public images that ship well-known extensions;
// %s is the PostgreSQL major.
var extensionImages = map[string]string{
	"postgis":     "postgis/postgis:%s-3.5",
	"timescaledb": "timescale/timescaledb:latest-pg%s",
	"vector":      "pgvector/pgvector:pg%s",
}

func missingExtensionsReason(missing []string, image string, d discover.Detection) string {
	major := MajorOf(d.DumpVersion)
	if major == "" {
		major = DefaultMajor
	}
	reason := fmt.Sprintf("the dump needs PostgreSQL extension(s) %s, which the sandbox image %s doesn't include, so it couldn't be tested",
		strings.Join(missing, ", "), strings.SplitN(image, "@", 2)[0])
	for _, e := range missing {
		if tmpl, ok := extensionImages[e]; ok {
			return reason + fmt.Sprintf("; rerun with --pg-image %s (or another image that has them)", fmt.Sprintf(tmpl, major))
		}
	}
	return reason + "; rerun with --pg-image set to an image that has them"
}
