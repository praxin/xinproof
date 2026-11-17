package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/praxin/xinproof/internal/engine"
)

const fieldSep = "\x1f" // ASCII unit separator: never in ordinary text values

// QueryValue runs a user query in the restore database and returns its single
// value (engine.Querier). Output is unaligned with a zero byte after every
// record, so values may span lines; SQL NULL is printed as a random marker.
func (s *session) QueryValue(ctx context.Context, query string) (string, bool, error) {
	null := "\x1enull-" + randomHex(8)
	res, err := s.exec(ctx, "psql", "-X", "-A", "-t", "-q", "-v", "ON_ERROR_STOP=1",
		"-F", fieldSep, "-0", "-P", "null="+null,
		"-h", "127.0.0.1", "-U", superuser, "-d", restoreDB, "-c", query)
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		if why := s.sandboxBroke(res); why != "" {
			return "", false, fmt.Errorf("%w: %s", engine.ErrSandbox, why)
		}
		return "", false, errors.New(firstErrors(res.Stderr))
	}
	return parseSingleValue(string(res.Stdout), null)
}

// parseSingleValue reads psql -A -t -F <unit separator> -0 output that must
// hold exactly one row with one column.
func parseSingleValue(out, null string) (string, bool, error) {
	if out == "" {
		return "", false, errors.New("query returned no rows (want one row with one column)")
	}
	recs := strings.Split(strings.TrimSuffix(out, "\x00"), "\x00")
	if len(recs) != 1 {
		return "", false, fmt.Errorf("query returned %d rows (want one row with one column)", len(recs))
	}
	if n := strings.Count(recs[0], fieldSep) + 1; n != 1 {
		return "", false, fmt.Errorf("query returned %d columns (want one row with one column)", n)
	}
	if recs[0] == null {
		return "", true, nil
	}
	return recs[0], false, nil
}
