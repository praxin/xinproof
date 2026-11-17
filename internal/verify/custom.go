package verify

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

// CustomCheck is a user-defined check (xinproof verify --check 'name=SQL'):
// a query run in the restored database that must return one truthy value.
type CustomCheck struct {
	Name string
	SQL  string
}

// CustomCheckID is the receipt check ID of every custom check.
const CustomCheckID = "l3.custom"

const maxCustomDetail = 200 // characters

var reCheckName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ParseCustomCheck parses "name=SQL". The name is 1–64 of [A-Za-z0-9_.-];
// the SQL is everything after the first "=" and must not be blank.
func ParseCustomCheck(s string) (CustomCheck, error) {
	name, sql, ok := strings.Cut(s, "=")
	if !ok {
		return CustomCheck{}, fmt.Errorf("custom check %q: want name=SQL", s)
	}
	if !reCheckName.MatchString(name) {
		return CustomCheck{}, fmt.Errorf("custom check name %q: use 1–64 letters, digits, '_', '.' or '-'", name)
	}
	if strings.TrimSpace(sql) == "" {
		return CustomCheck{}, fmt.Errorf("custom check %q has no SQL", name)
	}
	return CustomCheck{Name: name, SQL: sql}, nil
}

// Truthy reports whether a query result passes a custom check: boolean true,
// a non-zero number, or a non-empty string other than "0", "f" or "false".
// NULL is false. Values are compared as text, as the database clients print
// them (Postgres booleans are "t"/"f", MySQL booleans 1/0).
func Truthy(value string, null bool) bool {
	if null {
		return false
	}
	v := strings.TrimSpace(value)
	switch strings.ToLower(v) {
	case "", "0", "f", "false":
		return false
	}
	if f, err := strconv.ParseFloat(v, 64); err == nil {
		return f != 0
	}
	return true
}

// runCustomChecks runs the configured checks against a restored sandbox and
// folds their outcome into d. Each check becomes an l3.custom receipt check;
// a failing one makes the backup FAIL, one that couldn't run (sandbox broke,
// budget ran out) makes it ERROR unless another one failed.
func (v *Verifier) runCustomChecks(ctx context.Context, sess engine.Session, d *draft) {
	cks := v.Opts.Checks
	if len(cks) == 0 {
		return
	}
	if d.out.Result != receipt.Pass {
		for _, c := range cks {
			d.check(CustomCheckID, receipt.CheckSkip, customDetail(c.Name, "not run: the restore did not pass"))
		}
		return
	}
	q, ok := sess.(engine.Querier)
	if !ok {
		for _, c := range cks {
			d.check(CustomCheckID, receipt.CheckSkip, customDetail(c.Name, fmt.Sprintf("not run: %s backups don't support SQL checks", d.det.Engine)))
		}
		return
	}
	var failed, broken string
	for _, c := range cks {
		val, null, err := q.QueryValue(ctx, c.SQL)
		switch {
		case err != nil && (errors.Is(err, engine.ErrSandbox) || ctx.Err() != nil):
			msg := err.Error()
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				msg = "exceeded the time budget"
			}
			d.check(CustomCheckID, receipt.CheckError, customDetail(c.Name, msg))
			if broken == "" {
				broken = fmt.Sprintf("custom check %q could not run: %s", c.Name, clipRunes(msg, maxCustomDetail))
			}
		case err != nil:
			d.check(CustomCheckID, receipt.CheckFail, customDetail(c.Name, err.Error()))
			if failed == "" {
				failed = fmt.Sprintf("custom check %q failed: %s", c.Name, clipRunes(err.Error(), maxCustomDetail))
			}
		default:
			shown := showValue(val, null)
			if Truthy(val, null) {
				d.check(CustomCheckID, receipt.CheckPass, customDetail(c.Name, shown))
			} else {
				d.check(CustomCheckID, receipt.CheckFail, customDetail(c.Name, shown))
				if failed == "" {
					failed = fmt.Sprintf("custom check %q failed: returned %s", c.Name, clipRunes(shown, maxCustomDetail))
				}
			}
		}
	}
	switch {
	case failed != "":
		d.out.Result, d.out.Reason = receipt.Fail, failed
	case broken != "":
		d.out.Result, d.out.Reason = receipt.Error, broken
	}
}

func showValue(val string, null bool) string {
	switch {
	case null:
		return "NULL"
	case val == "":
		return `""`
	}
	return val
}

// customDetail is "<name>: <value or error>", at most 200 characters.
func customDetail(name, msg string) string { return clipRunes(name+": "+msg, maxCustomDetail) }

// clipRunes shortens s to at most n characters, ending in "…" when cut.
func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
