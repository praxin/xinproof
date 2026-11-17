package verify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

func TestTruthy(t *testing.T) {
	tests := []struct {
		v    string
		null bool
		want bool
	}{
		{"t", false, true}, {"true", false, true}, {"TRUE", false, true},
		{"1", false, true}, {"42", false, true}, {"-1", false, true}, {"0.5", false, true}, {"1e3", false, true},
		{"yes", false, true}, {"ok", false, true}, {"00x", false, true},
		{"f", false, false}, {"F", false, false}, {"false", false, false}, {"False", false, false},
		{"0", false, false}, {"0.00", false, false}, {"-0", false, false}, {"0e5", false, false},
		{"", false, false}, {"  ", false, false}, {" 0 ", false, false},
		{"", true, false}, {"1", true, false},
	}
	for _, tt := range tests {
		if got := Truthy(tt.v, tt.null); got != tt.want {
			t.Errorf("Truthy(%q, null=%v) = %v, want %v", tt.v, tt.null, got, tt.want)
		}
	}
}

func TestParseCustomCheck(t *testing.T) {
	c, err := ParseCustomCheck("orders.recent-1_x=SELECT count(*) = 3 FROM t")
	if err != nil || c.Name != "orders.recent-1_x" || c.SQL != "SELECT count(*) = 3 FROM t" {
		t.Errorf("got %+v, %v", c, err)
	}
	for _, bad := range []string{"", "x", "=SELECT 1", "a b=SELECT 1", "ü=SELECT 1", "a/b=SELECT 1", strings.Repeat("a", 65) + "=1", "x=", "x= \t"} {
		if _, err := ParseCustomCheck(bad); err == nil {
			t.Errorf("ParseCustomCheck(%q) accepted", bad)
		}
	}
	if _, err := ParseCustomCheck(strings.Repeat("a", 64) + "=1"); err != nil {
		t.Errorf("64-character name rejected: %v", err)
	}
}

// queryEngine is a fakeEngine whose sessions answer custom-check queries.
type queryEngine struct {
	*fakeEngine
	answers map[string]answer
	queries []string
}

type answer struct {
	val  string
	null bool
	err  error
}

func (q *queryEngine) Start(ctx context.Context, d discover.Detection) (engine.Session, error) {
	s, err := q.fakeEngine.Start(ctx, d)
	if err != nil {
		return nil, err
	}
	return &querySession{fakeSession: s.(*fakeSession), q: q}, nil
}

type querySession struct {
	*fakeSession
	q *queryEngine
}

func (s *querySession) QueryValue(ctx context.Context, query string) (string, bool, error) {
	s.q.queries = append(s.q.queries, query)
	a, ok := s.q.answers[query]
	if !ok {
		return "", false, fmt.Errorf("unexpected query %q", query)
	}
	return a.val, a.null, a.err
}

func customChecks(r *receipt.Receipt) []receipt.Check {
	var out []receipt.Check
	for _, c := range r.Checks {
		if c.ID == CustomCheckID {
			out = append(out, c)
		}
	}
	return out
}

func TestCustomChecks(t *testing.T) {
	long := strings.Repeat("é", 300)
	tests := []struct {
		name    string
		answers map[string]answer
		checks  []CustomCheck
		want    receipt.Result
		reason  string
		details []string // status + " " + detail of each l3.custom check
	}{
		{
			name:    "all pass",
			answers: map[string]answer{"q1": {val: "t"}, "q2": {val: "40000"}},
			checks:  []CustomCheck{{"has_orders", "q1"}, {"order_count", "q2"}},
			want:    receipt.Pass,
			details: []string{"pass has_orders: t", "pass order_count: 40000"},
		},
		{
			name:    "falsy value fails the backup; later checks still run",
			answers: map[string]answer{"q1": {val: "0"}, "q2": {null: true}, "q3": {val: "1"}},
			checks:  []CustomCheck{{"recent", "q1"}, {"nullable", "q2"}, {"ok", "q3"}},
			want:    receipt.Fail,
			reason:  `custom check "recent" failed: returned 0`,
			details: []string{"fail recent: 0", "fail nullable: NULL", "pass ok: 1"},
		},
		{
			name:    "empty string",
			answers: map[string]answer{"q": {val: ""}},
			checks:  []CustomCheck{{"e", "q"}},
			want:    receipt.Fail,
			reason:  `custom check "e" failed: returned ""`,
			details: []string{`fail e: ""`},
		},
		{
			name:    "SQL error fails",
			answers: map[string]answer{"q": {err: errors.New(`ERROR:  relation "nope" does not exist`)}},
			checks:  []CustomCheck{{"missing", "q"}},
			want:    receipt.Fail,
			reason:  `custom check "missing" failed: ERROR:  relation "nope" does not exist`,
			details: []string{`fail missing: ERROR:  relation "nope" does not exist`},
		},
		{
			name:    "sandbox failure is an ERROR, not a FAIL",
			answers: map[string]answer{"q": {err: fmt.Errorf("%w: sandbox container was OOM-killed", engine.ErrSandbox)}},
			checks:  []CustomCheck{{"c", "q"}},
			want:    receipt.Error,
			reason:  `custom check "c" could not run: sandbox failed: sandbox container was OOM-killed`,
			details: []string{"error c: sandbox failed: sandbox container was OOM-killed"},
		},
		{
			name: "a definite FAIL outranks a sandbox ERROR",
			answers: map[string]answer{
				"q1": {err: fmt.Errorf("%w: died", engine.ErrSandbox)},
				"q2": {val: "f"},
			},
			checks:  []CustomCheck{{"a", "q1"}, {"b", "q2"}},
			want:    receipt.Fail,
			reason:  `custom check "b" failed: returned f`,
			details: []string{"error a: sandbox failed: died", "fail b: f"},
		},
		{
			name:    "long values are truncated to 200 characters",
			answers: map[string]answer{"q": {val: long}},
			checks:  []CustomCheck{{"long", "q"}},
			want:    receipt.Pass,
			details: []string{"pass long: " + strings.Repeat("é", 200-len("long: ")-1) + "…"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eng := &queryEngine{fakeEngine: &fakeEngine{outcome: passOutcome}, answers: tt.answers}
			res, r := runOne(t, eng, Options{Checks: tt.checks})
			if res.Status != tt.want || res.Reason != tt.reason {
				t.Errorf("result %s %q, want %s %q", res.Status, res.Reason, tt.want, tt.reason)
			}
			if r.Result != tt.want || r.Reason != tt.reason {
				t.Errorf("receipt %s %q, want %s %q", r.Result, r.Reason, tt.want, tt.reason)
			}
			var got []string
			for _, c := range customChecks(r) {
				got = append(got, c.Status+" "+c.Detail)
				if n := utf8.RuneCountInString(c.Detail); n > 200 {
					t.Errorf("detail is %d characters", n)
				}
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.details) {
				t.Errorf("checks\n got %q\nwant %q", got, tt.details)
			}
			if eng.sessions != eng.closed {
				t.Errorf("sandbox leak: %d started, %d closed", eng.sessions, eng.closed)
			}
		})
	}
}

func TestCustomChecksNotRun(t *testing.T) {
	checks := []CustomCheck{{"a", "SELECT 1"}}

	// The restore failed: the checks are recorded as skipped and the FAIL stands.
	eng := &queryEngine{fakeEngine: &fakeEngine{outcome: engine.Outcome{Result: receipt.Fail, Reason: "pg_restore failed"}}}
	res, r := runOne(t, eng, Options{Checks: checks})
	if res.Status != receipt.Fail || res.Reason != "pg_restore failed" || len(eng.queries) != 0 {
		t.Errorf("got %s %q after %d queries", res.Status, res.Reason, len(eng.queries))
	}
	if cs := customChecks(r); len(cs) != 1 || cs[0].Status != receipt.CheckSkip || cs[0].Detail != "a: not run: the restore did not pass" {
		t.Errorf("checks %+v", cs)
	}

	// An engine without SQL: skipped, the PASS stands.
	res, r = runOne(t, &fakeEngine{outcome: passOutcome}, Options{Checks: checks})
	if res.Status != receipt.Pass {
		t.Errorf("got %s %q", res.Status, res.Reason)
	}
	if cs := customChecks(r); len(cs) != 1 || cs[0].Status != receipt.CheckSkip || !strings.Contains(cs[0].Detail, "don't support SQL checks") {
		t.Errorf("checks %+v", cs)
	}

	// No --check: no l3.custom checks at all.
	_, r = runOne(t, &queryEngine{fakeEngine: &fakeEngine{outcome: passOutcome}}, Options{})
	if cs := customChecks(r); len(cs) != 0 {
		t.Errorf("checks %+v", cs)
	}
}
