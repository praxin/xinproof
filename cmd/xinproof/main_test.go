package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/verify"
)

func TestCheckFlag(t *testing.T) {
	var c customChecks
	for _, s := range []string{
		"orders_recent=SELECT count(*) > 0 FROM orders WHERE created_at > now() - interval '1 day'",
		"has.users-v2=SELECT 1 WHERE 'a=b' = 'a=b'",
	} {
		if err := c.Set(s); err != nil {
			t.Fatalf("Set(%q): %v", s, err)
		}
	}
	want := []verify.CustomCheck{
		{Name: "orders_recent", SQL: "SELECT count(*) > 0 FROM orders WHERE created_at > now() - interval '1 day'"},
		{Name: "has.users-v2", SQL: "SELECT 1 WHERE 'a=b' = 'a=b'"},
	}
	if len(c) != 2 || c[0] != want[0] || c[1] != want[1] {
		t.Errorf("got %+v", c)
	}
	if err := c.Set("orders_recent=SELECT 1"); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Errorf("duplicate name: err = %v", err)
	}
}

func TestCheckFlagRejectsBadInput(t *testing.T) {
	for _, arg := range []string{
		"no-equals-sign",
		"=SELECT 1",
		"bad name=SELECT 1",
		"semi;colon=SELECT 1",
		strings.Repeat("x", 65) + "=SELECT 1",
		"blank=   ",
	} {
		var stderr bytes.Buffer
		code := run([]string{"verify", "--check", arg, t.TempDir()}, &bytes.Buffer{}, &stderr)
		if code != exitUsage {
			t.Errorf("--check %q: exit %d, want %d (usage)", arg, code, exitUsage)
		}
		if !strings.Contains(stderr.String(), "custom check") {
			t.Errorf("--check %q: stderr %q does not explain the problem", arg, stderr.String())
		}
	}
}
