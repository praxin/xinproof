package engine

import (
	"fmt"
	"sort"
	"strings"
)

// TableKey identifies a table across databases. db "" is the database the
// dump was restored into (when the dump doesn't name its own databases).
func TableKey(db, qualified string) string { return db + "\x00" + qualified }

// SplitTableKey is the inverse of TableKey.
func SplitTableKey(k string) (db, qualified string) {
	db, qualified, _ = strings.Cut(k, "\x00")
	return db, qualified
}

// TableCount is one restored table with its exact row count.
type TableCount struct {
	DB        string // "" for the database the dump was restored into
	Qualified string // e.g. "public.orders" (Postgres) or "orders" (MySQL)
	Kind      byte   // engine-specific; Postgres: 'r' table, 'p' partitioned parent
	Rows      int64
}

// AuditRows compares the rows each table holds in the dump with what was
// restored and describes every table that lost rows, sorted by table.
func AuditRows(dump map[string]int64, restored []TableCount) []string {
	have := map[string]int64{}
	for _, t := range restored {
		have[TableKey(t.DB, t.Qualified)] = t.Rows
	}
	keys := make([]string, 0, len(dump))
	for k := range dump {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var problems []string
	for _, k := range keys {
		want := dump[k]
		db, name := SplitTableKey(k)
		if db != "" {
			name = db + ":" + name
		}
		got, ok := have[k]
		switch {
		case !ok && want > 0:
			problems = append(problems, fmt.Sprintf("%s has %d rows in the dump but is missing after restore", name, want))
		case ok && got < want:
			problems = append(problems, fmt.Sprintf("%s has %d rows in the dump, %d restored (−%d)", name, want, got, want-got))
		}
	}
	return problems
}

// SummarizeProblems joins up to three problems and says how many more there are.
func SummarizeProblems(problems []string) string {
	s := strings.Join(problems[:min(3, len(problems))], "; ")
	if len(problems) > 3 {
		s += fmt.Sprintf("; and %d more", len(problems)-3)
	}
	return s
}
