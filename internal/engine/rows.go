package engine

import (
	"fmt"
	"sort"
	"strings"

	"github.com/praxin/xinproof/internal/receipt"
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

// TableName is how a table is named in receipts: its qualified name, prefixed
// with "<database>:" when it lives in a database other than the one the dump
// was restored into (the same naming as row-audit messages).
func TableName(t TableCount) string {
	if t.DB != "" {
		return t.DB + ":" + t.Qualified
	}
	return t.Qualified
}

// ReceiptTables turns restored table counts into the receipt's "tables" list:
// sorted by name and capped at receipt.MaxTables. total is how many tables
// there were before the cap.
func ReceiptTables(counts []TableCount) (tables []receipt.Table, total int) {
	if counts == nil {
		return nil, 0
	}
	tables = make([]receipt.Table, 0, len(counts))
	for _, t := range counts {
		tables = append(tables, receipt.Table{Name: TableName(t), Rows: t.Rows})
	}
	sort.Slice(tables, func(i, j int) bool { return tables[i].Name < tables[j].Name })
	total = len(tables)
	if total > receipt.MaxTables {
		tables = tables[:receipt.MaxTables]
	}
	return tables, total
}

// SummarizeProblems joins up to three problems and says how many more there are.
func SummarizeProblems(problems []string) string {
	s := strings.Join(problems[:min(3, len(problems))], "; ")
	if len(problems) > 3 {
		s += fmt.Sprintf("; and %d more", len(problems)-3)
	}
	return s
}
