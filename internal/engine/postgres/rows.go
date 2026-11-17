package postgres

import "github.com/praxin/xinproof/internal/engine"

// Row-audit helpers shared by all engines; see package engine.
type TableCount = engine.TableCount

func TableKey(db, qualified string) string          { return engine.TableKey(db, qualified) }
func SplitTableKey(k string) (db, qualified string) { return engine.SplitTableKey(k) }

func AuditRows(dump map[string]int64, restored []TableCount) []string {
	return engine.AuditRows(dump, restored)
}

func NewTableCount(db, qualified string, kind byte, rows int64) TableCount {
	return TableCount{DB: db, Qualified: qualified, Kind: kind, Rows: rows}
}
