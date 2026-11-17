package mysql

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

// Analyzer inspects mysqldump / mariadb-dump output as it streams past. It
// counts CREATE TABLE statements and the rows each INSERT adds per table
// (parsing extended inserts with quotes and escapes, without buffering the
// huge lines), and finds truncation: a dump that stops inside an INSERT, or
// whose closing "-- Dump completed" marker is missing.
type Analyzer struct {
	line     []byte
	overflow bool
	bytes    int64
	tail     []byte

	sawHeader bool // "-- MySQL dump" / "-- MariaDB dump" comment header
	completed bool // "-- Dump completed" seen

	// INSERT state
	inInsert bool
	key      string
	depth    int
	quote    byte // 0, or the quote character we are inside
	escape   bool

	db     string
	Tables int
	// Rows is the number of rows the dump inserts per table, keyed by
	// engine.TableKey(database, table). Database is "" until a USE statement.
	Rows map[string]int64
}

const maxLine = 1 << 20

func NewAnalyzer() *Analyzer { return &Analyzer{Rows: map[string]int64{}} }

func (a *Analyzer) Write(p []byte) (int, error) {
	n := len(p)
	a.bytes += int64(n)
	a.tail = append(a.tail, p...)
	if len(a.tail) > 2048 {
		a.tail = append(a.tail[:0], a.tail[len(a.tail)-1024:]...)
	}
	for len(p) > 0 {
		if a.inInsert {
			p = p[a.feedInsert(p):]
			continue
		}
		j := bytes.IndexByte(p, '\n')
		seg := p
		if j >= 0 {
			seg = p[:j]
		}
		a.appendLine(seg)
		if a.startInsert() {
			if j >= 0 {
				p = p[j:] // the newline is handled in INSERT mode or as an empty line
			} else {
				p = nil
			}
			continue
		}
		if j < 0 {
			break
		}
		a.processLine(strings.TrimSuffix(string(a.line), "\r"))
		a.line, a.overflow = a.line[:0], false
		p = p[j+1:]
	}
	return n, nil
}

func (a *Analyzer) appendLine(p []byte) {
	if a.overflow {
		return
	}
	if len(a.line)+len(p) > maxLine {
		a.overflow = true
		p = p[:maxLine-len(a.line)]
	}
	a.line = append(a.line, p...)
}

var (
	reInsert      = regexp.MustCompile("^(?:INSERT|REPLACE)(?:\\s+(?:IGNORE|LOW_PRIORITY|DELAYED|HIGH_PRIORITY))*\\s+INTO\\s+((?:`(?:[^`]|``)+`|[A-Za-z0-9_$]+)(?:\\.(?:`(?:[^`]|``)+`|[A-Za-z0-9_$]+))?)")
	reValues      = regexp.MustCompile(`\bVALUES\s*`)
	reCreateTable = regexp.MustCompile("^CREATE TABLE (?:IF NOT EXISTS )?((?:`(?:[^`]|``)+`|[A-Za-z0-9_$]+)(?:\\.(?:`(?:[^`]|``)+`|[A-Za-z0-9_$]+))?)")
	reUse         = regexp.MustCompile("^USE ((?:`(?:[^`]|``)+`)|[A-Za-z0-9_$]+);")
)

// startInsert switches to INSERT mode once the current line has reached its
// VALUES keyword, then feeds the rest of the line to the tuple counter.
func (a *Analyzer) startInsert() bool {
	if len(a.line) < 6 || (a.line[0] != 'I' && a.line[0] != 'R') {
		return false
	}
	m := reInsert.FindSubmatchIndex(a.line)
	if m == nil {
		return false
	}
	loc := reValues.FindIndex(a.line[m[1]:])
	if loc == nil {
		return false // VALUES not reached yet (or INSERT ... SELECT, which adds no literal rows)
	}
	db, table := splitName(string(a.line[m[2]:m[3]]))
	if db == "" {
		db = a.db
	}
	a.key = engine.TableKey(db, table)
	if _, ok := a.Rows[a.key]; !ok {
		a.Rows[a.key] = 0
	}
	a.inInsert, a.depth, a.quote, a.escape = true, 0, 0, false
	rest := append([]byte(nil), a.line[m[1]+loc[1]:]...)
	a.line, a.overflow = a.line[:0], false
	if n := a.feedInsert(rest); n < len(rest) {
		// The statement ended on this line; anything after ';' is whitespace.
		_ = n
	}
	return true
}

// feedInsert counts top-level "(...)" tuples until the statement's ';'. It
// returns how many bytes it consumed (stopping right after the ';').
func (a *Analyzer) feedInsert(p []byte) int {
	for i, c := range p {
		if a.quote != 0 {
			switch {
			case a.escape:
				a.escape = false
			case c == '\\' && a.quote != '`':
				a.escape = true
			case c == a.quote:
				a.quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			a.quote = c
		case '(':
			if a.depth == 0 {
				a.Rows[a.key]++
			}
			a.depth++
		case ')':
			if a.depth > 0 {
				a.depth--
			}
		case ';':
			if a.depth == 0 {
				a.inInsert = false
				return i + 1
			}
		}
	}
	return len(p)
}

func (a *Analyzer) processLine(l string) {
	switch {
	case strings.HasPrefix(l, "-- MySQL dump") || strings.HasPrefix(l, "-- MariaDB dump"):
		a.sawHeader = true
	case strings.HasPrefix(l, "-- Dump completed"):
		a.completed = true
	case strings.HasPrefix(l, "CREATE TABLE "):
		if m := reCreateTable.FindStringSubmatch(l); m != nil {
			a.Tables++
			db, table := splitName(m[1])
			if db == "" {
				db = a.db
			}
			if _, ok := a.Rows[engine.TableKey(db, table)]; !ok {
				a.Rows[engine.TableKey(db, table)] = 0
			}
		}
	case strings.HasPrefix(l, "USE "):
		if m := reUse.FindStringSubmatch(l); m != nil {
			a.db = unquote(m[1])
		}
	}
}

// Finish reports whether the dump is complete.
func (a *Analyzer) Finish() []receipt.Check {
	if len(a.line) > 0 && !a.inInsert {
		a.processLine(string(a.line))
		a.line = a.line[:0]
	}
	fail := func(d string) []receipt.Check {
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckFail, Detail: d}}
	}
	if a.inInsert {
		_, table := engine.SplitTableKey(a.key)
		return fail(fmt.Sprintf("dump ends inside an INSERT into %s at byte %d (truncated)", table, a.bytes))
	}
	notes := bytes.Contains(a.tail, []byte("SET SQL_NOTES=@OLD_SQL_NOTES"))
	switch {
	case a.completed:
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass, Detail: "complete dump ('-- Dump completed' marker present)"}}
	case a.sawHeader:
		return fail(fmt.Sprintf("dump is incomplete: the closing '-- Dump completed' line is missing (truncated at byte %d?)", a.bytes))
	case notes:
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass, Detail: "complete dump (closing session-restore statements present)"}}
	case bytes.HasSuffix(bytes.TrimSpace(a.tail), []byte(";")):
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass,
			Detail: "dump has no closing marker (compact dump?); it ends on a complete statement, but truncation at a statement boundary can't be ruled out"}}
	}
	return fail(fmt.Sprintf("dump ends mid-statement at byte %d (truncated)", a.bytes))
}

// splitName splits `db`.`table` or `table` into unquoted parts.
func splitName(s string) (db, table string) {
	var parts []string
	for len(s) > 0 {
		if s[0] == '`' {
			i := 1
			for i < len(s) {
				if s[i] == '`' {
					if i+1 < len(s) && s[i+1] == '`' {
						i += 2
						continue
					}
					break
				}
				i++
			}
			parts = append(parts, strings.ReplaceAll(s[1:min(i, len(s))], "``", "`"))
			s = s[min(i+1, len(s)):]
		} else {
			j := strings.IndexByte(s, '.')
			if j < 0 {
				j = len(s)
			}
			parts = append(parts, s[:j])
			s = s[j:]
		}
		s = strings.TrimPrefix(s, ".")
	}
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return "", parts[0]
	}
	return "", ""
}

func unquote(s string) string {
	if strings.HasPrefix(s, "`") && strings.HasSuffix(s, "`") && len(s) >= 2 {
		return strings.ReplaceAll(s[1:len(s)-1], "``", "`")
	}
	return s
}
