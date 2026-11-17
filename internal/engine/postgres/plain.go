package postgres

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/praxin/xinproof/internal/receipt"
)

// PlainAnalyzer inspects a plain-SQL pg_dump/pg_dumpall stream as it passes
// through. It finds truncation (missing "dump complete" trailer, stream ending
// inside COPY data), counts CREATE TABLE statements, and collects roles the
// dump references but doesn't create, so the sandbox can create placeholders
// instead of failing on "role does not exist".
type PlainAnalyzer struct {
	line     []byte
	overflow bool
	inCopy   bool
	bytes    int64
	tail     []byte

	Tables     int
	referenced map[string]bool
	created    map[string]bool

	// Rows is the number of data rows the dump holds per table, keyed by
	// TableKey(database, "schema.table"). Database is "" until a \connect.
	Rows       map[string]int64
	extensions map[string]bool
	db         string
	copyKey    string
}

const maxLine = 1 << 20

func NewPlainAnalyzer() *PlainAnalyzer {
	return &PlainAnalyzer{referenced: map[string]bool{}, created: map[string]bool{}, Rows: map[string]int64{}}
}

func (a *PlainAnalyzer) Write(p []byte) (int, error) {
	n := len(p)
	a.bytes += int64(n)
	a.tail = append(a.tail, p...)
	if len(a.tail) > 1024 {
		a.tail = append(a.tail[:0], a.tail[len(a.tail)-512:]...)
	}
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			a.appendLine(p)
			break
		}
		a.appendLine(p[:i])
		a.processLine(strings.TrimSuffix(string(a.line), "\r"))
		a.line, a.overflow = a.line[:0], false
		p = p[i+1:]
	}
	return n, nil
}

func (a *PlainAnalyzer) appendLine(p []byte) {
	if a.overflow {
		return
	}
	if len(a.line)+len(p) > maxLine {
		a.overflow = true // long lines are data; the prefix is enough to classify them
		p = p[:maxLine-len(a.line)]
	}
	a.line = append(a.line, p...)
}

var (
	reCreateTable = regexp.MustCompile(`^CREATE (?:UNLOGGED )?TABLE `)
	reCreateExt   = regexp.MustCompile(`^CREATE EXTENSION (?:IF NOT EXISTS )?("(?:[^"]|"")+"|[A-Za-z0-9_-]+)`)
	reOwnerTo     = regexp.MustCompile(`\bOWNER TO (.+);\s*$`)
	reGrantTo     = regexp.MustCompile(`^GRANT .+? TO (.+);\s*$`)
	reRevokeFrom  = regexp.MustCompile(`^REVOKE .+? FROM (.+);\s*$`)
	reCreateRole  = regexp.MustCompile(`^CREATE (?:ROLE|USER) ("(?:[^"]|"")+"|[^\s;]+)`)
	reForRole     = regexp.MustCompile(`^ALTER DEFAULT PRIVILEGES FOR ROLE ("(?:[^"]|"")+"|[^\s;]+)`)
	reSetAuth     = regexp.MustCompile(`^SET (?:SESSION AUTHORIZATION|ROLE) ('(?:[^']|'')+'|"(?:[^"]|"")+"|[^\s;]+)`)
	reDefaultPriv = regexp.MustCompile(`^ALTER DEFAULT PRIVILEGES .* (?:GRANT .+? TO|REVOKE .+? FROM) (.+);\s*$`)
	reTrailingOpt = regexp.MustCompile(`\s+(?:WITH (?:GRANT|ADMIN|INHERIT|SET) OPTION.*|GRANTED BY .*|CASCADE|RESTRICT)$`)
)

func (a *PlainAnalyzer) processLine(l string) {
	if a.inCopy {
		if l == `\.` {
			a.inCopy = false
		} else {
			a.Rows[a.copyKey]++
		}
		return
	}
	if strings.HasPrefix(l, "COPY ") && strings.HasSuffix(strings.TrimSpace(l), "FROM stdin;") {
		a.inCopy = true
		a.copyKey = TableKey(a.db, parseQualified(l[len("COPY "):]))
		if _, ok := a.Rows[a.copyKey]; !ok {
			a.Rows[a.copyKey] = 0
		}
		return
	}
	if strings.HasPrefix(l, `\connect `) || strings.HasPrefix(l, `\c `) {
		a.db = parseConnect(l)
		return
	}
	if m := reCreateExt.FindStringSubmatch(l); m != nil {
		if a.extensions == nil {
			a.extensions = map[string]bool{}
		}
		a.extensions[strings.Trim(m[1], `"`)] = true
	}
	if reCreateTable.MatchString(l) {
		a.Tables++
	}
	if m := reCreateRole.FindStringSubmatch(l); m != nil {
		for _, r := range parseIdents(m[1]) {
			a.created[r] = true
		}
	}
	if m := reOwnerTo.FindStringSubmatch(l); m != nil {
		a.ref(m[1])
	}
	if m := reGrantTo.FindStringSubmatch(l); m != nil {
		a.ref(reTrailingOpt.ReplaceAllString(m[1], ""))
	}
	if m := reRevokeFrom.FindStringSubmatch(l); m != nil {
		a.ref(reTrailingOpt.ReplaceAllString(m[1], ""))
	}
	if m := reForRole.FindStringSubmatch(l); m != nil {
		a.ref(m[1])
	}
	if m := reDefaultPriv.FindStringSubmatch(l); m != nil {
		a.ref(reTrailingOpt.ReplaceAllString(m[1], ""))
	}
	if m := reSetAuth.FindStringSubmatch(l); m != nil {
		v := m[1]
		if strings.HasPrefix(v, "'") { // SET SESSION AUTHORIZATION 'name'
			v = `"` + strings.ReplaceAll(strings.ReplaceAll(strings.Trim(v, "'"), "''", "'"), `"`, `""`) + `"`
		}
		a.ref(v)
	}
}

func (a *PlainAnalyzer) ref(list string) {
	for _, r := range parseIdents(list) {
		a.referenced[r] = true
	}
}

// PlaceholderRoles are roles the dump uses but never creates, sorted.
func (a *PlainAnalyzer) PlaceholderRoles(exclude ...string) []string {
	skip := map[string]bool{}
	for _, e := range exclude {
		skip[e] = true
	}
	var out []string
	for r := range a.referenced {
		if !a.created[r] && !skip[r] {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// Finish reports structural checks on the whole stream.
func (a *PlainAnalyzer) Finish() []receipt.Check {
	if len(a.line) > 0 {
		a.processLine(string(a.line))
		a.line = a.line[:0]
	}
	if a.inCopy {
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckFail,
			Detail: fmt.Sprintf("dump ends inside a table's COPY data at byte %d (truncated)", a.bytes)}}
	}
	if !bytes.Contains(a.tail, []byte("dump complete")) {
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckFail,
			Detail: fmt.Sprintf("dump is incomplete: the 'PostgreSQL database dump complete' trailer is missing (truncated at byte %d?)", a.bytes)}}
	}
	return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass, Detail: "complete plain-SQL dump (trailer present)"}}
}

// parseIdents splits a comma-separated list of SQL identifiers, unquoting
// quoted ones and lower-casing bare ones. Pseudo-roles are dropped.
func parseIdents(s string) []string {
	var out []string
	var cur strings.Builder
	inQ := false
	flush := func() {
		t := strings.TrimSpace(cur.String())
		cur.Reset()
		if t == "" {
			return
		}
		if strings.HasPrefix(t, `"`) && strings.HasSuffix(t, `"`) && len(t) >= 2 {
			out = append(out, strings.ReplaceAll(t[1:len(t)-1], `""`, `"`))
			return
		}
		switch strings.ToUpper(t) {
		case "PUBLIC", "CURRENT_USER", "SESSION_USER", "CURRENT_ROLE", "DEFAULT", "NONE":
			return
		}
		if strings.HasPrefix(strings.ToUpper(t), "GROUP ") {
			t = strings.TrimSpace(t[6:])
		}
		out = append(out, strings.ToLower(t))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQ = !inQ
			cur.WriteByte(c)
		case c == ',' && !inQ:
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// parseQualified reads `schema.table` (either part possibly quoted) from the
// start of s and returns it unquoted, as pg_catalog stores it.
func parseQualified(s string) string {
	var parts []string
	i := 0
	for len(parts) < 2 && i < len(s) {
		var id strings.Builder
		if s[i] == '"' {
			i++
			for i < len(s) {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						id.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				id.WriteByte(s[i])
				i++
			}
		} else {
			for i < len(s) && s[i] != '.' && s[i] != ' ' && s[i] != '(' {
				id.WriteByte(s[i])
				i++
			}
		}
		parts = append(parts, id.String())
		if i < len(s) && s[i] == '.' {
			i++
			continue
		}
		break
	}
	if len(parts) == 1 {
		return "public." + parts[0]
	}
	return strings.Join(parts, ".")
}

// parseConnect returns the database named by a psql \connect line, as written by
// pg_dump -C and pg_dumpall: `\connect name`, `\connect "Name"` or
// `\connect -reuse-previous=on "dbname='name'"`.
func parseConnect(l string) string {
	f := strings.Fields(l)
	if len(f) < 2 {
		return ""
	}
	arg := f[1]
	if strings.HasPrefix(arg, "-reuse-previous") && len(f) > 2 {
		arg = strings.Join(f[2:], " ")
		arg = strings.Trim(arg, `"`)
		if v, ok := strings.CutPrefix(arg, "dbname="); ok {
			return strings.ReplaceAll(strings.Trim(v, "'"), "''", "'")
		}
		return arg
	}
	if strings.HasPrefix(arg, `"`) {
		return strings.ReplaceAll(strings.Trim(strings.Join(f[1:], " "), `"`), `""`, `"`)
	}
	return arg
}

// quoteIdent quotes a role name for SQL.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }
