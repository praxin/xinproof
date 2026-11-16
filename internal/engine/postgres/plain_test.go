package postgres

import (
	"reflect"
	"strings"
	"testing"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/receipt"
)

const goodPlain = `--
-- PostgreSQL database dump
--

-- Dumped from database version 16.4
-- Dumped by pg_dump version 16.4

SET statement_timeout = 0;

CREATE TABLE public.customers (
    id integer NOT NULL,
    name text
);

ALTER TABLE public.customers OWNER TO app_owner;

CREATE UNLOGGED TABLE public.sessions (
    id integer
);

ALTER TABLE public.sessions OWNER TO "Weird Owner";

COPY public.customers (id, name) FROM stdin;
1	CREATE TABLE inside data must not count
2	OWNER TO not_a_role;
\.

GRANT SELECT ON TABLE public.customers TO reporting, PUBLIC;
REVOKE ALL ON SCHEMA public FROM legacy_user CASCADE;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO readers;

--
-- PostgreSQL database dump complete
--

\unrestrict abc123
`

func analyze(s string, chunk int) *PlainAnalyzer {
	a := NewPlainAnalyzer()
	for len(s) > 0 {
		n := chunk
		if n > len(s) {
			n = len(s)
		}
		a.Write([]byte(s[:n]))
		s = s[n:]
	}
	return a
}

func TestPlainAnalyzer(t *testing.T) {
	cut := strings.Index(goodPlain, "2\tOWNER")
	tests := []struct {
		name       string
		in         string
		wantStatus string
		detail     string
		tables     int
	}{
		{name: "complete dump", in: goodPlain, wantStatus: receipt.CheckPass, tables: 2},
		{name: "truncated inside COPY data", in: goodPlain[:cut], wantStatus: receipt.CheckFail, detail: "inside a table's COPY data", tables: 2},
		{name: "truncated after COPY, before trailer", in: goodPlain[:strings.Index(goodPlain, "GRANT")], wantStatus: receipt.CheckFail, detail: "trailer is missing", tables: 2},
		{name: "truncated at 10%", in: goodPlain[:len(goodPlain)/10], wantStatus: receipt.CheckFail, detail: "trailer is missing"},
		{name: "empty body", in: "", wantStatus: receipt.CheckFail, detail: "trailer is missing"},
		{name: "crlf line endings", in: strings.ReplaceAll(goodPlain, "\n", "\r\n"), wantStatus: receipt.CheckPass, tables: 2},
	}
	for _, tt := range tests {
		for _, chunk := range []int{1, 7, 4096} { // results must not depend on how the stream is chunked
			a := analyze(tt.in, chunk)
			checks := a.Finish()
			if len(checks) != 1 || checks[0].Status != tt.wantStatus || !strings.Contains(checks[0].Detail, tt.detail) {
				t.Errorf("%s (chunk %d): checks = %+v, want %s containing %q", tt.name, chunk, checks, tt.wantStatus, tt.detail)
			}
			if tt.tables > 0 && a.Tables != tt.tables {
				t.Errorf("%s (chunk %d): tables = %d, want %d", tt.name, chunk, a.Tables, tt.tables)
			}
		}
	}
}

func TestPlaceholderRoles(t *testing.T) {
	a := analyze(goodPlain, 13)
	got := a.PlaceholderRoles("xinproof")
	want := []string{"Weird Owner", "app_owner", "legacy_user", "readers", "reporting"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("roles = %q, want %q", got, want)
	}

	// pg_dumpall creates its own roles; those must not get placeholders.
	all := analyze("CREATE ROLE app_owner;\nALTER ROLE app_owner WITH NOLOGIN;\nCREATE ROLE postgres;\n"+goodPlain, 4096)
	for _, r := range all.PlaceholderRoles("xinproof") {
		if r == "app_owner" || r == "postgres" {
			t.Errorf("placeholder created for role %q that the dump creates", r)
		}
	}
}

func TestParseIdents(t *testing.T) {
	tests := map[string][]string{
		`app`:                    {"app"},
		`App, "Mixed Case"`:      {"app", "Mixed Case"},
		`"a,b", c`:               {"a,b", "c"},
		`"quote""inside"`:        {`quote"inside`},
		`PUBLIC`:                 nil,
		`GROUP admins, CURRENT_USER`: {"admins"},
	}
	for in, want := range tests {
		if got := parseIdents(in); !reflect.DeepEqual(got, want) {
			t.Errorf("parseIdents(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCountTOC(t *testing.T) {
	toc := `;
; Archive created at 2026-11-16 14:21:07 UTC
;     dbname: shop
;
; Selected TOC Entries:
;
215; 1259 16385 TABLE public customers app
216; 1259 16390 TABLE public orders app
217; 1259 16395 TABLE public orders_2026 app
3300; 0 0 TABLE ATTACH public orders_2026 app
218; 1259 16400 SEQUENCE public orders_id_seq app
3301; 0 16385 TABLE DATA public customers app
3302; 0 16390 TABLE DATA public orders app
3303; 2606 16410 CONSTRAINT public customers customers_pkey app
`
	tables, entries := CountTOC(toc)
	if tables != 3 || entries != 8 {
		t.Errorf("CountTOC = %d tables, %d entries; want 3, 8", tables, entries)
	}
}

func TestImageFor(t *testing.T) {
	e := &Engine{}
	tests := []struct {
		det  discover.Detection
		want string
	}{
		{discover.Detection{DumpVersion: "16.4"}, "postgres:16"},
		{discover.Detection{DumpVersion: "17.2", ServerVersion: "15.8"}, "postgres:17"},
		{discover.Detection{ServerVersion: "14.11"}, "postgres:14"},
		{discover.Detection{DumpVersion: "9.6.24"}, "postgres:9.6"},
		{discover.Detection{}, "postgres:" + DefaultMajor},
		{discover.Detection{DumpVersion: "garbage"}, "postgres:" + DefaultMajor},
	}
	for _, tt := range tests {
		if got := e.ImageFor(tt.det); got != tt.want {
			t.Errorf("ImageFor(%+v) = %s, want %s", tt.det, got, tt.want)
		}
	}
	if got := (&Engine{Image: "custom:1"}).ImageFor(discover.Detection{DumpVersion: "16"}); got != "custom:1" {
		t.Errorf("override ignored: %s", got)
	}
}

func TestFirstErrors(t *testing.T) {
	stderr := "pg_restore: connecting to database for restore\npg_restore: error: could not read from input file: end of file\n"
	if got := firstErrors(stderr); got != "pg_restore: error: could not read from input file: end of file" {
		t.Errorf("firstErrors = %q", got)
	}
}
