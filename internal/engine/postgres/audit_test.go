package postgres

import (
	"reflect"
	"strings"
	"testing"
)

func TestRowCounts(t *testing.T) {
	dump := strings.Join([]string{
		`COPY public.customers (id, name) FROM stdin;`,
		"1\tann",
		"2\tbob",
		`\.`,
		`COPY public."Order Items" (id) FROM stdin;`,
		`\.`,
		`COPY sales.orders FROM stdin;`,
		"1",
		`\.`,
		`\connect -reuse-previous=on "dbname='Other DB'"`,
		`COPY public.customers (id) FROM stdin;`,
		"9",
		`\.`,
		`\connect shop`,
		`COPY "We""ird".t (id) FROM stdin;`,
		"1",
		"2",
		"3",
		`\.`,
		"",
	}, "\n")
	a := NewPlainAnalyzer()
	a.Write([]byte(dump))
	want := map[string]int64{
		TableKey("", "public.customers"):         2,
		TableKey("", "public.Order Items"):       0,
		TableKey("", "sales.orders"):             1,
		TableKey("Other DB", "public.customers"): 1,
		TableKey("shop", `We"ird.t`):             3,
	}
	if !reflect.DeepEqual(a.Rows, want) {
		t.Errorf("rows = %q\nwant  %q", a.Rows, want)
	}
}

func TestAuditRows(t *testing.T) {
	dump := map[string]int64{
		TableKey("", "public.customers"): 5000,
		TableKey("", "public.orders"):    40000,
		TableKey("", "public.empty"):     0,
		TableKey("", "public.gone"):      7,
		TableKey("shop", "public.t"):     3,
	}
	tests := []struct {
		name     string
		restored []TableCount
		want     []string // substrings, one per problem, in order
	}{
		{
			name: "everything matches",
			restored: []TableCount{
				NewTableCount("", "public.customers", 'r', 5000), NewTableCount("", "public.orders", 'r', 40000),
				NewTableCount("", "public.empty", 'r', 0), NewTableCount("", "public.gone", 'r', 7), NewTableCount("shop", "public.t", 'r', 3),
			},
		},
		{
			name: "rows lost and a table missing",
			restored: []TableCount{
				NewTableCount("", "public.customers", 'r', 5000), NewTableCount("", "public.orders", 'r', 27550),
				NewTableCount("", "public.empty", 'r', 0), NewTableCount("shop", "public.t", 'r', 0),
			},
			want: []string{"public.gone has 7 rows in the dump but is missing", "public.orders has 40000 rows in the dump, 27550 restored (−12450)", "shop:public.t has 3 rows in the dump, 0 restored"},
		},
		{
			name: "data loaded via the partition root counts",
			restored: []TableCount{
				NewTableCount("", "public.customers", 'r', 5000), NewTableCount("", "public.orders", 'p', 40000),
				NewTableCount("", "public.empty", 'r', 0), NewTableCount("", "public.gone", 'r', 7), NewTableCount("shop", "public.t", 'r', 3),
			},
		},
	}
	for _, tt := range tests {
		got := AuditRows(dump, tt.restored)
		if len(got) != len(tt.want) {
			t.Errorf("%s: problems %q, want %d", tt.name, got, len(tt.want))
			continue
		}
		for i := range got {
			if !strings.Contains(got[i], tt.want[i]) {
				t.Errorf("%s: problem %d = %q, want it to contain %q", tt.name, i, got[i], tt.want[i])
			}
		}
	}
}

func TestParseConnect(t *testing.T) {
	for in, want := range map[string]string{
		`\connect shop`:    "shop",
		`\connect "Mixed"`: "Mixed",
		`\connect -reuse-previous=on "dbname='it''s'"`: "it's",
		`\c other`: "other",
	} {
		if got := parseConnect(in); got != want {
			t.Errorf("parseConnect(%q) = %q, want %q", in, got, want)
		}
	}
}
