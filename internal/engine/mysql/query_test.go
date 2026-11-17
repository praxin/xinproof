package mysql

import (
	"strings"
	"testing"
)

const xmlHead = `<?xml version="1.0"?>

<resultset statement="SELECT x" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`

func TestParseXMLValue(t *testing.T) {
	tests := []struct {
		name, out string
		val       string
		null      bool
		errMatch  string
	}{
		{name: "number", out: xmlHead + "\n  <row>\n\t<field name=\"COUNT(*) = 3\">1</field>\n  </row>\n</resultset>\n", val: "1"},
		{name: "escaped multiline", out: xmlHead + "<row><field name=\"v\">a &lt;b&gt; &amp;\nc</field></row></resultset>", val: "a <b> &\nc"},
		{name: "empty string", out: xmlHead + "<row><field name=\"v\"></field></row></resultset>", val: ""},
		{name: "null", out: xmlHead + "<row><field name=\"v\" xsi:nil=\"true\" /></row></resultset>", null: true},
		{name: "no rows", out: xmlHead + "</resultset>", errMatch: "no rows"},
		{name: "no output", out: "", errMatch: "no rows"},
		{name: "two rows", out: xmlHead + "<row><field name=\"v\">1</field></row><row><field name=\"v\">2</field></row></resultset>", errMatch: "2 rows"},
		{name: "two columns", out: xmlHead + "<row><field name=\"a\">1</field><field name=\"b\">2</field></row></resultset>", errMatch: "2 columns"},
		{name: "two result sets", out: xmlHead + "<row><field name=\"v\">1</field></row></resultset>\n" + xmlHead + "<row><field name=\"v\">2</field></row></resultset>", errMatch: "2 rows"},
	}
	for _, tt := range tests {
		val, null, err := parseXMLValue([]byte(tt.out))
		if tt.errMatch != "" {
			if err == nil || !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("%s: err = %v, want %q", tt.name, err, tt.errMatch)
			}
			continue
		}
		if err != nil || val != tt.val || null != tt.null {
			t.Errorf("%s: got %q null=%v err=%v", tt.name, val, null, err)
		}
	}
}
