package postgres

import (
	"strings"
	"testing"
)

func TestParseSingleValue(t *testing.T) {
	const null = "\x1enull-x"
	tests := []struct {
		out      string
		val      string
		isNull   bool
		errMatch string
	}{
		{out: "t\x00", val: "t"},
		{out: "40000\x00", val: "40000"},
		{out: "line 1\nline 2\x00", val: "line 1\nline 2"},
		{out: "\x00", val: ""},
		{out: null + "\x00", isNull: true},
		{out: "", errMatch: "no rows"},
		{out: "1\x002\x00", errMatch: "2 rows"},
		{out: "1\x1f2\x00", errMatch: "2 columns"},
	}
	for _, tt := range tests {
		val, isNull, err := parseSingleValue(tt.out, null)
		if tt.errMatch != "" {
			if err == nil || !strings.Contains(err.Error(), tt.errMatch) {
				t.Errorf("%q: err = %v, want %q", tt.out, err, tt.errMatch)
			}
			continue
		}
		if err != nil || val != tt.val || isNull != tt.isNull {
			t.Errorf("%q: got %q null=%v err=%v", tt.out, val, isNull, err)
		}
	}
}
