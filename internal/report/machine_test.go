package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source"
	"github.com/praxin/xinproof/internal/verify"
)

func sampleRun() Run {
	rc := &receipt.Receipt{ID: "rcpt_X", Subject: receipt.Subject{SHA256: "ab", Format: "postgres-custom"},
		Measured: receipt.Measured{RestoreSeconds: 4.2, TotalSeconds: 6},
		Checks:   []receipt.Check{{ID: "l2.restore", Status: "pass", Detail: "exit 0"}}}
	return Run{
		Tool: receipt.Tool{Name: "xinproof", Version: "0.1.0"}, Location: "s3://acme/pg/",
		StartedAt: time.Date(2026, 11, 16, 14, 0, 0, 0, time.UTC), ExitCode: 1,
		Results: []verify.Result{
			{Object: source.Object{Name: "good.dump", URL: "s3://acme/pg/good.dump", Size: 10}, Status: receipt.Pass,
				Tables: 214, Rows: 38_100_000, RowsKnown: true, Restore: 4200 * time.Millisecond, Total: 6 * time.Second,
				Receipt: rc, ReceiptPath: "receipts/receipt-000001.json"},
			{Object: source.Object{Name: "bad.dump", URL: "s3://acme/pg/bad.dump"}, Status: receipt.Fail, Reason: "truncated <&> \"x\""},
			{Object: source.Object{Name: "my.sql", URL: "s3://acme/pg/my.sql"}, Status: receipt.Error, Reason: "MySQL engine not in this release"},
		},
	}
}

func TestJSONReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJSON(&b, sampleRun()); err != nil {
		t.Fatal(err)
	}
	var rep JSONReport
	if err := json.Unmarshal(b.Bytes(), &rep); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	if rep.Schema != JSONSchema || rep.ExitCode != 1 || rep.Summary != (JSONSummary{Total: 3, Pass: 1, Fail: 1, Error: 1}) {
		t.Errorf("report header = %+v", rep)
	}
	g := rep.Results[0]
	if g.Tables == nil || *g.Tables != 214 || *g.Rows != 38_100_000 || g.ReceiptID != "rcpt_X" || g.RestoreSeconds != 4.2 || len(g.Checks) != 1 {
		t.Errorf("good result = %+v", g)
	}
	if rep.Results[1].Tables != nil || rep.Results[1].Checks == nil {
		t.Errorf("FAIL result should have no counts and an empty (not null) checks list: %+v", rep.Results[1])
	}
	if !strings.Contains(b.String(), `truncated <&> \"x\"`) {
		t.Error("JSON report HTML-escaped the reason")
	}

	b.Reset()
	WriteJSON(&b, Run{Location: "./x", ExitCode: 2, Err: errors.New("no backups found")})
	if !strings.Contains(b.String(), `"results": []`) || !strings.Contains(b.String(), `"error": "no backups found"`) {
		t.Errorf("empty run:\n%s", b.String())
	}
}

func TestJUnitReport(t *testing.T) {
	var b bytes.Buffer
	if err := WriteJUnit(&b, sampleRun()); err != nil {
		t.Fatal(err)
	}
	var doc junitSuites
	if err := xml.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid XML: %v\n%s", err, b.String())
	}
	s := doc.Suites[0]
	if doc.Tests != 3 || doc.Failures != 1 || doc.Errors != 1 || len(s.Cases) != 3 {
		t.Fatalf("counts: %+v", doc)
	}
	if s.Cases[0].Failure != nil || s.Cases[0].Error != nil {
		t.Error("PASS case has a failure")
	}
	if s.Cases[1].Failure == nil || s.Cases[1].Failure.Message != `truncated <&> "x"` {
		t.Errorf("FAIL case = %+v", s.Cases[1])
	}
	if s.Cases[2].Error == nil || s.Cases[2].Error.Type != "ERROR" {
		t.Errorf("ERROR case = %+v", s.Cases[2])
	}

	b.Reset()
	WriteJUnit(&b, Run{Location: "./x", Err: errors.New("no backups found")})
	if !strings.Contains(b.String(), `errors="1"`) {
		t.Errorf("nothing-found run must show as an error in CI:\n%s", b.String())
	}
}
