package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/verify"
)

// JSONSchema identifies the machine-readable run report (not the receipt format).
const JSONSchema = "xinproof.report/v1"

type JSONReport struct {
	Schema    string       `json:"schema"`
	Tool      receipt.Tool `json:"tool"`
	Location  string       `json:"location"`
	StartedAt string       `json:"started_at"`
	Results   []JSONResult `json:"results"`
	Summary   JSONSummary  `json:"summary"`
	ExitCode  int          `json:"exit_code"`
	Error     string       `json:"error,omitempty"` // run-level problem (e.g. listing failed, nothing found)
}

type JSONSummary struct {
	Total int `json:"total"`
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Error int `json:"error"`
}

type JSONResult struct {
	Name           string          `json:"name"`
	Source         string          `json:"source"`
	Status         receipt.Result  `json:"status"`
	Reason         string          `json:"reason,omitempty"`
	Size           int64           `json:"size"`
	SHA256         string          `json:"sha256,omitempty"`
	Format         string          `json:"format,omitempty"`
	Compression    string          `json:"compression,omitempty"`
	Tables         *int            `json:"tables,omitempty"`
	Rows           *int64          `json:"rows,omitempty"`
	RestoreSeconds float64         `json:"restore_seconds"`
	TotalSeconds   float64         `json:"total_seconds"`
	ReceiptID      string          `json:"receipt_id,omitempty"`
	ReceiptPath    string          `json:"receipt_path,omitempty"`
	Checks         []receipt.Check `json:"checks"`
}

// Run describes one verify invocation for the machine-readable reports.
type Run struct {
	Tool      receipt.Tool
	Location  string
	StartedAt time.Time
	Results   []verify.Result
	ExitCode  int
	Err       error
}

func (r Run) summary() JSONSummary {
	s := JSONSummary{Total: len(r.Results)}
	for _, res := range r.Results {
		switch res.Status {
		case receipt.Pass:
			s.Pass++
		case receipt.Fail:
			s.Fail++
		default:
			s.Error++
		}
	}
	return s
}

func WriteJSON(w io.Writer, run Run) error {
	rep := JSONReport{
		Schema:    JSONSchema,
		Tool:      run.Tool,
		Location:  run.Location,
		StartedAt: run.StartedAt.UTC().Format(time.RFC3339),
		Results:   []JSONResult{},
		Summary:   run.summary(),
		ExitCode:  run.ExitCode,
	}
	if run.Err != nil {
		rep.Error = run.Err.Error()
	}
	for _, r := range run.Results {
		jr := JSONResult{
			Name:           r.Object.Name,
			Source:         r.Object.URL,
			Status:         r.Status,
			Reason:         r.Reason,
			Size:           r.Object.Size,
			RestoreSeconds: r.Restore.Seconds(),
			TotalSeconds:   r.Total.Seconds(),
			ReceiptPath:    r.ReceiptPath,
			Checks:         []receipt.Check{},
		}
		if rc := r.Receipt; rc != nil {
			jr.ReceiptID = rc.ID
			jr.SHA256 = rc.Subject.SHA256
			jr.Format = rc.Subject.Format
			jr.Compression = rc.Subject.Compression
			jr.RestoreSeconds, jr.TotalSeconds = rc.Measured.RestoreSeconds, rc.Measured.TotalSeconds
			if rc.Checks != nil {
				jr.Checks = rc.Checks
			}
		}
		if r.RowsKnown {
			t, n := r.Tables, r.Rows
			jr.Tables, jr.Rows = &t, &n
		}
		rep.Results = append(rep.Results, jr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// JUnit XML, as understood by GitHub Actions, GitLab, Jenkins and most CI UIs:
// one test case per backup; FAIL → <failure>, ERROR → <error>.
type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name      string      `xml:"name,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Errors    int         `xml:"errors,attr"`
	Skipped   int         `xml:"skipped,attr"`
	Time      string      `xml:"time,attr"`
	Timestamp string      `xml:"timestamp,attr"`
	Cases     []junitCase `xml:"testcase"`
	SystemErr string      `xml:"system-err,omitempty"`
}

type junitCase struct {
	ClassName string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitProblem `xml:"failure,omitempty"`
	Error     *junitProblem `xml:"error,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
}

type junitProblem struct {
	Message string `xml:"message,attr"`
	Type    string `xml:"type,attr"`
	Body    string `xml:",chardata"`
}

func WriteJUnit(w io.Writer, run Run) error {
	s := run.summary()
	var total time.Duration
	suite := junitSuite{
		Name:      "xinproof verify " + run.Location,
		Tests:     s.Total,
		Failures:  s.Fail,
		Errors:    s.Error,
		Timestamp: run.StartedAt.UTC().Format("2006-01-02T15:04:05"),
	}
	if run.Err != nil {
		suite.SystemErr = run.Err.Error()
	}
	for _, r := range run.Results {
		total += r.Total
		c := junitCase{ClassName: "xinproof." + run.Location, Name: r.Object.Name, Time: secs(r.Total)}
		var detail strings.Builder
		if r.Receipt != nil {
			for _, ch := range r.Receipt.Checks {
				fmt.Fprintf(&detail, "%s: %s %s\n", ch.ID, ch.Status, ch.Detail)
			}
		}
		switch r.Status {
		case receipt.Pass:
		case receipt.Fail:
			c.Failure = &junitProblem{Message: r.Reason, Type: "FAIL", Body: detail.String()}
		default:
			c.Error = &junitProblem{Message: r.Reason, Type: "ERROR", Body: detail.String()}
		}
		out := "source: " + r.Object.URL
		if r.ReceiptPath != "" {
			out += "\nreceipt: " + r.ReceiptPath
		}
		if r.RowsKnown {
			out += fmt.Sprintf("\nrestored: %d tables, %d rows in %s", r.Tables, r.Rows, Duration(r.Restore))
		}
		c.SystemOut = out
		suite.Cases = append(suite.Cases, c)
	}
	if run.Err != nil && len(run.Results) == 0 {
		// Make "nothing tested" visible as an error in CI UIs too.
		suite.Tests, suite.Errors = 1, 1
		suite.Cases = append(suite.Cases, junitCase{ClassName: "xinproof." + run.Location, Name: "discover",
			Error: &junitProblem{Message: run.Err.Error(), Type: "ERROR"}})
	}
	suite.Time = secs(total)
	doc := junitSuites{Name: "xinproof", Tests: suite.Tests, Failures: suite.Failures, Errors: suite.Errors, Time: suite.Time, Suites: []junitSuite{suite}}
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func secs(d time.Duration) string { return fmt.Sprintf("%.3f", d.Seconds()) }
