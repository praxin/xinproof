package mysql

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/sandbox"
)

// QueryValue runs a user query in the restore database and returns its single
// value (engine.Querier). The client's XML output keeps rows, columns and
// NULL unambiguous whatever the values contain.
func (s *session) QueryValue(ctx context.Context, query string) (string, bool, error) {
	args := append(s.clientArgs(), "--xml", "-e", query, restoreDB)
	res, err := s.exec(ctx, sandbox.ExecOpts{Args: args})
	if err != nil {
		return "", false, err
	}
	if res.ExitCode != 0 {
		if why := s.c.Died(); why != "" {
			return "", false, fmt.Errorf("%w: %s", engine.ErrSandbox, why)
		}
		if res.DaemonError() {
			return "", false, fmt.Errorf("%w: %s", engine.ErrSandbox, lastLines(res.Stderr, 1))
		}
		if why := engine.SandboxFault(res.Stderr); why != "" {
			return "", false, fmt.Errorf("%w: %s", engine.ErrSandbox, why)
		}
		return "", false, errors.New(firstErrors(res.Stderr))
	}
	return parseXMLValue(res.Stdout)
}

type xmlField struct {
	Nil   string `xml:"http://www.w3.org/2001/XMLSchema-instance nil,attr"`
	Value string `xml:",chardata"`
}

type xmlResultset struct {
	Rows []struct {
		Fields []xmlField `xml:"field"`
	} `xml:"row"`
}

// parseXMLValue reads `mysql --xml` output that must hold exactly one row with
// one column (across every result set the statement(s) produced).
func parseXMLValue(out []byte) (string, bool, error) {
	dec := xml.NewDecoder(bytes.NewReader(out))
	var rows [][]xmlField
	for {
		var rs xmlResultset
		err := dec.Decode(&rs)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", false, fmt.Errorf("unreadable query output: %v", err)
		}
		for _, r := range rs.Rows {
			rows = append(rows, r.Fields)
		}
	}
	switch {
	case len(rows) == 0:
		return "", false, errors.New("query returned no rows (want one row with one column)")
	case len(rows) > 1:
		return "", false, fmt.Errorf("query returned %d rows (want one row with one column)", len(rows))
	case len(rows[0]) != 1:
		return "", false, fmt.Errorf("query returned %d columns (want one row with one column)", len(rows[0]))
	}
	f := rows[0][0]
	if f.Nil == "true" {
		return "", true, nil
	}
	return f.Value, false, nil
}
