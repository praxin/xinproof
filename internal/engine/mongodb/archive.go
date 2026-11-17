package mongodb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc64"
	"sort"
	"strings"

	"github.com/praxin/xinproof/internal/discover"
	"github.com/praxin/xinproof/internal/engine"
	"github.com/praxin/xinproof/internal/receipt"
)

// A mongodump archive is: magic, a header document, one metadata document
// per namespace, a terminator (int32 -1), then blocks. Each block is a
// namespace header {db, collection, EOF, CRC}; a block with EOF false is
// followed by that namespace's documents, one with EOF true closes the
// namespace and carries the CRC-64 (ECMA) of all its documents. Every block
// ends with a terminator. Blocks of different namespaces may interleave.

const (
	terminator = 0xFFFFFFFF
	// maxDoc bounds a document's declared size (BSON's limit is 16 MiB; the
	// server allows a little more for internal documents).
	maxDoc = 48 << 20
)

type archiveState int

const (
	stMagic archiveState = iota
	stHeader
	stPrelude  // metadata documents until a terminator
	stBlock    // expecting a namespace header
	stBody     // documents of the current namespace until a terminator
	stEOFBlock // after an EOF header: expecting its terminator
)

// ArchiveAnalyzer checks a mongodump archive's structure while it streams:
// framing, that every namespace is complete (truncation), the per-namespace
// CRCs (mongorestore reports a CRC mismatch but still exits 0), and counts the
// documents each user collection holds in the dump.
type ArchiveAnalyzer struct {
	// Rows are documents per user collection in the dump, keyed by
	// engine.TableKey("", "db.collection").
	Rows map[string]int64
	// Collections is the number of user collections the archive declares, -1
	// until the archive's metadata has been read.
	Collections int

	state   archiveState
	buf     []byte
	skip    int // bytes of the current body document still to read
	off     int64
	ns      string
	problem string

	kind    map[string]string // namespace → "collection", "view", "timeseries", …
	crcs    map[string]hash.Hash64
	started map[string]bool
	done    map[string]bool
	docs    int64
}

var crcTable = crc64.MakeTable(crc64.ECMA)

func NewArchiveAnalyzer() *ArchiveAnalyzer {
	return &ArchiveAnalyzer{
		Rows: map[string]int64{}, Collections: -1,
		kind: map[string]string{}, crcs: map[string]hash.Hash64{}, started: map[string]bool{}, done: map[string]bool{},
	}
}

// userCollection reports whether a namespace is user data that the restore
// is checked against (not a system database, system collection or view).
func userCollection(db, coll, kind string) bool {
	switch db {
	case "admin", "config", "local":
		return false
	}
	return !strings.HasPrefix(coll, "system.") && (kind == "collection" || kind == "")
}

func (a *ArchiveAnalyzer) fail(format string, args ...any) {
	if a.problem == "" {
		a.problem = fmt.Sprintf(format, args...)
	}
}

func (a *ArchiveAnalyzer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 && a.problem == "" {
		if a.skip > 0 { // inside a body document: hash it, don't keep it
			k := min(a.skip, len(p))
			a.crcs[a.ns].Write(p[:k])
			a.skip -= k
			a.off += int64(k)
			p = p[k:]
			if a.skip == 0 {
				a.docs++
				if key, ok := a.rowKey(a.ns); ok {
					a.Rows[key]++
				}
			}
			continue
		}
		// Collect the next frame: 4 bytes of magic or length, then (for
		// anything but a body document) the whole document.
		want := 4
		if len(a.buf) >= 4 && a.state != stMagic {
			if l := binary.LittleEndian.Uint32(a.buf); l != terminator {
				want = int(l)
			}
		}
		k := min(want-len(a.buf), len(p))
		a.buf = append(a.buf, p[:k]...)
		a.off += int64(k)
		p = p[k:]
		if len(a.buf) < 4 {
			continue
		}
		if a.state == stMagic {
			if !bytes.Equal(a.buf, discover.MongoArchiveMagic) {
				a.fail("not a mongodump archive (bad magic)")
			}
			a.state, a.buf = stHeader, a.buf[:0]
			continue
		}
		l := binary.LittleEndian.Uint32(a.buf)
		if l == terminator {
			a.buf = a.buf[:0]
			a.endBlock()
			continue
		}
		if l < 5 || l > maxDoc {
			a.fail("corrupt archive: document of %d bytes at byte %d", int32(l), a.off-int64(len(a.buf)))
			continue
		}
		if a.state == stBody {
			a.crcs[a.ns].Write(a.buf[:4])
			a.skip = int(l) - 4
			a.buf = a.buf[:0]
			continue
		}
		if len(a.buf) < int(l) {
			continue // keep collecting the document
		}
		a.document(a.buf)
		a.buf = a.buf[:0]
	}
	return n, nil
}

func (a *ArchiveAnalyzer) rowKey(ns string) (string, bool) {
	db, coll, _ := strings.Cut(ns, ".")
	if !userCollection(db, coll, a.kind[ns]) {
		return "", false
	}
	return engine.TableKey("", ns), true
}

// endBlock handles a terminator.
func (a *ArchiveAnalyzer) endBlock() {
	switch a.state {
	case stPrelude:
		a.Collections = 0
		for ns, k := range a.kind {
			db, coll, _ := strings.Cut(ns, ".")
			if userCollection(db, coll, k) {
				a.Collections++
				a.Rows[engine.TableKey("", ns)] = 0 // declared, even if it holds no documents
			}
		}
		a.state = stBlock
	case stBody, stEOFBlock:
		a.state = stBlock
	default:
		a.fail("corrupt archive: unexpected terminator at byte %d", a.off-4)
	}
}

// document handles a complete header, metadata or namespace-header document.
func (a *ArchiveAnalyzer) document(doc []byte) {
	m, err := discover.ParseBSON(doc)
	if err != nil {
		a.fail("corrupt archive at byte %d: %v", a.off-int64(len(doc)), err)
		return
	}
	switch a.state {
	case stHeader:
		a.state = stPrelude
	case stPrelude:
		db, _ := m["db"].(string)
		coll, _ := m["collection"].(string)
		kind, _ := m["type"].(string)
		if kind == "" { // older tools: views are recognizable from their options
			if md, _ := m["metadata"].(string); strings.Contains(md, `"viewOn"`) {
				kind = "view"
			}
		}
		a.kind[db+"."+coll] = kind
	case stBlock:
		db, _ := m["db"].(string)
		coll, _ := m["collection"].(string)
		ns := db + "." + coll
		if a.done[ns] {
			a.fail("corrupt archive: data for %s after its end", ns)
			return
		}
		if a.crcs[ns] == nil {
			a.crcs[ns] = crc64.New(crcTable)
		}
		a.started[ns] = true
		if eof, _ := m["EOF"].(bool); eof {
			crc, _ := m["CRC"].(int64)
			if got := int64(a.crcs[ns].Sum64()); got != crc {
				a.fail("%s: data is corrupt (CRC mismatch: archive says %d, data hashes to %d)", ns, crc, got)
				return
			}
			a.done[ns] = true
			a.state = stEOFBlock
			return
		}
		a.ns = ns
		a.state = stBody
	default:
		a.fail("corrupt archive: unexpected document at byte %d", a.off-int64(len(doc)))
	}
}

// Finish returns the l1.structure check.
func (a *ArchiveAnalyzer) Finish() []receipt.Check {
	if a.problem == "" {
		switch {
		case a.state == stMagic || a.state == stHeader || a.state == stPrelude:
			a.fail("archive ends early at byte %d, inside its header (truncated)", a.off)
		case a.skip > 0 || len(a.buf) > 0 || a.state != stBlock:
			where := "between blocks"
			if a.state == stBody {
				where = "inside the data of " + a.ns
			}
			a.fail("archive ends early at byte %d, %s (truncated)", a.off, where)
		}
	}
	if a.problem == "" {
		var open []string
		for ns := range a.kind {
			if !a.done[ns] {
				open = append(open, ns)
			}
		}
		for ns := range a.started {
			if _, declared := a.kind[ns]; !declared && !a.done[ns] {
				open = append(open, ns)
			}
		}
		if len(open) > 0 {
			sort.Strings(open)
			a.fail("archive ends before the data of %s is complete (truncated)%s", open[0], more(len(open)-1))
		}
	}
	if a.problem != "" {
		return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckFail, Detail: a.problem}}
	}
	return []receipt.Check{{ID: "l1.structure", Status: receipt.CheckPass,
		Detail: fmt.Sprintf("mongodump archive complete: %d namespaces, %d documents, every namespace's CRC matches", len(a.done), a.docs)}}
}

func more(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", n)
}
