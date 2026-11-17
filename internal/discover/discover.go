// Package discover decides what a stored object is: which compression, which
// dump format, and which database version produced it. It looks at content
// (magic bytes and headers), not only at file names.
package discover

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// HeadSize is how much (decompressed) content is inspected to detect a format.
const HeadSize = 64 << 10

type Compression string

const (
	None Compression = ""
	Gzip Compression = "gzip"
	Zstd Compression = "zstd"
	LZ4  Compression = "lz4"
)

type Format string

const (
	FormatEmpty    Format = "empty"
	FormatUnknown  Format = "unknown"
	FormatPGCustom Format = "postgres-custom"    // pg_dump -Fc
	FormatPGPlain  Format = "postgres-plain"     // pg_dump / pg_dumpall plain SQL
	FormatPGTar    Format = "postgres-tar"       // pg_dump -Ft
	FormatPGDir    Format = "postgres-directory" // pg_dump -Fd (a folder holding toc.dat and data files)
	FormatMySQL    Format = "mysql-plain"        // mysqldump / mariadb-dump
)

type Detection struct {
	Compression   Compression
	Format        Format
	Engine        string // "postgres", "mysql" or ""
	Flavor        string // for mysql: "mysql" or "mariadb"
	DumpVersion   string // version of the dump tool, e.g. "16.4"
	ServerVersion string // version of the server it was dumped from
	// Problem is set when the content is structurally broken in a way that
	// means it cannot restore (bad compression header, truncated PGDMP header,
	// unrecognizable content). Such backups FAIL.
	Problem string
}

var candidateExt = map[string]bool{
	".dump": true, ".backup": true, ".bak": true, ".pgdump": true, ".pg_dump": true,
	".sql": true, ".psql": true, ".pgsql": true, ".dmp": true,
}

var compressionExt = map[string]bool{".gz": true, ".gzip": true, ".zst": true, ".zstd": true, ".lz4": true}

// IsCandidate reports whether an object name looks like a database backup.
// IsTarCandidate reports whether name may be a pg_dump tar-format archive.
// Tar files are common for other things too, so these are only treated as
// backups if their content is a pg_dump tar archive.
func IsTarCandidate(name string) bool {
	base := strings.ToLower(path.Base(name))
	ext := path.Ext(base)
	if ext == ".tgz" {
		return true
	}
	if compressionExt[ext] {
		ext = path.Ext(strings.TrimSuffix(base, ext))
	}
	return ext == ".tar"
}

// IsDirectoryTOC reports whether name is the toc.dat of a pg_dump -Fd directory.
func IsDirectoryTOC(name string) bool { return path.Base(name) == "toc.dat" }

// MemberCompression guesses a directory-format data file's compression from its extension.
func MemberCompression(name string) Compression {
	switch strings.ToLower(path.Ext(name)) {
	case ".gz":
		return Gzip
	case ".zst":
		return Zstd
	case ".lz4":
		return LZ4
	}
	return None
}

func IsCandidate(name string) bool {
	base := strings.ToLower(path.Base(name))
	ext := path.Ext(base)
	if compressionExt[ext] {
		ext = path.Ext(strings.TrimSuffix(base, ext))
	}
	return candidateExt[ext]
}

// IsSidecar reports whether name is a checksum sidecar, and for which object.
func IsSidecar(name string) (target string, ok bool) {
	if strings.HasSuffix(strings.ToLower(name), ".sha256") {
		return name[:len(name)-len(".sha256")], true
	}
	return "", false
}

// DetectCompression identifies a compression format by its magic number.
func DetectCompression(b []byte) Compression {
	switch {
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return Gzip
	case len(b) >= 4 && b[0] == 0x28 && b[1] == 0xb5 && b[2] == 0x2f && b[3] == 0xfd:
		return Zstd
	case len(b) >= 4 && b[0] == 0x04 && b[1] == 0x22 && b[2] == 0x4d && b[3] == 0x18:
		return LZ4
	}
	return None
}

// NewDecompressor wraps r in a streaming decompressor for c.
func NewDecompressor(c Compression, r io.Reader) (io.ReadCloser, error) {
	switch c {
	case None:
		return io.NopCloser(r), nil
	case Gzip:
		return gzip.NewReader(r)
	case Zstd:
		d, err := zstd.NewReader(r, zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case LZ4:
		return io.NopCloser(lz4.NewReader(r)), nil
	}
	return nil, fmt.Errorf("unsupported compression %q", c)
}

// Sniff detects the format of a byte prefix.
func Sniff(head []byte) Detection { return SniffStream(bytes.NewReader(head)) }

// SniffStream reads at most what it needs from r (decompressing if necessary)
// and detects the format. Read errors from r surface as a Problem; callers that
// need to tell source errors apart should wrap r and inspect it afterwards.
func SniffStream(r io.Reader) Detection {
	br := bufio.NewReaderSize(r, 4096)
	magic, err := br.Peek(4)
	if len(magic) == 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			return Detection{Format: FormatUnknown, Problem: "cannot read object: " + err.Error()}
		}
		return Detection{Format: FormatEmpty, Problem: "empty file (0 bytes)"}
	}
	d := Detection{Compression: DetectCompression(magic)}
	var inner io.Reader = br
	if d.Compression != None {
		dec, err := NewDecompressor(d.Compression, br)
		if err != nil {
			d.Format, d.Problem = FormatUnknown, fmt.Sprintf("%s header is corrupt: %v", d.Compression, err)
			return d
		}
		defer dec.Close()
		inner = dec
	}
	buf := make([]byte, HeadSize)
	n, err := io.ReadFull(inner, buf)
	buf = buf[:n]
	if n == 0 {
		if err != nil && !errors.Is(err, io.EOF) {
			d.Format, d.Problem = FormatUnknown, fmt.Sprintf("cannot decompress %s stream: %v", d.Compression, err)
			return d
		}
		d.Format, d.Problem = FormatEmpty, fmt.Sprintf("%s stream contains no data", d.Compression)
		return d
	}
	detectContent(&d, buf)
	return d
}

var (
	rePGDumpVer   = regexp.MustCompile(`(?m)^-- Dumped by pg_dump(?:all)? version (\d+(?:\.\d+)*)`)
	rePGServerVer = regexp.MustCompile(`(?m)^-- Dumped from database version (\d+(?:\.\d+)*)`)
	// "-- MySQL dump 10.13  Distrib 8.0.36, for Linux" or "-- MariaDB dump 10.19-11.4.2-MariaDB, for debian-linux-gnu"
	reMySQLVer    = regexp.MustCompile(`(?m)^-- (?:MySQL|MariaDB) dump \S+?(?:\s+Distrib (\S+?),|-(\S+?), for)`)
	reMySQLServer = regexp.MustCompile(`(?m)^-- Server version\s+(\S+)`)
)

// pg_dump archive format bytes (pg_backup.h: archCustom, archTar, archDirectory).
const (
	archCustom    = 1
	archTar       = 3
	archDirectory = 5
)

func detectContent(d *Detection, b []byte) {
	if len(b) >= 512 && string(b[257:262]) == "ustar" {
		name := string(bytes.TrimRight(b[:100], "\x00"))
		if name != "toc.dat" {
			d.Format = FormatUnknown
			d.Problem = fmt.Sprintf("a tar archive, but not a pg_dump tar-format archive (first entry %q)", name)
			return
		}
		d.Format, d.Engine = FormatPGTar, "postgres"
		h, err := ParsePGDMP(b[512:])
		if err == nil && h.Format != archTar {
			err = fmt.Errorf("tar archive's toc.dat has archive format %d, expected tar (%d)", h.Format, archTar)
		}
		if err != nil {
			d.Problem = err.Error()
			return
		}
		d.DumpVersion, d.ServerVersion = firstWord(h.DumpVersion), firstWord(h.ServerVersion)
		return
	}
	if bytes.HasPrefix(b, []byte("PGDMP")) {
		d.Format, d.Engine = FormatPGCustom, "postgres"
		h, err := ParsePGDMP(b)
		if err != nil {
			d.Problem = err.Error()
			return
		}
		switch h.Format {
		case archCustom:
		case archTar, archDirectory:
			// A bare PGDMP header with the tar/directory format byte is the
			// toc.dat of a directory-format dump (pg_dump writes archTar there);
			// the caller groups the folder.
			d.Format = FormatPGDir
		default:
			d.Problem = fmt.Sprintf("pg_dump archive format %d is not restorable from a single file", h.Format)
			return
		}
		d.DumpVersion, d.ServerVersion = firstWord(h.DumpVersion), firstWord(h.ServerVersion)
		return
	}
	text := string(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")))
	switch {
	case strings.Contains(text, "-- PostgreSQL database dump") || strings.Contains(text, "-- PostgreSQL database cluster dump"):
		d.Format, d.Engine = FormatPGPlain, "postgres"
		if m := rePGDumpVer.FindStringSubmatch(text); m != nil {
			d.DumpVersion = m[1]
		}
		if m := rePGServerVer.FindStringSubmatch(text); m != nil {
			d.ServerVersion = m[1]
		}
	case strings.Contains(text, "-- MySQL dump") || strings.Contains(text, "-- MariaDB dump"),
		// mysqldump --skip-comments: no header, but always these session settings.
		strings.HasPrefix(strings.TrimSpace(text), "/*!40101 SET @OLD_CHARACTER_SET_CLIENT") ||
			strings.HasPrefix(strings.TrimSpace(text), "/*M!999999"): // MariaDB's sandbox-mode marker line
		d.Format, d.Engine, d.Flavor = FormatMySQL, "mysql", "mysql"
		if m := reMySQLVer.FindStringSubmatch(text); m != nil {
			d.DumpVersion = m[1] + m[2]
		}
		if m := reMySQLServer.FindStringSubmatch(text); m != nil {
			d.ServerVersion = m[1]
		}
		if strings.Contains(text, "-- MariaDB dump") || strings.Contains(d.DumpVersion+d.ServerVersion, "MariaDB") ||
			strings.HasPrefix(strings.TrimSpace(text), "/*M!999999") {
			d.Flavor = "mariadb"
		}
	default:
		d.Format = FormatUnknown
		d.Problem = fmt.Sprintf("not a recognizable PostgreSQL or MySQL dump (starts with %q)", preview(b))
	}
}

func firstWord(s string) string {
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

func preview(b []byte) string {
	if len(b) > 16 {
		b = b[:16]
	}
	return string(b)
}

// PGHeader is the parsed header of a pg_dump custom-format archive.
type PGHeader struct {
	VMajor, VMinor, VRev int
	IntSize, OffSize     int
	Format               byte // 1 = custom
	Compression          string
	DBName               string
	ServerVersion        string
	DumpVersion          string
}

// ParsePGDMP parses the header written by pg_dump's WriteHead
// (src/bin/pg_dump/pg_backup_archiver.c).
func ParsePGDMP(b []byte) (PGHeader, error) {
	var h PGHeader
	if !bytes.HasPrefix(b, []byte("PGDMP")) {
		return h, errors.New("missing PGDMP magic")
	}
	r := &hdrReader{b: b, pos: 5}
	h.VMajor, h.VMinor = int(r.byte()), int(r.byte())
	if h.VMajor > 1 || (h.VMajor == 1 && h.VMinor > 0) {
		h.VRev = int(r.byte())
	}
	h.IntSize, h.OffSize = int(r.byte()), int(r.byte())
	h.Format = r.byte()
	if r.err != nil {
		return h, errors.New("pg_dump archive header is truncated")
	}
	if h.VMajor != 1 || h.VMinor < 0 || h.VMinor > 30 {
		return h, fmt.Errorf("pg_dump archive header is corrupt (archive version %d.%d)", h.VMajor, h.VMinor)
	}
	if h.IntSize < 1 || h.IntSize > 8 || h.OffSize < 1 || h.OffSize > 8 {
		return h, fmt.Errorf("pg_dump archive header is corrupt (int size %d, offset size %d)", h.IntSize, h.OffSize)
	}
	if h.Format != archCustom && h.Format != archTar && h.Format != archDirectory {
		return h, fmt.Errorf("pg_dump archive header is corrupt (unknown archive format %d)", h.Format)
	}
	r.intSize = h.IntSize
	ver := h.VMajor<<16 | h.VMinor<<8 | h.VRev
	mk := func(maj, min int) int { return maj<<16 | min<<8 }
	if ver >= mk(1, 15) {
		h.Compression = map[byte]string{0: "none", 1: "gzip", 2: "lz4", 3: "zstd"}[r.byte()]
	} else if ver >= mk(1, 2) {
		if lvl := r.int(); lvl != 0 {
			h.Compression = "gzip"
		} else {
			h.Compression = "none"
		}
	}
	if ver >= mk(1, 4) {
		for i := 0; i < 7; i++ { // creation time: sec, min, hour, mday, mon, year, isdst
			r.int()
		}
		h.DBName = r.str()
	}
	if ver >= mk(1, 10) {
		h.ServerVersion = r.str()
		h.DumpVersion = r.str()
	}
	if r.err != nil {
		return h, errors.New("pg_dump archive header is truncated or corrupt")
	}
	return h, nil
}

type hdrReader struct {
	b       []byte
	pos     int
	intSize int
	err     error
}

func (r *hdrReader) byte() byte {
	if r.pos >= len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	c := r.b[r.pos]
	r.pos++
	return c
}

func (r *hdrReader) int() int64 {
	sign := r.byte()
	var v int64
	for i := 0; i < r.intSize; i++ {
		v |= int64(r.byte()) << (8 * i)
	}
	if sign != 0 {
		v = -v
	}
	return v
}

func (r *hdrReader) str() string {
	l := r.int()
	if l < 0 {
		return ""
	}
	if l > 4096 || r.pos+int(l) > len(r.b) {
		r.err = errors.New("bad string length")
		return ""
	}
	s := string(r.b[r.pos : r.pos+int(l)])
	r.pos += int(l)
	return s
}
