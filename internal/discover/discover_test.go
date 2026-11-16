package discover

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// pgdmpHeader builds a custom-format header the way pg_dump's WriteHead does.
func pgdmpHeader(vmin byte, server, dump string) []byte {
	var b bytes.Buffer
	b.WriteString("PGDMP")
	b.Write([]byte{1, vmin, 0, 4, 8, 1}) // version 1.vmin.0, intSize 4, offSize 8, format custom
	writeInt := func(v int) {
		sign := byte(0)
		if v < 0 {
			sign, v = 1, -v
		}
		b.WriteByte(sign)
		for i := 0; i < 4; i++ {
			b.WriteByte(byte(v >> (8 * i)))
		}
	}
	writeStr := func(s string) { writeInt(len(s)); b.WriteString(s) }
	if vmin >= 15 {
		b.WriteByte(1) // gzip
	} else {
		writeInt(-1) // default compression
	}
	for _, v := range []int{7, 21, 14, 16, 10, 126, 0} {
		writeInt(v)
	}
	writeStr("shop")
	writeStr(server)
	writeStr(dump)
	b.WriteString("\x00\x00\x00\x00 toc follows …")
	return b.Bytes()
}

const plainPG = "--\n-- PostgreSQL database dump\n--\n\n-- Dumped from database version 16.4 (Debian 16.4-1.pgdg120+1)\n-- Dumped by pg_dump version 16.4 (Debian 16.4-1.pgdg120+1)\n\nSET statement_timeout = 0;\n"
const plainMySQL = "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n--\n-- Host: localhost    Database: shop\n-- Server version\t8.0.36\n"

func gz(b []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func zst(b []byte) []byte {
	var out bytes.Buffer
	w, _ := zstd.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func lz(b []byte) []byte {
	var out bytes.Buffer
	w := lz4.NewWriter(&out)
	w.Write(b)
	w.Close()
	return out.Bytes()
}

func TestSniff(t *testing.T) {
	hdr15 := pgdmpHeader(15, "16.4 (Debian 16.4-1.pgdg120+1)", "16.4 (Debian 16.4-1.pgdg120+1)")
	hdr14 := pgdmpHeader(14, "13.11", "14.9")
	tests := []struct {
		name        string
		in          []byte
		format      Format
		comp        Compression
		dumpVersion string
		server      string
		problem     string // substring; "" means no problem expected
	}{
		{name: "pg custom 1.15", in: hdr15, format: FormatPGCustom, dumpVersion: "16.4", server: "16.4"},
		{name: "pg custom 1.14", in: hdr14, format: FormatPGCustom, dumpVersion: "14.9", server: "13.11"},
		{name: "pg custom truncated header", in: hdr15[:30], format: FormatPGCustom, problem: "truncated"},
		{name: "pg custom bad int size", in: append([]byte("PGDMP\x01\x0f\x00\x63\x08\x01"), make([]byte, 64)...), format: FormatPGCustom, problem: "corrupt"},
		{name: "pg custom tar format byte", in: append([]byte("PGDMP\x01\x0f\x00\x04\x08\x03"), make([]byte, 64)...), format: FormatPGCustom, problem: "not the custom format"},
		{name: "pg plain", in: []byte(plainPG), format: FormatPGPlain, dumpVersion: "16.4", server: "16.4"},
		{name: "pg plain with BOM", in: append([]byte("\xef\xbb\xbf"), plainPG...), format: FormatPGPlain, dumpVersion: "16.4"},
		{name: "pg_dumpall", in: []byte("--\n-- PostgreSQL database cluster dump\n--\n\n-- Dumped by pg_dumpall version 17.2\n"), format: FormatPGPlain, dumpVersion: "17.2"},
		{name: "mysql", in: []byte(plainMySQL), format: FormatMySQL, dumpVersion: "8.0.36", server: "8.0.36"},
		{name: "gzip pg plain", in: gz([]byte(plainPG)), format: FormatPGPlain, comp: Gzip, dumpVersion: "16.4"},
		{name: "gzip pg custom", in: gz(hdr15), format: FormatPGCustom, comp: Gzip, dumpVersion: "16.4"},
		{name: "zstd pg custom", in: zst(hdr15), format: FormatPGCustom, comp: Zstd, dumpVersion: "16.4"},
		{name: "lz4 pg plain", in: lz([]byte(plainPG)), format: FormatPGPlain, comp: LZ4, dumpVersion: "16.4"},
		{name: "empty", in: nil, format: FormatEmpty, problem: "empty file"},
		{name: "gzip of nothing", in: gz(nil), format: FormatEmpty, comp: Gzip, problem: "no data"},
		{name: "gzip header truncated", in: gz([]byte(plainPG))[:5], format: FormatUnknown, comp: Gzip, problem: "gzip"},
		{name: "garbage", in: []byte("hello, this is not a dump"), format: FormatUnknown, problem: "not a recognizable"},
		{name: "first bytes flipped", in: append([]byte("XGDMP"), hdr15[5:]...), format: FormatUnknown, problem: "not a recognizable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := Sniff(tt.in)
			if d.Format != tt.format {
				t.Errorf("format = %q, want %q (problem %q)", d.Format, tt.format, d.Problem)
			}
			if d.Compression != tt.comp {
				t.Errorf("compression = %q, want %q", d.Compression, tt.comp)
			}
			if tt.dumpVersion != "" && d.DumpVersion != tt.dumpVersion {
				t.Errorf("dump version = %q, want %q", d.DumpVersion, tt.dumpVersion)
			}
			if tt.server != "" && d.ServerVersion != tt.server {
				t.Errorf("server version = %q, want %q", d.ServerVersion, tt.server)
			}
			if tt.problem == "" && d.Problem != "" {
				t.Errorf("unexpected problem %q", d.Problem)
			}
			if tt.problem != "" && !strings.Contains(d.Problem, tt.problem) {
				t.Errorf("problem = %q, want it to mention %q", d.Problem, tt.problem)
			}
		})
	}
}

func TestIsCandidate(t *testing.T) {
	tests := map[string]bool{
		"pg_2026-11-14.dump":  true,
		"nightly/shop.sql.gz": true,
		"shop.sql.zst":        true,
		"db.backup":           true,
		"DB.DUMP":             true,
		"shop.pgdump.lz4":     true,
		"notes.txt":           false,
		"archive.tar.gz":      false,
		"pg.dump.sha256":      false,
		"receipts/HEAD":       false,
		"image.png":           false,
		"x.gz":                false,
	}
	for name, want := range tests {
		if got := IsCandidate(name); got != want {
			t.Errorf("IsCandidate(%q) = %v, want %v", name, got, want)
		}
	}
	if target, ok := IsSidecar("a/pg.dump.sha256"); !ok || target != "a/pg.dump" {
		t.Errorf("IsSidecar = %q %v", target, ok)
	}
}
