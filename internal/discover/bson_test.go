package discover

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"testing"
)

// bsonDoc builds a BSON document from string, bool, int32 and int64 fields.
func bsonDoc(fields ...any) []byte {
	var body bytes.Buffer
	for i := 0; i < len(fields); i += 2 {
		name := fields[i].(string)
		switch v := fields[i+1].(type) {
		case string:
			body.WriteByte(0x02)
			body.WriteString(name + "\x00")
			binary.Write(&body, binary.LittleEndian, int32(len(v)+1))
			body.WriteString(v + "\x00")
		case bool:
			body.WriteByte(0x08)
			body.WriteString(name + "\x00")
			if v {
				body.WriteByte(1)
			} else {
				body.WriteByte(0)
			}
		case int32:
			body.WriteByte(0x10)
			body.WriteString(name + "\x00")
			binary.Write(&body, binary.LittleEndian, v)
		case int64:
			body.WriteByte(0x12)
			body.WriteString(name + "\x00")
			binary.Write(&body, binary.LittleEndian, v)
		}
	}
	out := make([]byte, 4, 4+body.Len()+1)
	binary.LittleEndian.PutUint32(out, uint32(4+body.Len()+1))
	out = append(out, body.Bytes()...)
	return append(out, 0)
}

func TestParseBSON(t *testing.T) {
	doc := bsonDoc("db", "shop", "EOF", true, "n", int32(-7), "CRC", int64(1)<<40)
	m, err := ParseBSON(doc)
	if err != nil {
		t.Fatal(err)
	}
	if m["db"] != "shop" || m["EOF"] != true || m["n"] != int64(-7) || m["CRC"] != int64(1)<<40 {
		t.Errorf("got %v", m)
	}
	for _, bad := range [][]byte{nil, {5, 0, 0, 0}, doc[:len(doc)-1], append(doc[:len(doc)-1:len(doc)-1], 1)} {
		if _, err := ParseBSON(bad); err == nil {
			t.Errorf("accepted %x", bad)
		}
	}
}

func TestSniffMongoArchive(t *testing.T) {
	head := append(append([]byte(nil), MongoArchiveMagic...),
		bsonDoc("concurrent_collections", int32(4), "version", "0.1", "server_version", "7.0.14", "tool_version", "100.10.0")...)
	head = append(head, bytes.Repeat([]byte{0}, 100)...)
	d := Sniff(head)
	if d.Format != FormatMongoArchive || d.Engine != "mongodb" || d.ServerVersion != "7.0.14" || d.DumpVersion != "100.10.0" || d.Problem != "" {
		t.Errorf("plain archive: %+v", d)
	}

	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(head)
	w.Close()
	d = Sniff(gz.Bytes())
	if d.Format != FormatMongoArchive || d.Compression != Gzip || d.ServerVersion != "7.0.14" {
		t.Errorf("gzip archive: %+v", d)
	}

	d = Sniff(head[:20])
	if d.Format != FormatMongoArchive || d.Problem == "" {
		t.Errorf("truncated header: %+v", d)
	}
}
