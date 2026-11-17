package discover

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// MongoArchiveMagic starts every mongodump --archive stream (0x8199e26d, little-endian).
var MongoArchiveMagic = []byte{0x6d, 0xe2, 0x99, 0x81}

var errBSON = errors.New("malformed BSON document")

// ParseBSON reads the top-level fields of one BSON document. Strings come
// back as string, booleans as bool, int32/int64 as int64; fields of other
// types are skipped. It is just enough to read mongodump archive headers.
func ParseBSON(doc []byte) (map[string]any, error) {
	if len(doc) < 5 {
		return nil, errBSON
	}
	n := int(int32(binary.LittleEndian.Uint32(doc)))
	if n < 5 || n > len(doc) || doc[n-1] != 0 {
		return nil, errBSON
	}
	b := doc[4 : n-1]
	out := map[string]any{}
	for len(b) > 0 {
		typ := b[0]
		end := bytes.IndexByte(b[1:], 0)
		if end < 0 {
			return nil, errBSON
		}
		name := string(b[1 : 1+end])
		b = b[2+end:]
		size := -1
		i32 := func() int {
			if len(b) < 4 {
				return -1
			}
			return int(int32(binary.LittleEndian.Uint32(b)))
		}
		switch typ {
		case 0x01, 0x09, 0x11, 0x12: // double, datetime, timestamp, int64
			size = 8
			if typ == 0x12 && len(b) >= 8 {
				out[name] = int64(binary.LittleEndian.Uint64(b))
			}
		case 0x02, 0x0D, 0x0E: // string, JavaScript, symbol
			if l := i32(); l >= 1 && len(b) >= 4+l {
				size = 4 + l
				if typ == 0x02 {
					out[name] = string(b[4 : 4+l-1])
				}
			}
		case 0x03, 0x04, 0x0F: // document, array, code with scope
			size = i32()
		case 0x05: // binary
			if l := i32(); l >= 0 {
				size = 5 + l
			}
		case 0x07: // ObjectId
			size = 12
		case 0x08:
			size = 1
			if len(b) >= 1 {
				out[name] = b[0] != 0
			}
		case 0x0A, 0x06, 0x7F, 0xFF: // null, undefined, max key, min key
			size = 0
		case 0x0B: // regex: two cstrings
			p := bytes.IndexByte(b, 0)
			if p >= 0 {
				if q := bytes.IndexByte(b[p+1:], 0); q >= 0 {
					size = p + 1 + q + 1
				}
			}
		case 0x0C: // DBPointer
			if l := i32(); l >= 1 {
				size = 4 + l + 12
			}
		case 0x10:
			size = 4
			if v := i32(); len(b) >= 4 {
				out[name] = int64(v)
			}
		case 0x13: // decimal128
			size = 16
		default:
			return nil, fmt.Errorf("%w: unknown element type 0x%02x", errBSON, typ)
		}
		if size < 0 || size > len(b) {
			return nil, errBSON
		}
		b = b[size:]
	}
	return out, nil
}

// detectMongoArchive reads the mongodump archive header that follows the magic.
func detectMongoArchive(d *Detection, b []byte) {
	d.Format, d.Engine = FormatMongoArchive, "mongodb"
	h, err := ParseBSON(b[len(MongoArchiveMagic):])
	if err != nil {
		if len(b) < len(MongoArchiveMagic)+4 || int(binary.LittleEndian.Uint32(b[len(MongoArchiveMagic):])) > len(b)-len(MongoArchiveMagic) {
			d.Problem = "mongodump archive header is truncated"
		} else {
			d.Problem = "mongodump archive header is corrupt: " + err.Error()
		}
		return
	}
	d.DumpVersion, _ = h["tool_version"].(string)
	d.ServerVersion, _ = h["server_version"].(string)
}
