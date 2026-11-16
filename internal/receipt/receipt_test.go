package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{
			// RFC 8785 §3.2.2 example.
			name: "rfc8785 example",
			in:   `{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}`,
			want: `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
		},
		{name: "key order and whitespace", in: "{ \"b\" : 1, \"a\" : [ 1 , 2 ] }", want: `{"a":[1,2],"b":1}`},
		{name: "nested objects sorted", in: `{"z":{"y":1,"x":2},"a":null}`, want: `{"a":null,"z":{"x":2,"y":1}}`},
		{name: "no html escaping", in: `{"s":"<a>&"}`, want: `{"s":"<a>&"}`},
		{name: "negative zero", in: `[-0]`, want: `[0]`},
		{name: "big integer", in: `[13314398208]`, want: `[13314398208]`},
		{name: "utf16 key order", in: `{"\u20ac":1,"\ud83d\ude00":2,"a":3}`, want: "{\"a\":3,\"€\":1,\"😀\":2}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize([]byte(tt.in))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	if _, err := Canonicalize([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Error("trailing data accepted")
	}
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func sample(result Result) *Receipt {
	r := New(time.Date(2026, 11, 16, 14, 21, 7, 0, time.UTC))
	r.Subject = Subject{Source: "s3://acme/pg.dump", Size: 1234, SHA256: strings.Repeat("ab", 32)}
	r.Engine = Engine{Kind: "postgres", DumpVersion: "16.4"}
	r.Result = result
	r.Measured = Measured{RestoreSeconds: 4.237, TotalSeconds: 6.5}
	r.Checks = []Check{{ID: "l2.restore", Status: CheckPass, Detail: "exit 0"}}
	r.Tool = Tool{Name: "xinproof", Version: "0.1.0"}
	return r
}

func TestSignVerify(t *testing.T) {
	priv := testKey(t)
	other := testKey(t)
	r := sample(Pass)
	r.Chain = Chain{Prev: GenesisPrev, Seq: 1}
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	doc, _ := json.MarshalIndent(r, "", "  ")

	tamper := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(doc, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	tests := []struct {
		name    string
		doc     []byte
		trusted []ed25519.PublicKey
		wantErr bool
		pinned  bool
	}{
		{name: "valid, embedded key", doc: doc},
		{name: "valid, pinned key", doc: doc, trusted: []ed25519.PublicKey{priv.Public().(ed25519.PublicKey)}, pinned: true},
		{name: "wrong pinned key", doc: doc, trusted: []ed25519.PublicKey{other.Public().(ed25519.PublicKey)}, wantErr: true},
		{name: "result flipped", doc: tamper(func(m map[string]any) { m["result"] = "FAIL" }), wantErr: true},
		{name: "size changed", doc: tamper(func(m map[string]any) { m["subject"].(map[string]any)["size"] = 1235 }), wantErr: true},
		{name: "field added", doc: tamper(func(m map[string]any) { m["note"] = "trust me" }), wantErr: true},
		{name: "key swapped without re-signing", doc: tamper(func(m map[string]any) {
			m["signature"].(map[string]any)["public_key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}), wantErr: true},
		{name: "unsigned", doc: tamper(func(m map[string]any) { delete(m, "signature") }), wantErr: true},
		{name: "reformatted but unchanged", doc: tamper(func(m map[string]any) {})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := Verify(tt.doc, tt.trusted)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && v.Pinned != tt.pinned {
				t.Errorf("pinned = %v, want %v", v.Pinned, tt.pinned)
			}
		})
	}
}

func TestStoreChain(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir}
	priv := testKey(t)
	var paths []string
	for _, res := range []Result{Pass, Fail, Error} {
		p, err := s.Append(sample(res), priv)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	var vs []*Verified
	for _, p := range paths {
		doc, _ := os.ReadFile(p)
		v, err := Verify(doc, nil)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		vs = append(vs, v)
	}
	if vs[0].Receipt.Chain.Prev != GenesisPrev || vs[0].Receipt.Chain.Seq != 1 {
		t.Errorf("first receipt chain = %+v", vs[0].Receipt.Chain)
	}
	for i := 1; i < len(vs); i++ {
		if err := CheckLink(vs[i-1], vs[i]); err != nil {
			t.Errorf("link %d: %v", i, err)
		}
	}
	if err := CheckLink(vs[0], vs[2]); err == nil {
		t.Error("gap not detected")
	}

	// Rewriting history: re-sign receipt 2 with different content. Its own
	// signature is valid, but receipt 3 no longer links to it.
	doc, _ := os.ReadFile(paths[1])
	var r Receipt
	_ = json.Unmarshal(doc, &r)
	r.Result = Pass
	r.Reason = ""
	if err := r.Sign(priv); err != nil {
		t.Fatal(err)
	}
	forged, _ := json.Marshal(&r)
	fv, err := Verify(forged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLink(fv, vs[2]); err == nil {
		t.Error("rewritten history not detected by the chain")
	}

	// HEAD missing: the store rebuilds it from the newest receipt.
	_ = os.Remove(filepath.Join(dir, "HEAD"))
	p, err := s.Append(sample(Pass), priv)
	if err != nil {
		t.Fatal(err)
	}
	doc, _ = os.ReadFile(p)
	v4, err := Verify(doc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLink(vs[2], v4); err != nil {
		t.Errorf("chain after HEAD rebuild: %v", err)
	}
}

func TestKeys(t *testing.T) {
	dir := t.TempDir()
	k1, created, err := LoadOrCreateKey(dir)
	if err != nil || !created {
		t.Fatalf("create: %v %v", created, err)
	}
	k2, created, err := LoadOrCreateKey(dir)
	if err != nil || created {
		t.Fatalf("reload: %v %v", created, err)
	}
	if !k1.Equal(k2) {
		t.Error("reloaded key differs")
	}
	pub, err := LoadLocalPublicKey(dir)
	if err != nil || !pub.Equal(k1.Public()) {
		t.Errorf("public key: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, privFile)); fi.Mode().Perm()&0o077 != 0 && !isWindows() {
		t.Errorf("private key mode %v", fi.Mode().Perm())
	}
	if _, err := ParsePublicKey([]byte("nope")); err == nil {
		t.Error("garbage public key accepted")
	}
}

func isWindows() bool { return os.PathSeparator == '\\' }

func TestULID(t *testing.T) {
	a := NewULID(time.UnixMilli(1000))
	b := NewULID(time.UnixMilli(2000))
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("lengths %d %d", len(a), len(b))
	}
	if !(a < b) {
		t.Errorf("ULIDs not time-ordered: %s >= %s", a, b)
	}
	if NewULID(time.UnixMilli(1000))[:10] != a[:10] {
		t.Errorf("time prefix not stable for equal timestamps")
	}
}
