package verify

import (
	"context"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"google.golang.org/api/option"

	"github.com/praxin/xinproof/internal/receipt"
	"github.com/praxin/xinproof/internal/source"
	azsrc "github.com/praxin/xinproof/internal/source/azblob"
	"github.com/praxin/xinproof/internal/source/conformance"
	gcssrc "github.com/praxin/xinproof/internal/source/gcs"
)

// The full pipeline over Azure (Azurite) and GCS (fake-gcs-server): provider
// checksums are compared, corruption FAILs, receipts name the cloud URL.

func runOver(t *testing.T, src source.Source) map[string]Result {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	v := &Verifier{Src: src, Engine: &fakeEngine{outcome: passOutcome}, Opts: Options{
		Store: &receipt.Store{Dir: filepath.Join(t.TempDir(), "receipts")}, Key: priv,
	}}
	results, err := v.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Result{}
	for _, r := range results {
		out[r.Object.Name] = r
		t.Logf("%s: %s %s", r.Object.Name, r.Status, r.Reason)
	}
	return out
}

func TestAzureEndToEnd(t *testing.T) {
	base := conformance.StartEmulator(t, conformance.AzuriteImage, 10000, "/", "azurite-blob", "--blobHost", "0.0.0.0", "--loose", "--skipApiVersionCheck")
	const account, key = "devstoreaccount1", "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	endpoint := base + "/" + account + "/"
	cred, _ := azblob.NewSharedKeyCredential(account, key)
	admin, err := azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	const c = "backups"
	if _, err := admin.CreateContainer(ctx, c, nil); err != nil {
		t.Fatal(err)
	}
	good := pgCustom()
	rotted := append([]byte(nil), good...)
	rotted[len(rotted)/2] ^= 0x01 // one bit flipped after the uploader recorded Content-MD5
	put := func(name string, body, md5For []byte) {
		real := md5.Sum(body)
		if _, err := admin.UploadBuffer(ctx, c, "pg/"+name, body, &azblob.UploadBufferOptions{HTTPHeaders: &blob.HTTPHeaders{BlobContentMD5: real[:]}}); err != nil {
			t.Fatal(err)
		}
		// The service validates Content-MD5 on upload, so a stale one (bit rot,
		// a bad copy tool) is set afterwards through the blob's properties.
		stored := md5.Sum(md5For)
		if stored != real {
			bc := admin.ServiceClient().NewContainerClient(c).NewBlobClient("pg/" + name)
			if _, err := bc.SetHTTPHeaders(ctx, blob.HTTPHeaders{BlobContentMD5: stored[:]}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	put("good.dump", good, good)
	put("rotted.dump", rotted, good)
	bigGz := gzipped([]byte(strings.Replace(completePlain, "1\n2\n", strings.Repeat("123456789\n", 20_000), 1)))
	put("trunc.sql.gz", bigGz[:len(bigGz)/2], bigGz[:len(bigGz)/2])

	src, err := azsrc.New(ctx, account, c, "pg/", azsrc.Options{Endpoint: endpoint, AccountKey: key})
	if err != nil {
		t.Fatal(err)
	}
	res := runOver(t, src)
	want := map[string]string{"good.dump": "PASS", "rotted.dump": "FAIL", "trunc.sql.gz": "FAIL"}
	for name, w := range want {
		if string(res[name].Status) != w {
			t.Errorf("%s = %s (%s), want %s", name, res[name].Status, res[name].Reason, w)
		}
	}
	if !strings.Contains(res["rotted.dump"].Reason, "provider MD5") {
		t.Errorf("rotted.dump reason %q", res["rotted.dump"].Reason)
	}
	if got := res["good.dump"].Receipt.Subject.Source; got != "azblob://"+account+"/"+c+"/pg/good.dump" {
		t.Errorf("receipt source %q", got)
	}
	var sawMD5 bool
	for _, ch := range res["good.dump"].Receipt.Checks {
		sawMD5 = sawMD5 || (ch.ID == "l1.checksum" && strings.Contains(ch.Detail, "md5"))
	}
	if !sawMD5 {
		t.Error("good.dump receipt has no MD5 checksum check")
	}
}

func TestGCSEndToEnd(t *testing.T) {
	base := conformance.StartEmulator(t, conformance.FakeGCSImage, 0, "/storage/v1/b",
		"-scheme", "http", "-port", "{PORT}", "-external-url", "http://127.0.0.1:{PORT}", "-backend", "memory")
	ctx := context.Background()
	admin, err := storage.NewClient(ctx, option.WithEndpoint(base+"/storage/v1/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	bucket := fmt.Sprintf("backups-%d", time.Now().UnixNano()%1e6)
	if err := admin.Bucket(bucket).Create(ctx, "test-project", nil); err != nil {
		t.Fatal(err)
	}
	put := func(name string, body []byte) {
		w := admin.Bucket(bucket).Object("pg/" + name).NewWriter(ctx)
		w.ChunkSize = 0
		w.Write(body)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	}
	put("good.dump", pgCustom())
	bigGz := gzipped([]byte(strings.Replace(completePlain, "1\n2\n", strings.Repeat("123456789\n", 20_000), 1)))
	put("trunc.sql.gz", bigGz[:len(bigGz)/2])

	src, err := gcssrc.New(ctx, bucket, "pg/", gcssrc.Options{Endpoint: base})
	if err != nil {
		t.Fatal(err)
	}
	res := runOver(t, src)
	if res["good.dump"].Status != receipt.Pass || res["trunc.sql.gz"].Status != receipt.Fail {
		t.Errorf("results %v / %v", res["good.dump"].Status, res["trunc.sql.gz"].Status)
	}
	var algs []string
	for _, ch := range res["good.dump"].Receipt.Checks {
		if ch.ID == "l1.checksum" {
			algs = append(algs, ch.Detail)
		}
	}
	if len(algs) != 2 {
		t.Errorf("want MD5 and CRC32C checks against GCS, got %q", algs)
	}
}
