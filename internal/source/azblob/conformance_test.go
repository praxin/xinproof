package azblob_test

import (
	"context"
	"crypto/md5"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/sas"

	"github.com/praxin/xinproof/internal/source"
	azsrc "github.com/praxin/xinproof/internal/source/azblob"
	"github.com/praxin/xinproof/internal/source/conformance"
)

// Azurite's well-known development account.
const (
	account = "devstoreaccount1"
	key     = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
)

type azurite struct {
	endpoint string
	cred     *azblob.SharedKeyCredential
	admin    *azblob.Client
	n        int
}

func startAzurite(t *testing.T) *azurite {
	base := conformance.StartEmulator(t, conformance.AzuriteImage, 10000, "/", "azurite-blob", "--blobHost", "0.0.0.0", "--loose", "--skipApiVersionCheck")
	a := &azurite{endpoint: base + "/" + account + "/"}
	var err error
	if a.cred, err = azblob.NewSharedKeyCredential(account, key); err != nil {
		t.Fatal(err)
	}
	if a.admin, err = azblob.NewClientWithSharedKeyCredential(a.endpoint, a.cred, nil); err != nil {
		t.Fatal(err)
	}
	return a
}

// seed creates a fresh container holding objs under pg/, plus objects that must
// not appear in the listing (outside the prefix, an ADLS Gen2 folder marker).
func (a *azurite) seed(t *testing.T, objs map[string][]byte) string {
	ctx := context.Background()
	a.n++
	name := fmt.Sprintf("conf-%d-%d", time.Now().UnixNano()%1e6, a.n)
	if _, err := a.admin.CreateContainer(ctx, name, nil); err != nil {
		t.Fatal(err)
	}
	put := func(k string, b []byte, md map[string]*string) {
		sum := md5.Sum(b)
		_, err := a.admin.UploadBuffer(ctx, name, k, b, &azblob.UploadBufferOptions{
			HTTPHeaders: &blob.HTTPHeaders{BlobContentMD5: sum[:]}, Metadata: md, BlockSize: 8 << 20})
		if err != nil {
			t.Fatalf("upload %s: %v", k, err)
		}
	}
	for k, b := range objs {
		put("pg/"+k, b, nil)
	}
	put("other/outside.dump", []byte("not under the location"), nil)
	yes := "true"
	put("pg/a-folder", nil, map[string]*string{"hdi_isfolder": &yes})
	return name
}

func (a *azurite) sas(t *testing.T, containerName string, perms sas.ContainerPermissions) string {
	qp, err := sas.BlobSignatureValues{
		Protocol:      sas.ProtocolHTTPSandHTTP,
		StartTime:     time.Now().Add(-time.Hour).UTC(),
		ExpiryTime:    time.Now().Add(time.Hour).UTC(),
		Permissions:   perms.String(),
		ContainerName: containerName,
	}.SignWithSharedKey(a.cred)
	if err != nil {
		t.Fatal(err)
	}
	return qp.Encode()
}

func TestConformanceAzurite(t *testing.T) {
	a := startAzurite(t)
	conformance.Run(t, conformance.Backend{
		Name:      "azblob-account-key",
		Published: []string{"md5"},
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			c := a.seed(t, objs)
			s, err := azsrc.New(context.Background(), account, c, "pg/", azsrc.Options{Endpoint: a.endpoint, AccountKey: key})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
	// Least privilege: a SAS with only read + list is all the verifier needs.
	conformance.Run(t, conformance.Backend{
		Name:      "azblob-sas-read-list",
		Published: []string{"md5"},
		Setup: func(t *testing.T, objs map[string][]byte) source.Source {
			c := a.seed(t, objs)
			s, err := azsrc.New(context.Background(), account, c, "pg/", azsrc.Options{Endpoint: a.endpoint,
				SASToken: a.sas(t, c, sas.ContainerPermissions{Read: true, List: true})})
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	})
}

func TestAzureErrors(t *testing.T) {
	a := startAzurite(t)
	c := a.seed(t, map[string][]byte{"x.dump": []byte("x")})
	ctx := context.Background()

	// Without list permission the error names the role to grant.
	s, _ := azsrc.New(ctx, account, c, "pg/", azsrc.Options{Endpoint: a.endpoint, SASToken: a.sas(t, c, sas.ContainerPermissions{Read: true})})
	if _, err := s.List(ctx, ""); err == nil || !strings.Contains(err.Error(), "Storage Blob Data Reader") {
		t.Errorf("read-only SAS list: err = %v", err)
	}
	// Missing container.
	s, _ = azsrc.New(ctx, account, "no-such-container", "", azsrc.Options{Endpoint: a.endpoint, AccountKey: key})
	if _, err := s.List(ctx, ""); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing container: err = %v", err)
	}
	// Wrong key.
	s, _ = azsrc.New(ctx, account, c, "", azsrc.Options{Endpoint: a.endpoint, AccountKey: strings.Repeat("A", 86) + "=="})
	// Azure answers a bad signature with AuthenticationFailed; Azurite with AuthorizationFailure.
	if _, err := s.List(ctx, ""); err == nil || !(strings.Contains(err.Error(), "credentials rejected") || strings.Contains(err.Error(), "access denied")) {
		t.Errorf("wrong key: err = %v", err)
	}
}
