// Package azblob reads backups from Azure Blob Storage and ADLS Gen2 (HNS
// accounts are read through the Blob endpoint). It only lists blobs, reads
// their properties and downloads them.
package azblob

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"

	"github.com/praxin/xinproof/internal/source"
)

type Options struct {
	// Endpoint overrides https://<account>.blob.core.windows.net (Azurite,
	// sovereign clouds, private endpoints).
	Endpoint string
	// Credentials, in order of precedence; all optional. With none of them the
	// default Azure credential chain is used (environment, workload identity,
	// managed identity, Azure CLI, …).
	ConnectionString string // AZURE_STORAGE_CONNECTION_STRING
	SASToken         string // AZURE_STORAGE_SAS_TOKEN (needs read + list)
	AccountKey       string // AZURE_STORAGE_KEY
}

// OptionsFromEnv fills credentials from the standard environment variables.
func OptionsFromEnv(o Options) Options {
	if o.ConnectionString == "" {
		o.ConnectionString = os.Getenv("AZURE_STORAGE_CONNECTION_STRING")
	}
	if o.SASToken == "" {
		o.SASToken = os.Getenv("AZURE_STORAGE_SAS_TOKEN")
	}
	if o.AccountKey == "" {
		o.AccountKey = os.Getenv("AZURE_STORAGE_KEY")
	}
	return o
}

type Source struct {
	cc        *container.Client
	account   string
	container string
	prefix    string
}

func New(ctx context.Context, account, containerName, prefix string, o Options) (*Source, error) {
	if account == "" || containerName == "" {
		return nil, errors.New("azblob: location must be azblob://<account>/<container>/<prefix>")
	}
	endpoint := o.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net/", account)
	}
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}
	var (
		client *azblob.Client
		err    error
	)
	switch {
	case o.ConnectionString != "":
		client, err = azblob.NewClientFromConnectionString(o.ConnectionString, nil)
	case o.SASToken != "":
		client, err = azblob.NewClientWithNoCredential(endpoint+"?"+strings.TrimPrefix(o.SASToken, "?"), nil)
	case o.AccountKey != "":
		var cred *azblob.SharedKeyCredential
		if cred, err = azblob.NewSharedKeyCredential(account, o.AccountKey); err == nil {
			client, err = azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
		}
	default:
		var cred *azidentity.DefaultAzureCredential
		if cred, err = azidentity.NewDefaultAzureCredential(nil); err == nil {
			client, err = azblob.NewClient(endpoint, cred, nil)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("azblob: setting up credentials: %w", err)
	}
	return &Source{cc: client.ServiceClient().NewContainerClient(containerName), account: account, container: containerName, prefix: prefix}, nil
}

func (s *Source) String() string {
	return fmt.Sprintf("azblob://%s/%s/%s", s.account, s.container, s.prefix)
}

func (s *Source) url(key string) string {
	return fmt.Sprintf("azblob://%s/%s/%s", s.account, s.container, key)
}

func (s *Source) name(key string) string {
	n := strings.TrimPrefix(strings.TrimPrefix(key, s.prefix), "/")
	if n == "" {
		n = path.Base(key)
	}
	return n
}

func (s *Source) List(ctx context.Context, prefix string) ([]source.Object, error) {
	p := s.prefix + prefix
	pager := s.cc.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: &p, Include: container.ListBlobsInclude{Metadata: true}})
	var out []source.Object
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, s.explain(err, "list")
		}
		for _, b := range page.Segment.BlobItems {
			if b.Name == nil || b.Properties == nil || isFolder(b.Metadata) || strings.HasSuffix(*b.Name, "/") {
				continue // ADLS Gen2 directory markers
			}
			o := source.Object{Key: *b.Name, Name: s.name(*b.Name), URL: s.url(*b.Name)}
			if b.Properties.ContentLength != nil {
				o.Size = *b.Properties.ContentLength
			}
			if b.Properties.ETag != nil {
				o.ETag = strings.Trim(string(*b.Properties.ETag), `"`)
			}
			if b.Properties.LastModified != nil {
				o.LastModified = b.Properties.LastModified.UTC()
			}
			if len(b.Properties.ContentMD5) == 16 {
				o.MD5 = hex.EncodeToString(b.Properties.ContentMD5)
			}
			out = append(out, o)
		}
	}
	return out, nil
}

func isFolder(md map[string]*string) bool {
	for k, v := range md {
		if strings.EqualFold(k, "hdi_isfolder") && v != nil && strings.EqualFold(*v, "true") {
			return true
		}
	}
	return false
}

func (s *Source) Stat(ctx context.Context, key string) (source.Object, error) {
	p, err := s.cc.NewBlobClient(key).GetProperties(ctx, nil)
	if err != nil {
		return source.Object{}, s.explain(err, "read")
	}
	o := source.Object{Key: key, Name: s.name(key), URL: s.url(key)}
	if p.ContentLength != nil {
		o.Size = *p.ContentLength
	}
	if p.ETag != nil {
		o.ETag = strings.Trim(string(*p.ETag), `"`)
	}
	if p.LastModified != nil {
		o.LastModified = p.LastModified.UTC()
	}
	if len(p.ContentMD5) == 16 {
		o.MD5 = hex.EncodeToString(p.ContentMD5)
	}
	return o, nil
}

func (s *Source) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	resp, err := s.cc.NewBlobClient(key).DownloadStream(ctx, nil)
	if err != nil {
		return nil, s.explain(err, "read")
	}
	// Retry transient connection drops mid-download from where they stopped.
	return resp.NewRetryReader(ctx, &blob.RetryReaderOptions{MaxRetries: 5}), nil
}

// explain turns common errors into actionable messages naming the missing permission.
func (s *Source) explain(err error, op string) error {
	switch {
	case bloberror.HasCode(err, bloberror.AuthorizationPermissionMismatch, bloberror.AuthorizationFailure, bloberror.InsufficientAccountPermissions):
		return fmt.Errorf("access denied to %s/%s (%s): the identity needs the 'Storage Blob Data Reader' role on the container, or a SAS with read+list", s.account, s.container, op)
	case bloberror.HasCode(err, bloberror.AuthenticationFailed, bloberror.InvalidAuthenticationInfo, bloberror.NoAuthenticationInformation):
		return fmt.Errorf("credentials rejected by %s: check AZURE_STORAGE_SAS_TOKEN / AZURE_STORAGE_KEY or `az login`", s.account)
	case bloberror.HasCode(err, bloberror.ContainerNotFound):
		return fmt.Errorf("container %q does not exist in account %s", s.container, s.account)
	case bloberror.HasCode(err, bloberror.BlobNotFound):
		return fmt.Errorf("blob not found: %w", err)
	}
	return err
}
