// Package s3test is a tiny in-process S3 API (ListObjectsV2, HeadObject,
// GetObject, path-style) for tests. It records every request so tests can
// prove the verifier only ever reads.
package s3test

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Object struct {
	Body           []byte
	LastModified   time.Time
	ChecksumSHA256 string // base64, returned by HeadObject when checksum mode is enabled
}

type Request struct {
	Method string
	Path   string
	Query  string
}

type Server struct {
	*httptest.Server
	Bucket   string
	PageSize int    // keys per ListObjectsV2 page (default 1000)
	Deny     string // if set, every request fails with this S3 error code and 403

	mu       sync.Mutex
	objects  map[string]Object
	requests []Request
}

func New(bucket string, objects map[string]Object) *Server {
	s := &Server{Bucket: bucket, objects: objects}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// Requests returns every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

func etag(b []byte) string { h := md5.Sum(b); return `"` + hex.EncodeToString(h[:]) + `"` }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requests = append(s.requests, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
	s.mu.Unlock()

	if s.Deny != "" {
		writeErr(w, http.StatusForbidden, s.Deny, "denied by test server")
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/")
	bucket, key, _ := strings.Cut(path, "/")
	if bucket != s.Bucket {
		writeErr(w, http.StatusNotFound, "NoSuchBucket", "no such bucket")
		return
	}
	switch {
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		s.list(w, r)
	case r.Method == http.MethodHead && key != "":
		o, ok := s.objects[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.headers(w, o)
		if r.Header.Get("x-amz-checksum-mode") == "ENABLED" && o.ChecksumSHA256 != "" {
			w.Header().Set("x-amz-checksum-sha256", o.ChecksumSHA256)
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodGet && key != "":
		o, ok := s.objects[key]
		if !ok {
			writeErr(w, http.StatusNotFound, "NoSuchKey", "no such key")
			return
		}
		s.headers(w, o)
		w.WriteHeader(http.StatusOK)
		w.Write(o.Body)
	default:
		writeErr(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "the test server is read-only")
	}
}

func (s *Server) headers(w http.ResponseWriter, o Object) {
	w.Header().Set("Content-Length", strconv.Itoa(len(o.Body)))
	w.Header().Set("ETag", etag(o.Body))
	w.Header().Set("Last-Modified", o.LastModified.UTC().Format(http.TimeFormat))
	w.Header().Set("Content-Type", "application/octet-stream")
}

type listResult struct {
	XMLName               xml.Name   `xml:"ListBucketResult"`
	Xmlns                 string     `xml:"xmlns,attr"`
	Name                  string     `xml:"Name"`
	Prefix                string     `xml:"Prefix"`
	KeyCount              int        `xml:"KeyCount"`
	MaxKeys               int        `xml:"MaxKeys"`
	IsTruncated           bool       `xml:"IsTruncated"`
	ContinuationToken     string     `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string     `xml:"NextContinuationToken,omitempty"`
	Contents              []contents `xml:"Contents"`
}

type contents struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int    `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	start := 0
	tok := r.URL.Query().Get("continuation-token")
	if tok != "" {
		start, _ = strconv.Atoi(tok)
	}
	size := s.PageSize
	if size <= 0 {
		size = 1000
	}
	end := start + size
	if end > len(keys) {
		end = len(keys)
	}
	res := listResult{Xmlns: "http://s3.amazonaws.com/doc/2006-03-01/", Name: s.Bucket, Prefix: prefix, MaxKeys: size, ContinuationToken: tok}
	for _, k := range keys[start:end] {
		o := s.objects[k]
		res.Contents = append(res.Contents, contents{Key: k, LastModified: o.LastModified.UTC().Format("2006-01-02T15:04:05.000Z"),
			ETag: etag(o.Body), Size: len(o.Body), StorageClass: "STANDARD"})
	}
	res.KeyCount = len(res.Contents)
	if end < len(keys) {
		res.IsTruncated, res.NextContinuationToken = true, strconv.Itoa(end)
	}
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(xml.Header))
	xml.NewEncoder(w).Encode(res)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><RequestId>test</RequestId></Error>`, code, msg)
}
