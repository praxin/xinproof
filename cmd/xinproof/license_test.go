package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Tests sign licences with their own key, standing in for Xinproof's.
var testLicenseKey ed25519.PrivateKey
var testLicense string

func init() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	testLicenseKey = priv
	licensePublicKey = base64.RawURLEncoding.EncodeToString(pub)
	testLicense = issueTestLicense(licensePayload{ID: "lic_t", Customer: "Acme Health", Expires: "2099-12-31", Runners: 5}, priv)
}

func issueTestLicense(p licensePayload, key ed25519.PrivateKey) string {
	b, _ := json.Marshal(p)
	body := licensePrefix + base64.RawURLEncoding.EncodeToString(b)
	return body + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(body)))
}

func TestServerLicense(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	endsToday := issueTestLicense(licensePayload{ID: "a", Expires: "2026-11-18", Runners: 1}, testLicenseKey)
	ended := issueTestLicense(licensePayload{ID: "b", Expires: "2026-11-17", Runners: 1}, testLicenseKey)
	forged := issueTestLicense(licensePayload{ID: "c", Expires: "2099-01-01", Runners: 99}, otherKey)
	parts := strings.Split(testLicense, ".")
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"id":"lic_t","expires":"2199-12-31","runners":999}`)) + "." + parts[2]

	cases := []struct {
		name, url, lic string
		ok             bool
		want           string
	}{
		{"Xinproof Cloud needs none", "https://xinproof-cloud.xinproof.workers.dev", "", true, ""},
		{"not over plain http", "http://xinproof-cloud.xinproof.workers.dev", "", false, "no licence"},
		{"look-alike host", "https://xinproof-cloud.xinproof.workers.dev.evil.example", "", false, "no licence"},
		{"self-hosted without one", "https://xinproof.acme.internal", "", false, "no licence"},
		{"valid", "https://xinproof.acme.internal", testLicense, true, ""},
		{"line breaks are fine", "https://xinproof.acme.internal", testLicense[:30] + "\n " + testLicense[30:], true, ""},
		{"last day still works", "https://xinproof.acme.internal", endsToday, true, ""},
		{"ended yesterday", "https://xinproof.acme.internal", ended, false, "ended on 2026-11-17"},
		{"signed by someone else", "https://xinproof.acme.internal", forged, false, "signature doesn't match"},
		{"changed after signing", "https://xinproof.acme.internal", tampered, false, "signature doesn't match"},
		{"junk", "https://xinproof.acme.internal", "hello", false, "not a Xinproof licence"},
	}
	for _, c := range cases {
		err := serverLicense(c.url, c.lic, now)
		if c.ok && err != nil {
			t.Errorf("%s: want ok, got %v", c.name, err)
		}
		if !c.ok && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: want error containing %q, got %v", c.name, c.want, err)
		}
	}
	// One second after the end date's last moment.
	if err := serverLicense("https://x.example", endsToday, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Error("a licence must stop working the day after its end date")
	}
}

func TestAgentTestsNothingWithoutAValidLicence(t *testing.T) {
	ended := issueTestLicense(licensePayload{ID: "b", Expires: "2025-12-31", Runners: 1}, testLicenseKey)
	for _, lic := range []string{"none", ended} {
		cloud := &fakeCloud{jobs: []agentJob{{ID: "job_1", Location: "s3://b/pg/", Newest: 3}}, done: map[string]map[string]any{}, license: lic}
		srv := httptest.NewServer(cloud)
		a, calls := newTestAgent(t, srv.URL)
		if err := a.loop(t.Context(), true); err != nil {
			t.Fatal(err)
		}
		srv.Close()
		if len(*calls) != 0 {
			t.Errorf("licence %q: verify ran %d times; it must not run at all", lic[:min(len(lic), 12)], len(*calls))
		}
		d := cloud.done["job_1"]
		if d == nil || d["exit_code"] != float64(exitUsage) || !strings.Contains(d["message"].(string), "not tested") {
			t.Errorf("licence %q: job should be reported as not tested, got %v", lic[:min(len(lic), 12)], d)
		}
		if len(cloud.receipts) != 0 {
			t.Errorf("no results may be sent without a licence")
		}
	}
}
