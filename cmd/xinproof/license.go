package main

// The runner's own licence check. A runner connected to anything other than
// Xinproof Cloud tests only while that server presents a valid Xinproof
// Enterprise licence (header X-Xinproof-License): signed with Xinproof's
// licence key, whose public half is compiled in here, and not past its end
// date. So getting around the licence means changing this binary too, not
// just the server.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// licensePublicKey is Xinproof's licence-signing public key (base64url raw
// Ed25519); it must match LICENSE_PUBLIC_KEY in xinproof-cloud/src/license.js.
var licensePublicKey = "2teYqFWADxzYCWF3xE7po2mif8Y4nwzL2h9dl3olS90"

// officialHosts are Xinproof Cloud's own addresses, which need no licence.
var officialHosts = []string{"xinproof-cloud.xinproof.workers.dev"}

const licensePrefix = "XINPROOF-LICENSE-1."

type licensePayload struct {
	ID       string `json:"id"`
	Customer string `json:"customer"`
	Expires  string `json:"expires"`
	Runners  int    `json:"runners"`
}

// serverLicense says whether this runner may test for the server at serverURL,
// given the licence the server presented (empty if none).
func serverLicense(serverURL, token string, now time.Time) error {
	if u, err := url.Parse(serverURL); err == nil && u.Scheme == "https" {
		for _, h := range officialHosts {
			if strings.EqualFold(u.Hostname(), h) {
				return nil
			}
		}
	}
	token = strings.Join(strings.Fields(token), "")
	if token == "" {
		return fmt.Errorf("not tested: this Xinproof server has no licence. Add one in Settings, then tests resume by themselves")
	}
	p, err := parseLicense(token)
	if err != nil {
		return fmt.Errorf("not tested: this Xinproof server's licence isn't valid (%v)", err)
	}
	end, err := time.Parse("2006-01-02", p.Expires)
	if err != nil {
		return fmt.Errorf("not tested: this Xinproof server's licence has no end date")
	}
	if now.UTC().After(end.Add(24*time.Hour - time.Second)) {
		return fmt.Errorf("not tested: this Xinproof server's licence ended on %s. Add a renewed licence in Settings, then tests resume by themselves", p.Expires)
	}
	return nil
}

func parseLicense(token string) (*licensePayload, error) {
	if !strings.HasPrefix(token, licensePrefix) {
		return nil, fmt.Errorf("not a Xinproof licence")
	}
	parts := strings.Split(strings.TrimPrefix(token, licensePrefix), ".")
	if len(parts) != 2 {
		return nil, fmt.Errorf("not a Xinproof licence")
	}
	pub, err := base64.RawURLEncoding.DecodeString(licensePublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("this runner has no licence key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), []byte(licensePrefix+parts[0]), sig) {
		return nil, fmt.Errorf("its signature doesn't match")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("it can't be read")
	}
	var p licensePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("it can't be read")
	}
	return &p, nil
}
