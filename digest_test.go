// Copyright 2013 M-Lab
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The digest package provides an implementation of http.RoundTripper that takes
// care of HTTP Digest Authentication (http://www.ietf.org/rfc/rfc2617.txt).
// This only implements the MD5 and "auth" portions of the RFC, but that covers
// the majority of avalible server side implementations including apache web
// server.
//

package digest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"testing"
)

var cred = &credentials{
	Username:   "Mufasa",
	Realm:      "testrealm@host.com",
	Nonce:      "dcd98b7102dd2f0e8b11d0f600bfb0c093",
	DigestURI:  "/dir/index.html",
	Algorithm:  "MD5",
	Opaque:     "5ccc069c403ebaf9f0171e9517f40e41",
	MessageQop: "auth",
	method:     "GET",
	password:   "Circle Of Life",
}

var cnonce = "0a4f113b"

const (
	MoneroServer1 = "http://64.98.18.21:18081"
	MoneroServer2 = "http://64.98.18.21:28081"
)

func TestMoneroDigest(t *testing.T) {
	d := struct {
		TxHashes []string `json:"txs_hashes"`
	}{
		TxHashes: []string{"test"},
	}
	payload, err := json.Marshal(d)
	if err != nil {
		t.Errorf("got an error from node client: %v", err)
	}
	tr := NewTransport("jeff", "jeff")
	u, err := url.Parse(MoneroServer1)
	if err != nil {
		t.Errorf("parsing url: %w", err)
	}
	u.Path = path.Join(u.Path, "/get_transactions")
	req, err := http.NewRequest("GET", u.String(), bytes.NewReader(payload))
	if err != nil {
		t.Errorf("got an error from node client: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Errorf("got an error from node client: %v", err)
	}
	out := struct {
		Status string `json:"status"`
	}{}
	json.NewDecoder(resp.Body).Decode(out)
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		fmt.Println("Resp Body: ", resp.Body)
		fmt.Println("Out: ", out)
		t.Errorf("http status %v", resp.StatusCode)
	}
}
