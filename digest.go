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
// Example usage:
//
//	t := NewTransport("myUserName", "myP@55w0rd")
//	req, err := http.NewRequest("GET", "http://notreal.com/path?arg=1", nil)
//	if err != nil {
//		return err
//	}
//	resp, err := t.RoundTrip(req)
//	if err != nil {
//		return err
//	}
//
// OR it can be used as a client:
//
//	c, err := t.Client()
//	if err != nil {
//		return err
//	}
//	resp, err := c.Get("http://notreal.com/path?arg=1")
//	if err != nil {
//		return err
//	}
//
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrNilTransport      = errors.New("Transport is nil")
	ErrBadChallenge      = errors.New("Challenge is bad")
	ErrAlgNotImplemented = errors.New("Alg not implemented")
)

// Transport is an implementation of http.RoundTripper that takes care of http
// digest authentication.
type Transport struct {
	Username  string
	Password  string
	Transport http.RoundTripper
}

// NewTransport creates a new digest transport using the http.DefaultTransport.
func NewTransport(username, password string) *Transport {
	t := &Transport{
		Username: username,
		Password: password,
	}
	t.Transport = http.DefaultTransport
	return t
}

type challenge struct {
	Realm     string
	Domain    string
	Nonce     string
	Opaque    string
	Stale     string
	Algorithm string
	Qop       string
}

func parseChallenge(input string) (*challenge, error) {
	const ws = " \n\r\t"
	const qs = `"`
	s := strings.Trim(input, ws)
	if !strings.HasPrefix(s, "Digest ") {
		return nil, ErrBadChallenge
	}
	s = strings.Trim(s[7:], ws)
	sl := strings.Split(s, ", ")
	c := &challenge{
		Algorithm: "MD5",
	}
	for _, ss := range sl {
		spl := strings.Split(ss, ",")
		for _, sss := range spl {
			stf := strings.Split(sss, "=")
			switch stf[0] {
			case "realm":
				c.Realm = stf[1]
			case "domain":
				c.Domain = stf[1]
			case "nonce":
				c.Nonce = stf[1]
			case "opaque":
				c.Opaque = stf[1]
			case "stale":
				c.Stale = stf[1]
			case "algorithm":
				c.Algorithm = stf[1]
			case "qop":
				c.Qop = stf[1]
			default:
				return nil, ErrBadChallenge
			}
		}
	}
	return c, nil
}

type credentials struct {
	Username   string
	Realm      string
	Nonce      string
	DigestURI  string
	Algorithm  string
	Cnonce     string
	Opaque     string
	Qop        string
	MessageQop string
	NonceCount int
	method     string
	password   string
}

func h(data string) string {
	hf := md5.New()
	io.WriteString(hf, data)
	return fmt.Sprintf("%x", hf.Sum(nil))
}

func kd(secret, data string) string {
	return h(fmt.Sprintf("%s:%s", secret, data))
}

func (c *credentials) ha1() string {
	return h(fmt.Sprintf("%s:%s:%s", c.Username, c.Realm, c.password))
}

func (c *credentials) ha2() string {
	return h(fmt.Sprintf("%s:%s", c.method, c.DigestURI))
}

func (c *credentials) resp(cnonce string) (string, error) {
	c.NonceCount++
	if c.MessageQop == "auth" {
		if cnonce != "" {
			c.Cnonce = cnonce
		} else {
			b := make([]byte, 8)
			io.ReadFull(rand.Reader, b)
			c.Cnonce = fmt.Sprintf("%x", b)[:16]
		}
		return kd(c.ha1(), fmt.Sprintf("%s:%08x:%s:%s:%s",
			c.Nonce, c.NonceCount, c.Cnonce, c.MessageQop, c.ha2())), nil
	} else if c.MessageQop == "" {
		return kd(c.ha1(), fmt.Sprintf("%s:%s", c.Nonce, c.ha2())), nil
	}
	return "", ErrAlgNotImplemented
}

func (c *credentials) authorize() (string, error) {
	sl := []string{fmt.Sprintf(`username="%s"`, c.Username)}
	sl = append(sl, fmt.Sprintf(`realm=%s`, c.Realm))
	sl = append(sl, fmt.Sprintf(`nonce=%s=="`, c.Nonce))
	sl = append(sl, fmt.Sprintf(`uri="%s"`, c.DigestURI))
	sl = append(sl, fmt.Sprintf(`qop=%s`, c.Qop))
	sl = append(sl, fmt.Sprintf(`algorithm=%s`, c.Algorithm))
	sl = append(sl, fmt.Sprintf(`stale=false`))
	sl = append(sl, fmt.Sprintf(`password="jeff"`))
	return fmt.Sprintf("Digest %s", strings.Join(sl, ", ")), nil
}

func (t *Transport) newCredentials(req *http.Request, c *challenge) *credentials {
	return &credentials{
		Username:   t.Username,
		Realm:      c.Realm,
		Nonce:      c.Nonce,
		DigestURI:  req.URL.RequestURI(),
		Algorithm:  c.Algorithm,
		Opaque:     c.Opaque,
		Qop:        c.Qop, // "auth" must be a single value
		NonceCount: 0,
		method:     req.Method,
		password:   t.Password,
	}
}

// RoundTrip makes a request expecting a 401 response that will require digest
// authentication.  It creates the credentials it needs and makes a follow-up
// request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}
	// Set client timeout
	cc := &http.Client{}
	resp, err := cc.Do(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}
	chal := resp.Header.Get("WWW-Authenticate")
	c, err := parseChallenge(chal)
	if err != nil {
		return resp, err
	}
	// Form credentials based on the challenge.
	cr := t.newCredentials(req, c)
	auth, err := cr.authorize()
	if err != nil {
		return resp, err
	}
	// We'll no longer use the initial response, so close it
	//resp.Body.Close()
	req.Header.Set("Authorization", auth)
	return cc.Do(req)
}

// Client returns an HTTP client that uses the digest transport.
func (t *Transport) Client() (*http.Client, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}
	return &http.Client{Transport: t}, nil
}
