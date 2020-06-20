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

// https://en.wikipedia.org/wiki/Digest_access_authentication
func (t *Transport) digestResponse(dm map[string]string, bd io.ReadCloser, nc int) (string, error) {
	h1 := md5.New()
	h2 := md5.New()
	r := md5.New()
	b := make([]byte, 8)
	io.ReadFull(rand.Reader, b)
	dm["cnonce"] = fmt.Sprintf("%x", b)[:16]
	dm["nc"] = fmt.Sprintf("%08x", nc)
	v, ok := dm["algorithm"]
	if !ok {
		return "", ErrBadChallenge
	}
	io.WriteString(h1, fmt.Sprintf("%s:%s:%s", t.Username, dm["realm"], t.Password))
	if v == "algorithm=MD5-sess" {
		io.WriteString(h1, fmt.Sprintf("%s:%s:%s:%s", h1, dm["realm"], dm["nonce"], dm["cnonce"]))
	}
	fmt.Println(dm["method"])
	io.WriteString(h2, fmt.Sprintf("%s:%s", dm["method"], dm["uri"]))
	v, ok = dm["qop"]
	if !ok {
		return "", ErrBadChallenge
	}
	if v == "qop=auth-int" || v == "auth" {
		io.WriteString(h2, fmt.Sprintf("%s", bd))
		io.WriteString(h2, fmt.Sprintf("%s:%s:%s", dm["method"], dm["uri"], h2))
		io.WriteString(r, fmt.Sprintf("%s:%s:%s:%s:%s:%s", h1, dm["nonce"], dm["nc"], dm["nonce"], dm["qop"], h2))
	} else {
		io.WriteString(r, fmt.Sprintf("%s:%s:%s", h1, dm["nonce"], h2))
	}
	return fmt.Sprintf("Digest username=\"%s\", %s, %s, uri=%s, %s, nc=%s, cnonce=\"%s\", response=\"%s\"", t.Username, dm["realm"], dm["nonce"], dm["uri"], dm["qop"], dm["nc"], dm["cnonce"], r), nil
}

// NewTransport creates a new digest transport using the http.DefaultTransport.
func NewTransport(username, password string) *Transport {
	return &Transport{
		Username:  username,
		Password:  password,
		Transport: http.DefaultTransport,
	}
}

func parseDigest(in string) (map[string]string, error) {
	s := strings.Trim(in, " \n\r\t")
	if !strings.HasPrefix(s, "Digest ") {
		return nil, ErrBadChallenge
	}
	dm := make(map[string]string, 0)

	s = strings.Trim(s[7:], " \n\r\t")
	sl := strings.Split(s, ", ")
	for _, v := range sl {
		spl := strings.Split(v, ",")
		for _, vv := range spl {
			ss := strings.Split(vv, "=")
			fmt.Println(ss)
			dm[ss[0]] = vv
		}
	}
	return dm, nil
}

// RoundTrip makes a request expecting a 401 response that will require digest
// authentication.  It creates the credentials it needs and makes a follow-up
// request.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}

	// Copy the request so we don't modify the input.
	req2 := new(http.Request)
	*req2 = *req
	req2.Header = make(http.Header)
	for k, s := range req.Header {
		req2.Header[k] = s
	}
	b, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	req2.Body = b
	resp, err := t.Transport.RoundTrip(req)
	if err != nil || resp.StatusCode != 401 {
		return resp, err
	}
	fmt.Println(resp.Header["Www-Authenticate"])
	dm, err := parseDigest(resp.Header["Www-Authenticate"][1])
	if err != nil {
		return resp, err
	}
	dm["method"] = req.Method
	dm["uri"] = req.URL.RequestURI()
	r, err := t.digestResponse(dm, b, 1)
	if err != nil {
		return resp, err
	}
	fmt.Printf("%s", r)
	// We'll no longer use the initial response, so close it
	resp.Body.Close()
	req2.Header["Authorization"] = append(req2.Header["Authorization"], r)
	return t.Transport.RoundTrip(req2)
}

// Client returns an HTTP client that uses the digest transport.
func (t *Transport) Client() (*http.Client, error) {
	if t.Transport == nil {
		return nil, ErrNilTransport
	}
	return &http.Client{Transport: t}, nil
}
